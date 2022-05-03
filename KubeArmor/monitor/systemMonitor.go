// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package monitor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	cle "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ===================== //
// == Const. Vaiables == //
// ===================== //

// System Call Numbers
const (
	SysOpen   = 2
	SysOpenAt = 257
	SysClose  = 3

	SysSocket  = 41
	SysConnect = 42
	SysAccept  = 43
	SysBind    = 49
	SysListen  = 50

	SysExecve   = 59
	SysExecveAt = 322

	DoExit            = 351
	SecurityBprmCheck = 352
)

// SystemMonitor Constant Values
const (
	PermissionDenied = -13
	MaxStringLen     = 4096
)

// ======================= //
// == Namespace Context == //
// ======================= //

// NsKey Structure
type NsKey struct {
	PidNS uint32
	MntNS uint32
}

// ===================== //
// == Syscall Context == //
// ===================== //

// SyscallContext Structure
type SyscallContext struct {
	Ts uint64

	PidID uint32
	MntID uint32

	HostPPID uint32
	HostPID  uint32

	PPID uint32
	PID  uint32
	UID  uint32

	EventID int32
	Argnum  int32
	Retval  int64

	Comm [16]byte
}

// ContextCombined Structure
type ContextCombined struct {
	ContainerID string
	ContextSys  SyscallContext
	ContextArgs []interface{}
}

// ======================= //
// == Container Monitor == //
// ======================= //

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

// SystemMonitor Structure
type SystemMonitor struct {
	// host
	HostName      string
	KernelVersion string

	// logs
	Logger *fd.Feeder

	// container id -> cotnainer
	Containers     *map[string]tp.Container
	ContainersLock **sync.RWMutex

	// container id -> host pid
	ActiveHostPidMap *map[string]tp.PidMap
	ActivePidMapLock **sync.RWMutex

	// PidID + MntID -> container id
	NsMap     map[NsKey]string
	NsMapLock *sync.RWMutex

	// system monitor (for container)
	BpfModule *cle.Collection

	// Probes Links
	Probes map[string]link.Link

	// HostProbes Links
	HostProbes map[string]link.Link

	// context + args (for container)
	ContextChan chan ContextCombined

	// process + file (for container)
	SyscallChannel     chan []byte
	SyscallLostChannel chan uint64
	SyscallPerfMap     *perf.Reader

	// system monitor (for host)
	HostBpfModule *cle.Collection

	// context + args (for host)
	HostContextChan chan ContextCombined

	// process + file (for host)
	HostSyscallChannel     chan []byte
	HostSyscallLostChannel chan uint64
	HostSyscallPerfMap     *perf.Reader

	// lists to skip
	UntrackedNamespaces []string

	UptimeTimeStamp float64
	HostByteOrder   binary.ByteOrder

	// ticker to clean up exited pids
	Ticker *time.Ticker
}

// NewSystemMonitor Function
func NewSystemMonitor(node tp.Node, logger *fd.Feeder, containers *map[string]tp.Container, containersLock **sync.RWMutex,
	activePidMap *map[string]tp.PidMap, activeHostPidMap *map[string]tp.PidMap, activePidMapLock **sync.RWMutex,
	activeHostMap *map[uint32]tp.PidMap, activeHostMapLock **sync.RWMutex) *SystemMonitor {
	mon := new(SystemMonitor)

	mon.HostName = cfg.GlobalCfg.Host
	mon.KernelVersion = node.KernelVersion

	mon.Logger = logger

	mon.Containers = containers
	mon.ContainersLock = containersLock

	mon.ActiveHostPidMap = activeHostPidMap
	mon.ActivePidMapLock = activePidMapLock

	mon.NsMap = make(map[NsKey]string)
	mon.NsMapLock = new(sync.RWMutex)

	mon.ContextChan = make(chan ContextCombined, 4096)
	mon.HostContextChan = make(chan ContextCombined, 4096)

	mon.UntrackedNamespaces = []string{"kube-system", "kubearmor"}

	mon.UptimeTimeStamp = kl.GetUptimeTimestamp()
	mon.HostByteOrder = binary.LittleEndian

	mon.Ticker = time.NewTicker(time.Second * 10)

	return mon
}

// InitBPF Function
func (mon *SystemMonitor) InitBPF() error {
	homeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}

	if kl.IsInK8sCluster() {
		if b, err := ioutil.ReadFile(filepath.Clean("/media/root/etc/os-release")); err == nil {
			s := string(b)
			if strings.Contains(s, "Container-Optimized OS") {
				mon.Logger.Print("Detected Container-Optimized OS, started to download kernel headers for COS")

				// check and download kernel headers
				if err := kl.RunCommandAndWaitWithErr(homeDir+"/GKE/download_cos_kernel_headers.sh", []string{}); err != nil {
					mon.Logger.Errf("Failed to download COS kernel headers (%s)", err.Error())
					return err
				}

				mon.Logger.Printf("Downloaded kernel headers (%s)", mon.KernelVersion)

				// set a new location for kernel headers
				if err := os.Setenv("BCC_KERNEL_SOURCE", homeDir+"/GKE/kernel/usr/src/linux-headers-"+mon.KernelVersion); err != nil {
					mon.Logger.Err(err.Error())
				}

				// just for safety
				time.Sleep(time.Second * 1)
			} else {
				// In case of GKE COS release >= 1.22, the base OS img does not
				// contain /usr/src folder. Thus we now mount /usr folder to
				// /media/root/usr folder in kubearmor for GKE. The following code
				// checks whether the /media/root/usr/src/kernel-hdrs path exists
				// and uses it for BCC kernel source, if present.
				lklhdrpath := "/media/root/usr/src/linux-headers-" + mon.KernelVersion
				mon.Logger.Printf("checking if kernel headers path (%s) exists", lklhdrpath)
				if _, err := os.Stat(lklhdrpath); err == nil {
					mon.Logger.Printf("using kernel headers from (%s)", lklhdrpath)
					if err := os.Setenv("BCC_KERNEL_SOURCE", lklhdrpath); err != nil {
						mon.Logger.Errf("setenv failed for [BCC_KERNEL_SOURCE=%s] Error=%s", lklhdrpath, err.Error())
					}
				}
			}
		}
	}

	bpfPath := homeDir + "/BPF/"
	if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil {
		// go test

		bpfPath = os.Getenv("PWD") + "/../BPF/"
		if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil {
			return err
		}
	}

	mon.Logger.Print("Initializing an eBPF program")

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error removing memlock %v", err)
	}

	if cfg.GlobalCfg.Policy && !cfg.GlobalCfg.HostPolicy { // container only
		mon.BpfModule, err = cle.LoadCollection(bpfPath + "system_monitor.container.bpf.o")
		if err != nil {
			return fmt.Errorf("bpf module is nil %v", err)
		}
	} else if !cfg.GlobalCfg.Policy && cfg.GlobalCfg.HostPolicy { // host only
		mon.HostBpfModule, err = cle.LoadCollection(bpfPath + "system_monitor.host.bpf.o")
		if err != nil {
			return fmt.Errorf("bpf module is nil %v", err)
		}
	} else if cfg.GlobalCfg.Policy && cfg.GlobalCfg.HostPolicy { // container and host
		if strings.HasPrefix(mon.KernelVersion, "4.") { // 4.x
			mon.BpfModule, err = cle.LoadCollection(bpfPath + "system_monitor.bpf.o")
			if err != nil {
				return fmt.Errorf("bpf module is nil %v", err)
			}
		} else { // 5.x
			mon.BpfModule, err = cle.LoadCollection(bpfPath + "system_monitor.container.bpf.o")
			if err != nil {
				return fmt.Errorf("bpf module is nil %v", err)
			}

			mon.HostBpfModule, err = cle.LoadCollection(bpfPath + "system_monitor.host.bpf.o")
			if err != nil {
				return fmt.Errorf("bpf module is nil %v", err)
			}
		}
	}

	mon.Logger.Print("Initialized the eBPF program")

	// sysPrefix := bcc.GetSyscallPrefix()
	systemCalls := []string{"open", "openat", "execve", "execveat", "socket", "connect", "accept", "bind", "listen"}
	// {category, event}
	sysTracepoints := [][2]string{{"syscalls", "sys_exit_openat"}}
	sysKprobes := []string{"do_exit", "security_bprm_check", "security_file_open"}

	if mon.BpfModule != nil {

		mon.Probes = make(map[string]link.Link)

		for _, syscallName := range systemCalls {
			mon.Probes["kprobe__"+syscallName], err = link.Kprobe("sys_"+syscallName, mon.BpfModule.Programs["kprobe__"+syscallName])
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", syscallName, err)
			}

			mon.Probes["kretprobe__"+syscallName], err = link.Kretprobe("sys_"+syscallName, mon.BpfModule.Programs["kretprobe__"+syscallName])
			if err != nil {
				return fmt.Errorf("error loading kretprobe %s: %v", syscallName, err)
			}

		}

		for _, sysTracepoint := range sysTracepoints {
			mon.Probes[sysTracepoint[1]], err = link.Tracepoint(sysTracepoint[0], sysTracepoint[1], mon.BpfModule.Programs[sysTracepoint[1]])
			if err != nil {
				return fmt.Errorf("error:%s: %v", sysTracepoint, err)
			}
		}

		for _, sysKprobe := range sysKprobes {
			mon.Probes["kprobe__"+sysKprobe], err = link.Kprobe(sysKprobe, mon.BpfModule.Programs["kprobe__"+sysKprobe])
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", sysKprobe, err)
			}
		}

		mon.SyscallChannel = make(chan []byte, 8192)
		mon.SyscallLostChannel = make(chan uint64)

		mon.SyscallPerfMap, err = perf.NewReader(mon.BpfModule.Maps["sys_events"], os.Getpagesize())
		if err != nil {
			return fmt.Errorf("error initializing events perf map: %v", err)
		}
	}

	if mon.HostBpfModule != nil {

		mon.HostProbes = make(map[string]link.Link)

		for _, syscallName := range systemCalls {
			mon.HostProbes["kprobe__"+syscallName], err = link.Kprobe("sys_"+syscallName, mon.HostBpfModule.Programs["kprobe__"+syscallName])
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", syscallName, err)
			}

			mon.HostProbes["kretprobe__"+syscallName], err = link.Kretprobe("sys_"+syscallName, mon.HostBpfModule.Programs["kretprobe__"+syscallName])
			if err != nil {
				return fmt.Errorf("error loading kretprobe %s: %v", syscallName, err)
			}

		}

		for _, sysTracepoint := range sysTracepoints {
			mon.HostProbes[sysTracepoint[1]], err = link.Tracepoint(sysTracepoint[0], sysTracepoint[1], mon.HostBpfModule.Programs[sysTracepoint[1]])
			if err != nil {
				return fmt.Errorf("error:%s: %v", sysTracepoint, err)
			}
		}

		for _, sysKprobe := range sysKprobes {
			mon.HostProbes["kprobe__"+sysKprobe], err = link.Kprobe(sysKprobe, mon.HostBpfModule.Programs["kprobe__"+sysKprobe])
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", sysKprobe, err)
			}
		}

		mon.HostSyscallChannel = make(chan []byte, 8192)
		mon.HostSyscallLostChannel = make(chan uint64)

		mon.HostSyscallPerfMap, err = perf.NewReader(mon.HostBpfModule.Maps["sys_events"], os.Getpagesize())
		if err != nil {
			return fmt.Errorf("error initializing events perf map: %v", err)
		}
	}

	return nil
}

// DestroySystemMonitor Function
func (mon *SystemMonitor) DestroySystemMonitor() error {
	if mon.SyscallPerfMap != nil {
		if err := mon.SyscallPerfMap.Close(); err != nil {
			return err
		}
	}

	if mon.BpfModule != nil {
		mon.BpfModule.Close()
	}

	if mon.ContextChan != nil {
		close(mon.ContextChan)
	}

	if mon.HostSyscallPerfMap != nil {
		if err := mon.HostSyscallPerfMap.Close(); err != nil {
			return err
		}
	}

	if mon.HostBpfModule != nil {
		mon.HostBpfModule.Close()
	}

	if mon.HostContextChan != nil {
		close(mon.HostContextChan)
	}

	for _, link := range mon.Probes {
		if err := link.Close(); err != nil {
			return err
		}
	}

	for _, link := range mon.HostProbes {
		if err := link.Close(); err != nil {
			return err
		}
	}

	mon.Ticker.Stop()

	return nil
}

// ======================= //
// == System Call Trace == //
// ======================= //

// TraceSyscall Function
func (mon *SystemMonitor) TraceSyscall() {
	if mon.SyscallPerfMap != nil {
		go func() {
			for {
				record, err := mon.SyscallPerfMap.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						return
					}
					continue
				}

				if record.LostSamples != 0 {
					mon.SyscallLostChannel <- record.LostSamples
					continue
				}

				mon.SyscallChannel <- record.RawSample

			}
		}()
	} else {
		return
	}

	Containers := *(mon.Containers)
	ContainersLock := *(mon.ContainersLock)

	execLogMap := map[uint32]tp.Log{}

	for {
		select {
		case <-StopChan:
			return

		case dataRaw, valid := <-mon.SyscallChannel:
			if !valid {
				continue
			}

			dataBuff := bytes.NewBuffer(dataRaw)
			ctx, err := readContextFromBuff(dataBuff)
			if err != nil {
				continue
			}

			args, err := GetArgs(dataBuff, ctx.Argnum)
			if err != nil {
				continue
			}

			containerID := ""

			if ctx.PidID != 0 && ctx.MntID != 0 {
				containerID = mon.LookupContainerID(ctx.PidID, ctx.MntID, ctx.HostPPID, ctx.HostPID)

				if containerID != "" {
					ContainersLock.RLock()
					namespace := Containers[containerID].NamespaceName
					if kl.ContainsElement(mon.UntrackedNamespaces, namespace) {
						ContainersLock.RUnlock()
						continue
					}
					ContainersLock.RUnlock()
				}
			}

			if ctx.PidID != 0 && ctx.MntID != 0 && containerID == "" {
				continue
			}

			if ctx.EventID == SysOpen {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == SysOpenAt {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SysExecve {
				if len(args) == 2 { // enter
					// build a pid node
					pidNode := mon.BuildPidNode(containerID, ctx, args[0].(string), args[1].([]string))
					mon.AddActivePid(containerID, pidNode)

					// generate a log with the base information
					log := mon.BuildLogBase(ContextCombined{ContainerID: containerID, ContextSys: ctx})

					// add arguments
					if val, ok := args[0].(string); ok {
						log.Resource = val // procExecPath
					}
					if val, ok := args[1].([]string); ok {
						for idx, arg := range val { // procArgs
							if idx == 0 {
								continue
							} else {
								log.Resource = log.Resource + " " + arg
							}
						}
					}

					log.Operation = "Process"
					log.Data = "syscall=" + getSyscallName(int32(ctx.EventID))

					// store the log in the map
					execLogMap[ctx.HostPID] = log

				} else if len(args) == 0 { // return
					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

					// update the log again
					log = mon.UpdateLogBase(ctx.EventID, log)

					// get error message
					if ctx.Retval < 0 {
						message := getErrorMessage(ctx.Retval)
						if message != "" {
							log.Result = message
						} else {
							log.Result = fmt.Sprintf("Unknown (%d)", ctx.Retval)
						}
					} else {
						log.Result = "Passed"
					}

					// push the generated log
					if mon.Logger != nil {
						go mon.Logger.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == SysExecveAt {
				if len(args) == 4 { // enter
					// build a pid node
					pidNode := mon.BuildPidNode(containerID, ctx, args[1].(string), args[2].([]string))
					mon.AddActivePid(containerID, pidNode)

					// generate a log with the base information
					log := mon.BuildLogBase(ContextCombined{ContainerID: containerID, ContextSys: ctx})

					fd := ""
					procExecFlag := ""

					// add arguments
					if val, ok := args[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := args[1].(string); ok {
						log.Resource = val // procExecPath
					}
					if val, ok := args[2].([]string); ok {
						for idx, arg := range val { // procArgs
							if idx == 0 {
								continue
							} else {
								log.Resource = log.Resource + " " + arg
							}
						}
					}
					if val, ok := args[3].(string); ok {
						procExecFlag = val
					}

					log.Operation = "Process"
					log.Data = "syscall=" + getSyscallName(int32(ctx.EventID)) + " fd=" + fd + " flag=" + procExecFlag

					// store the log in the map
					execLogMap[ctx.HostPID] = log

				} else if len(args) == 0 { // return
					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

					// update the log again
					log = mon.UpdateLogBase(ctx.EventID, log)

					// get error message
					if ctx.Retval < 0 {
						message := getErrorMessage(ctx.Retval)
						if message != "" {
							log.Result = message
						} else {
							log.Result = fmt.Sprintf("Unknown (%d)", ctx.Retval)
						}
					} else {
						log.Result = "Passed"
					}

					// push the generated log
					if mon.Logger != nil {
						go mon.Logger.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == DoExit {
				mon.DeleteActivePid(containerID, ctx)
				continue
			} else if ctx.EventID == SecurityBprmCheck {
				if val, ok := args[0].(string); ok {
					mon.UpdateExecPath(containerID, ctx.HostPID, val)
				}
				continue
			}

			// push the context to the channel for logging
			mon.ContextChan <- ContextCombined{ContainerID: containerID, ContextSys: ctx, ContextArgs: args}

		case <-mon.SyscallLostChannel:
			continue
		}
	}
}

// TraceHostSyscall Function
func (mon *SystemMonitor) TraceHostSyscall() {
	if mon.HostSyscallPerfMap != nil {
		go func() {
			for {
				record, err := mon.SyscallPerfMap.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						return
					}
					continue
				}

				if record.LostSamples != 0 {
					mon.SyscallLostChannel <- record.LostSamples
					continue
				}

				mon.SyscallChannel <- record.RawSample

			}
		}()
	} else {
		return
	}

	execLogMap := map[uint32]tp.Log{}

	for {
		select {
		case <-StopChan:
			return

		case dataRaw, valid := <-mon.HostSyscallChannel:
			if !valid {
				continue
			}

			dataBuff := bytes.NewBuffer(dataRaw)
			ctx, err := readContextFromBuff(dataBuff)
			if err != nil {
				continue
			}

			args, err := GetArgs(dataBuff, ctx.Argnum)
			if err != nil {
				continue
			}

			if ctx.EventID == SysOpen {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == SysOpenAt {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SysExecve {
				if len(args) == 2 { // enter
					// build a pid node
					pidNode := mon.BuildPidNode("", ctx, args[0].(string), args[1].([]string))
					mon.AddActivePid("", pidNode)

					// generate a log with the base information
					log := mon.BuildLogBase(ContextCombined{ContainerID: "", ContextSys: ctx})

					// add arguments
					if val, ok := args[0].(string); ok {
						log.Resource = val // procExecPath
					}
					if val, ok := args[1].([]string); ok {
						for idx, arg := range val { // procArgs
							if idx == 0 {
								continue
							} else {
								log.Resource = log.Resource + " " + arg
							}
						}
					}

					log.Operation = "Process"
					log.Data = "syscall=" + getSyscallName(int32(ctx.EventID))

					// store the log in the map
					execLogMap[ctx.HostPID] = log

				} else if len(args) == 0 { // return
					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

					// update the log again
					if !strings.HasPrefix(log.Source, "/") {
						log = mon.UpdateLogBase(ctx.EventID, log)
					}

					// get error message
					if ctx.Retval < 0 {
						message := getErrorMessage(ctx.Retval)
						if message != "" {
							log.Result = message
						} else {
							log.Result = fmt.Sprintf("Unknown (%d)", ctx.Retval)
						}
					} else {
						log.Result = "Passed"
					}

					// push the generated log
					if mon.Logger != nil {
						go mon.Logger.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == SysExecveAt {
				if len(args) == 4 { // enter
					// build a pid node
					pidNode := mon.BuildPidNode("", ctx, args[1].(string), args[2].([]string))
					mon.AddActivePid("", pidNode)

					// generate a log with the base information
					log := mon.BuildLogBase(ContextCombined{ContainerID: "", ContextSys: ctx})

					fd := ""
					procExecFlag := ""

					// add arguments
					if val, ok := args[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := args[1].(string); ok {
						log.Resource = val // procExecPath
					}
					if val, ok := args[2].([]string); ok {
						for idx, arg := range val { // procArgs
							if idx == 0 {
								continue
							} else {
								log.Resource = log.Resource + " " + arg
							}
						}
					}
					if val, ok := args[3].(string); ok {
						procExecFlag = val
					}

					log.Operation = "Process"
					log.Data = "syscall=" + getSyscallName(int32(ctx.EventID)) + " fd=" + fd + " flag=" + procExecFlag

					// store the log in the map
					execLogMap[ctx.HostPID] = log

				} else if len(args) == 0 { // return
					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

					// update the log again
					if !strings.HasPrefix(log.Source, "/") {
						log = mon.UpdateLogBase(ctx.EventID, log)
					}

					// get error message
					if ctx.Retval < 0 {
						message := getErrorMessage(ctx.Retval)
						if message != "" {
							log.Result = message
						} else {
							log.Result = fmt.Sprintf("Unknown (%d)", ctx.Retval)
						}
					} else {
						log.Result = "Passed"
					}

					// push the generated log
					if mon.Logger != nil {
						go mon.Logger.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == DoExit {
				mon.DeleteActivePid("", ctx)
				continue
			} else if ctx.EventID == SecurityBprmCheck {
				if val, ok := args[0].(string); ok {
					mon.UpdateExecPath("", ctx.HostPID, val)
				}
				continue
			}

			// push the context to the channel for logging
			mon.HostContextChan <- ContextCombined{ContainerID: "", ContextSys: ctx, ContextArgs: args}

		case <-mon.HostSyscallLostChannel:
			continue
		}
	}
}
