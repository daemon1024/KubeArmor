package monitor

import (
	"sync"
	"testing"
	"time"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestSystemMonitor(t *testing.T) {
	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := new(sync.RWMutex)

	// container id -> (host) pid
	ActivePidMap := map[string]tp.PidMap{}
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)

	// host pid
	ActiveHostMap := map[uint32]tp.PidMap{}
	ActiveHostMapLock := new(sync.RWMutex)

	// Create Feeder
	logFeeder := fd.NewFeeder("Default", "32767", "none", "policy", true)
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}

	// Create System Monitor

	systemMonitor := NewSystemMonitor(logFeeder, false, true, &Containers, &ContainersLock,
		&ActivePidMap, &ActiveHostPidMap, &ActivePidMapLock, &ActiveHostMap, &ActiveHostMapLock)
	if systemMonitor == nil {
		t.Log("[FAIL] Failed to create SystemMonitor")
		return
	}

	t.Log("[PASS] Created SystemMonitor")

	// Destroy System Monitor

	if err := systemMonitor.DestroySystemMonitor(); err != nil {
		t.Log("[FAIL] Failed to destroy SystemMonitor")
	}

	t.Log("[PASS] Destroyed SystemMonitor")

	// destroy Feeder
	if err := logFeeder.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy Feeder")
		return
	}

	t.Log("[PASS] Destroyed Feeder")
}

func TestTraceSyscall(t *testing.T) {
	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := new(sync.RWMutex)

	// container id -> (host) pid
	ActivePidMap := map[string]tp.PidMap{}
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)

	// host pid
	ActiveHostMap := map[uint32]tp.PidMap{}
	ActiveHostMapLock := new(sync.RWMutex)

	// Create Feeder
	logFeeder := fd.NewFeeder("Default", "32767", "none", "policy", true)
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}

	// Create System Monitor

	systemMonitor := NewSystemMonitor(logFeeder, false, false, &Containers, &ContainersLock,
		&ActivePidMap, &ActiveHostPidMap, &ActivePidMapLock, &ActiveHostMap, &ActiveHostMapLock)
	if systemMonitor == nil {
		t.Log("[FAIL] Failed to create SystemMonitor")
		return
	}

	t.Log("[PASS] Created SystemMonitor")

	// Initialize BPF

	if err := systemMonitor.InitBPF(); err != nil {
		t.Errorf("[FAIL] Failed to initialize BPF (%s)", err.Error())
		return
	}

	t.Logf("[PASS] Initialized BPF (for container only)")

	// wait for a while

	time.Sleep(time.Second * 1)

	// Start to trace syscalls

	go systemMonitor.TraceSyscall()

	t.Log("[PASS] Started to trace syscalls")

	// wait for a while

	time.Sleep(time.Second * 1)

	// Destroy System Monitor

	if err := systemMonitor.DestroySystemMonitor(); err != nil {
		t.Log("[FAIL] Failed to destroy SystemMonitor")
	}

	t.Log("[PASS] Destroyed SystemMonitor")

	// destroy Feeder
	if err := logFeeder.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy Feeder")
		return
	}

	t.Log("[PASS] Destroyed Feeder")
}

func TestTraceSyscallWithHost(t *testing.T) {
	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := new(sync.RWMutex)

	// container id -> (host) pid
	ActivePidMap := map[string]tp.PidMap{}
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)

	// host pid
	ActiveHostMap := map[uint32]tp.PidMap{}
	ActiveHostMapLock := new(sync.RWMutex)

	// Create Feeder
	logFeeder := fd.NewFeeder("Default", "32767", "none", "policy", true)
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}

	// Create System Monitor

	systemMonitor := NewSystemMonitor(logFeeder, false, true, &Containers, &ContainersLock,
		&ActivePidMap, &ActiveHostPidMap, &ActivePidMapLock, &ActiveHostMap, &ActiveHostMapLock)
	if systemMonitor == nil {
		t.Log("[FAIL] Failed to create SystemMonitor")
		return
	}

	t.Log("[PASS] Created SystemMonitor")

	// Initialize BPF

	if err := systemMonitor.InitBPF(); err != nil {
		t.Errorf("[FAIL] Failed to initialize BPF (%s)", err.Error())
		return
	}

	t.Logf("[PASS] Initialized BPF (for container and host)")

	// wait for a while

	time.Sleep(time.Second * 1)

	// Start to trace syscalls for container

	go systemMonitor.TraceSyscall()

	t.Log("[PASS] Started to trace syscalls")

	// Start to trace syscalls for host

	go systemMonitor.TraceHostSyscall()

	t.Log("[PASS] Started to trace syscalls")

	// wait for a while

	time.Sleep(time.Second * 1)

	// Destroy System Monitor

	if err := systemMonitor.DestroySystemMonitor(); err != nil {
		t.Log("[FAIL] Failed to destroy SystemMonitor")
	}

	t.Log("[PASS] Destroyed SystemMonitor")

	// destroy Feeder
	if err := logFeeder.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy Feeder")
		return
	}

	t.Log("[PASS] Destroyed Feeder")
}
