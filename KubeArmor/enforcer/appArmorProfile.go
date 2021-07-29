// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package enforcer

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

func allowedProcessMatchPaths(enableAuditd bool, path tp.ProcessPathType, processWhiteList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			}
		} else { // !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit %s ix,\n", path.Path)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func allowedProcessMatchDirectories(enableAuditd bool, dir tp.ProcessDirectoryType, processWhiteList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processWhiteList, line) {
					*processWhiteList = append(*processWhiteList, line)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func allowedProcessMatchPatterns(enableAuditd bool, pat tp.ProcessPatternType, processWhiteList *[]string) {
	if pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processWhiteList, line) {
				*processWhiteList = append(*processWhiteList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processWhiteList, line) {
				*processWhiteList = append(*processWhiteList, line)
			}
		}
	} else { // !pat.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit %s* ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processWhiteList, line) {
				*processWhiteList = append(*processWhiteList, line)
			}
		} else {
			line := fmt.Sprintf("  %s* ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processWhiteList, line) {
				*processWhiteList = append(*processWhiteList, line)
			}
		}
	}
}

func allowedFileMatchPaths(enableAuditd bool, path tp.FilePathType, fileWhiteList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileWhiteList, line) {
					*fileWhiteList = append(*fileWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileWhiteList, line) {
					*fileWhiteList = append(*fileWhiteList, line)
				}
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit %s r,\n", path.Path)
				if !kl.ContainsElement(*fileWhiteList, line) {
					*fileWhiteList = append(*fileWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  %s r,\n", path.Path)
				if !kl.ContainsElement(*fileWhiteList, line) {
					*fileWhiteList = append(*fileWhiteList, line)
				}
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileWhiteList, line) {
					*fileWhiteList = append(*fileWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileWhiteList, line) {
					*fileWhiteList = append(*fileWhiteList, line)
				}
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileWhiteList, line) {
					*fileWhiteList = append(*fileWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileWhiteList, line) {
					*fileWhiteList = append(*fileWhiteList, line)
				}
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func allowedFileMatchDirectories(enableAuditd bool, dir tp.FileDirectoryType, fileWhiteList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileWhiteList, line) {
						*fileWhiteList = append(*fileWhiteList, line)
					}
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			}
		}
	}
}

func allowedFileMatchPatterns(enableAuditd bool, pat tp.FilePatternType, fileWhiteList *[]string) {
	if pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileWhiteList, line) {
				*fileWhiteList = append(*fileWhiteList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileWhiteList, line) {
				*fileWhiteList = append(*fileWhiteList, line)
			}
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileWhiteList, line) {
				*fileWhiteList = append(*fileWhiteList, line)
			}
		} else {
			line := fmt.Sprintf("  %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileWhiteList, line) {
				*fileWhiteList = append(*fileWhiteList, line)
			}
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileWhiteList, line) {
				*fileWhiteList = append(*fileWhiteList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileWhiteList, line) {
				*fileWhiteList = append(*fileWhiteList, line)
			}
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileWhiteList, line) {
				*fileWhiteList = append(*fileWhiteList, line)
			}
		} else {
			line := fmt.Sprintf("  %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileWhiteList, line) {
				*fileWhiteList = append(*fileWhiteList, line)
			}
		}
	}
}

func allowedNetworkMatchProtocols(proto tp.NetworkProtocolType, networkWhiteList *[]string, fromSources map[string][]string) {
	if len(proto.FromSource) == 0 {
		line := fmt.Sprintf("  network %s,\n", proto.Protocol)
		if !kl.ContainsElement(*networkWhiteList, line) {
			*networkWhiteList = append(*networkWhiteList, line)
		}
	} else {
		for _, src := range proto.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  network %s,\n", proto.Protocol)
			if !kl.ContainsElement(fromSources[source], line) {
				fromSources[source] = append(fromSources[source], line)
			}
		}
	}
}

func allowedCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, capabilityWhiteList *[]string, fromSources map[string][]string) {
	if len(cap.FromSource) == 0 {
		line := fmt.Sprintf("  capability %s,\n", cap.Capability)
		if !kl.ContainsElement(*capabilityWhiteList, line) {
			*capabilityWhiteList = append(*capabilityWhiteList, line)
		}
	} else {
		for _, src := range cap.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  capability %s,\n", cap.Capability)
			if !kl.ContainsElement(fromSources[source], line) {
				fromSources[source] = append(fromSources[source], line)
			}
		}
	}
}

//

func auditedProcessMatchPaths(enableAuditd bool, path tp.ProcessPathType, processAuditList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		} else { // !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit %s ix,\n", path.Path)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func auditedProcessMatchDirectories(enableAuditd bool, dir tp.ProcessDirectoryType, processAuditList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func auditedProcessMatchPatterns(enableAuditd bool, pat tp.ProcessPatternType, processAuditList *[]string) {
	if pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		}
	} else { // !pat.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit %s* ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  %s* ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		}
	}
}

func auditedFileMatchPaths(enableAuditd bool, path tp.FilePathType, fileAuditList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit %s r,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s r,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func auditedFileMatchDirectories(enableAuditd bool, dir tp.FileDirectoryType, fileAuditList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			}
		}
	}
}

func auditedFileMatchPatterns(enableAuditd bool, pat tp.FilePatternType, fileAuditList *[]string) {
	if pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		}
	}
}

//

func blockedProcessMatchPaths(enableAuditd bool, path tp.ProcessPathType, processBlackList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		} else { // !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s x,\n", path.Path)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s x,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func blockedProcessMatchDirectories(enableAuditd bool, dir tp.ProcessDirectoryType, processBlackList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func blockedProcessMatchPatterns(enableAuditd bool, pat tp.ProcessPatternType, processBlackList *[]string) {
	if pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		}
	} else { // !path.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit deny %s x,\n", pat.Pattern)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  deny %s x,\n", pat.Pattern)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		}
	}
}

func blockedFileMatchPaths(enableAuditd bool, path tp.FilePathType, fileBlackList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s w,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s w,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s w,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s w,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func blockedFileMatchDirectories(enableAuditd bool, dir tp.FileDirectoryType, fileBlackList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s{*,**} w,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s* w,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit deny %s{*,**} w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit deny %s* w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  deny %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			}
		}
	}
}

func blockedFileMatchPatterns(enableAuditd bool, pat tp.FilePatternType, fileBlackList *[]string) {
	if pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit deny %s w,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  deny %s w,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit deny %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  deny %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		}
	}
}

func blockedNetworkMatchProtocols(proto tp.NetworkProtocolType, networkBlackList *[]string, fromSources map[string][]string) {
	if len(proto.FromSource) == 0 {
		line := fmt.Sprintf("  deny network %s,\n", proto.Protocol)
		if !kl.ContainsElement(*networkBlackList, line) {
			*networkBlackList = append(*networkBlackList, line)
		}
	} else {
		for _, src := range proto.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  deny network %s,\n", proto.Protocol)
			if !kl.ContainsElement(fromSources[source], line) {
				fromSources[source] = append(fromSources[source], line)
			}
		}
	}
}

func blockedCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, capabilityBlackList *[]string, fromSources map[string][]string) {
	if len(cap.FromSource) == 0 {
		line := fmt.Sprintf("  deny capability %s,\n", cap.Capability)
		if !kl.ContainsElement(*capabilityBlackList, line) {
			*capabilityBlackList = append(*capabilityBlackList, line)
		}
	} else {
		for _, src := range cap.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  deny capability %s,\n", cap.Capability)
			if !kl.ContainsElement(fromSources[source], line) {
				fromSources[source] = append(fromSources[source], line)
			}
		}
	}
}

// == //

// GenerateProfileHead Function
func GenerateProfileHead(processWhiteList, fileWhiteList, networkWhiteList, capabilityWhiteList []string) string {
	profileHead := "  #include <abstractions/base>\n"
	profileHead = profileHead + "  umount,\n"

	if len(processWhiteList) == 0 && len(fileWhiteList) == 0 {
		profileHead = profileHead + "  file,\n"
	}

	if len(networkWhiteList) == 0 {
		profileHead = profileHead + "  network,\n"
	}

	if len(capabilityWhiteList) == 0 {
		profileHead = profileHead + "  capability,\n"
	}

	return profileHead
}

// GenerateProfileFoot Function
func GenerateProfileFoot() string {
	profileFoot := "  /lib/x86_64-linux-gnu/{*,**} r,\n"
	profileFoot = profileFoot + "\n"
	profileFoot = profileFoot + "  deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,\n"
	profileFoot = profileFoot + "  deny @{PROC}/sysrq-trigger rwklx,\n"
	profileFoot = profileFoot + "  deny @{PROC}/mem rwklx,\n"
	profileFoot = profileFoot + "  deny @{PROC}/kmem rwklx,\n"
	profileFoot = profileFoot + "  deny @{PROC}/kcore rwklx,\n"
	profileFoot = profileFoot + "\n"
	profileFoot = profileFoot + "  deny mount,\n"
	profileFoot = profileFoot + "\n"
	profileFoot = profileFoot + "  deny /sys/[^f]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/f[^s]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/fs/[^c]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/fs/c[^g]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/fs/cg[^r]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/firmware/efi/efivars/** rwklx,\n"
	profileFoot = profileFoot + "  deny /sys/kernel/security/** rwklx,\n"

	return profileFoot
}

// == //

// GenerateProfileBody Function
func GenerateProfileBody(enableAuditd bool, oldContentsPreMid, oldConetntsMidPost []string, securityPolicies []tp.SecurityPolicy) (int, string) {
	// preparation

	count := 0

	processWhiteList := []string{}
	processAuditList := []string{}
	processBlackList := []string{}

	fileWhiteList := []string{}
	fileAuditList := []string{}
	fileBlackList := []string{}

	networkWhiteList := []string{}
	networkBlackList := []string{}

	capabilityWhiteList := []string{}
	capabilityBlackList := []string{}

	fromSources := map[string][]string{}

	nativeAppArmorRules := []string{}

	// preparation

	for _, secPolicy := range securityPolicies {
		if len(secPolicy.Spec.AppArmor) > 0 {
			scanner := bufio.NewScanner(strings.NewReader(secPolicy.Spec.AppArmor))
			for scanner.Scan() {
				line := "  " + strings.TrimSpace(scanner.Text()) + "\n"
				nativeAppArmorRules = append(nativeAppArmorRules, line)
			}
		}

		if len(secPolicy.Spec.Process.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.Process.MatchPaths {
				if path.Action == "Allow" || path.Action == "AllowWithAudit" {
					allowedProcessMatchPaths(enableAuditd, path, &processWhiteList, fromSources)
				} else if path.Action == "Audit" {
					auditedProcessMatchPaths(enableAuditd, path, &processAuditList, fromSources)
				} else if path.Action == "Block" || path.Action == "BlockWithAudit" {
					blockedProcessMatchPaths(enableAuditd, path, &processBlackList, fromSources)
				}
			}
		} else if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" || dir.Action == "AllowWithAudit" {
					allowedProcessMatchDirectories(enableAuditd, dir, &processWhiteList, fromSources)
				} else if dir.Action == "Audit" {
					auditedProcessMatchDirectories(enableAuditd, dir, &processAuditList, fromSources)
				} else if dir.Action == "Block" || dir.Action == "BlockWithAudit" {
					blockedProcessMatchDirectories(enableAuditd, dir, &processBlackList, fromSources)
				}
			}
		} else if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.Process.MatchPatterns {
				if pat.Action == "Allow" || pat.Action == "AllowWithAudit" {
					allowedProcessMatchPatterns(enableAuditd, pat, &processWhiteList)
				} else if pat.Action == "Audit" {
					auditedProcessMatchPatterns(enableAuditd, pat, &processAuditList)
				} else if pat.Action == "Block" || pat.Action == "BlockWithAudit" {
					blockedProcessMatchPatterns(enableAuditd, pat, &processBlackList)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" || path.Action == "AllowWithAudit" {
					allowedFileMatchPaths(enableAuditd, path, &fileWhiteList, fromSources)
				} else if path.Action == "Audit" {
					auditedFileMatchPaths(enableAuditd, path, &fileAuditList, fromSources)
				} else if path.Action == "Block" || path.Action == "BlockWithAudit" {
					blockedFileMatchPaths(enableAuditd, path, &fileBlackList, fromSources)
				}
			}
		} else if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" || dir.Action == "AllowWithAudit" {
					allowedFileMatchDirectories(enableAuditd, dir, &fileWhiteList, fromSources)
				} else if dir.Action == "Audit" {
					auditedFileMatchDirectories(enableAuditd, dir, &fileAuditList, fromSources)
				} else if dir.Action == "Block" || dir.Action == "BlockWithAudit" {
					blockedFileMatchDirectories(enableAuditd, dir, &fileBlackList, fromSources)
				}
			}
		} else if len(secPolicy.Spec.File.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.File.MatchPatterns {
				if pat.Action == "Allow" || pat.Action == "AllowWithAudit" {
					allowedFileMatchPatterns(enableAuditd, pat, &fileWhiteList)
				} else if pat.Action == "Audit" {
					auditedFileMatchPatterns(enableAuditd, pat, &fileAuditList)
				} else if pat.Action == "Block" || pat.Action == "BlockWithAudit" {
					blockedFileMatchPatterns(enableAuditd, pat, &fileBlackList)
				}
			}
		}

		if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
			for _, proto := range secPolicy.Spec.Network.MatchProtocols {
				if proto.Action == "Allow" || proto.Action == "AllowWithAudit" {
					allowedNetworkMatchProtocols(proto, &networkWhiteList, fromSources)
				} else if proto.Action == "Block" || proto.Action == "BlockWithAudit" {
					blockedNetworkMatchProtocols(proto, &networkBlackList, fromSources)
				}
			}
		}

		if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
			for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
				if cap.Action == "Allow" || cap.Action == "AllowWithAudit" {
					allowedCapabilitiesMatchCapabilities(cap, &capabilityWhiteList, fromSources)
				} else if cap.Action == "Block" || cap.Action == "BlockWithAudit" {
					blockedCapabilitiesMatchCapabilities(cap, &capabilityBlackList, fromSources)
				}
			}
		}
	}

	// head

	profileHead := "  ## == PRE START == ##\n"

	profileHead = profileHead + GenerateProfileHead(processWhiteList, fileWhiteList, networkWhiteList, capabilityWhiteList)

	profileHead = profileHead + "  ## == PRE END == ##\n"

	// body

	profileBody := ""

	// body - from source

	bodyFromSource := ""

	for source, lines := range fromSources {
		bodyFromSource = bodyFromSource + fmt.Sprintf("  %s cx,\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("  profile %s {\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("    %s r,\n", source)

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == PRE START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + "    #include <abstractions/base>\n"
		bodyFromSource = bodyFromSource + "    umount,\n"

		file := true
		network := true
		capability := true

		for _, line := range lines {
			if strings.Contains(line, "  network") {
				network = false
				continue
			}

			if strings.Contains(line, "  capability") {
				capability = false
				continue
			}

			if strings.Contains(line, "  audit owner") {
				continue
			}

			if strings.Contains(line, "  audit deny") {
				continue
			}

			file = false
		}

		if file && len(processWhiteList) == 0 && len(fileWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "    file,\n"
		}

		if network && len(networkWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "    network,\n"
		}

		if capability && len(capabilityWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "    capability,\n"
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == PRE END (%s) == ##\n", source)
		bodyFromSource = bodyFromSource + strings.Replace(profileBody, "  ", "    ", -1)
		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY START (%s) == ##\n\n", source)

		//

		for _, line := range lines {
			bodyFromSource = bodyFromSource + "  " + line
		}

		//

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY END (%s) == ##\n\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POST START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + strings.Replace(GenerateProfileFoot(), "  ", "    ", -1)

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POST END (%s) == ##\n", source)
		bodyFromSource = bodyFromSource + "  }\n"
	}

	for _, source := range fromSources {
		count = count + len(source)
	}

	// body - white list

	for _, line := range processWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(processWhiteList)

	for _, line := range fileWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(fileWhiteList)

	for _, line := range networkWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(networkWhiteList)

	for _, line := range capabilityWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(capabilityWhiteList)

	// body - audit list

	for _, line := range processAuditList {
		profileBody = profileBody + line
	}

	count = count + len(processAuditList)

	for _, line := range fileAuditList {
		profileBody = profileBody + line
	}

	count = count + len(fileAuditList)

	// body - black list

	for _, line := range processBlackList {
		profileBody = profileBody + line
	}

	count = count + len(processBlackList)

	for _, line := range fileBlackList {
		profileBody = profileBody + line
	}

	count = count + len(fileBlackList)

	for _, line := range networkBlackList {
		profileBody = profileBody + line
	}

	count = count + len(networkBlackList)

	for _, line := range capabilityBlackList {
		profileBody = profileBody + line
	}

	count = count + len(capabilityBlackList)

	// body - together

	profileBody = "  ## == POLICY START == ##\n" + bodyFromSource + profileBody + "  ## == POLICY END == ##\n"

	// body - native apparmor
	if len(nativeAppArmorRules) > 0 {
		profileBody = profileBody + "\n  ## == NATIVE POLICY START == ##\n"
		for _, nativeRule := range nativeAppArmorRules {
			profileBody = profileBody + nativeRule
		}
		profileBody = profileBody + "  ## == NATIVE POLICY END == ##\n"
	}
	count = count + len(nativeAppArmorRules)

	// foot

	profileFoot := "  ## == POST START == ##\n" + GenerateProfileFoot() + "  ## == POST END == ##\n"

	// finalization

	profile := profileHead

	for _, preMid := range oldContentsPreMid {
		profile = profile + preMid
	}

	profile = profile + profileBody

	for _, midPost := range oldConetntsMidPost {
		profile = profile + midPost
	}

	profile = profile + profileFoot

	return count, profile
}

// == //

// GenerateAppArmorProfile Function
func (ae *AppArmorEnforcer) GenerateAppArmorProfile(appArmorProfile string, securityPolicies []tp.SecurityPolicy) (int, string, bool) {
	// check apparmor profile

	if _, err := os.Stat("/etc/apparmor.d/" + appArmorProfile); os.IsNotExist(err) {
		return 0, err.Error(), false
	}

	// get the old profile

	oldProfile := ""

	oldContentsHead := []string{}
	oldContentsPreMid := []string{}
	oldConetntsMidPost := []string{}
	oldContentsFoot := []string{}

	file, err := os.Open("/etc/apparmor.d/" + appArmorProfile)
	if err != nil {
		return 0, err.Error(), false
	}

	fscanner := bufio.NewScanner(file)
	pos := "HEAD"

	for fscanner.Scan() {
		line := fscanner.Text()

		oldProfile += (line + "\n")

		if strings.Contains(line, "## == PRE START == ##") {
			pos = "PRE"
			continue
		} else if strings.Contains(line, "## == PRE END == ##") {
			pos = "PRE-MIDDLE"
			continue
		} else if strings.Contains(line, "## == POLICY START == ##") {
			pos = "POLICY"
			continue
		} else if strings.Contains(line, "## == POLICY END == ##") {
			pos = "MIDDLE-POST"
			continue
		} else if strings.Contains(line, "## == POST START == ##") {
			pos = "POST"
			continue
		} else if strings.Contains(line, "## == POST END == ##") {
			pos = "FOOT"
			continue
		} else if strings.Contains(line, "## == NATIVE POLICY START == ##") {
			pos = "NATIVE-START"
			continue
		} else if strings.Contains(line, "## == NATIVE POLICY END == ##") {
			pos = "NATIVE-END"
			continue
		}

		if pos == "HEAD" {
			oldContentsHead = append(oldContentsHead, line+"\n")
		} else if pos == "PRE" {
			//
		} else if pos == "PRE-MIDDLE" {
			oldContentsPreMid = append(oldContentsPreMid, line+"\n")
		} else if pos == "POLICY" {
			//
		} else if pos == "MIDDLE-POST" {
			oldConetntsMidPost = append(oldConetntsMidPost, line+"\n")
		} else if pos == "POST" {
			//
		} else if pos == "FOOT" {
			oldContentsFoot = append(oldContentsFoot, line+"\n")
		}
	}

	file.Close()

	// generate a profile body

	count, profileBody := GenerateProfileBody(ae.EnableAuditd, oldContentsPreMid, oldConetntsMidPost, securityPolicies)

	// generate a new profile

	newProfile := ""

	// head

	for _, head := range oldContentsHead {
		newProfile = newProfile + head
	}

	// body

	newProfile = newProfile + profileBody

	// foot

	for _, foot := range oldContentsFoot {
		newProfile = newProfile + foot
	}

	if newProfile != oldProfile {
		return count, newProfile, true
	}

	return 0, "", false
}
