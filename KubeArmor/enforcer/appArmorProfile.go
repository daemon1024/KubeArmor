// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

// ResolvedProcessWhiteListConflicts Function
func (ae *AppArmorEnforcer) ResolvedProcessWhiteListConflicts(rules *ruleList) {
	prunedProcessWhiteList := make([]string, len(*&rules.elements.processWhiteList))
	copy(prunedProcessWhiteList, (*rules).elements.processWhiteList)
	numOfRemovedElements := 0

	for index, line := range (*rules).elements.processWhiteList {
		for source := range (*rules).fromSources {
			if strings.Contains(line, source) {
				(*rules).fusionProcessWhiteList = append((*rules).fusionProcessWhiteList, source)

				// remove line from WhiteList
				prunedProcessWhiteList = kl.RemoveStringElement(prunedProcessWhiteList, index-numOfRemovedElements)
				numOfRemovedElements = numOfRemovedElements + 1
			}
		}
	}

	(*rules).elements.processWhiteList = prunedProcessWhiteList
}

// AllowedProcessMatchPaths Function
func (ae *AppArmorEnforcer) AllowedProcessMatchPaths(path tp.ProcessPathType, rules *ruleList) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			line := fmt.Sprintf("  owner %s ix,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.processWhiteList, line) {
				(*rules).elements.processWhiteList = append((*rules).elements.processWhiteList, line)
			}
		} else { // !path.OwnerOnly
			line := fmt.Sprintf("  %s ix,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.processWhiteList, line) {
				(*rules).elements.processWhiteList = append((*rules).elements.processWhiteList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].processWhiteList, line) {
					(*rules).fromSources[source].processWhiteList = append((*rules).fromSources[source].processWhiteList, line)
				}
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].processWhiteList, line) {
					(*rules).fromSources[source].processWhiteList = append((*rules).fromSources[source].processWhiteList, line)
				}
			}
		}
	}
}

// AllowedProcessMatchDirectories Function
func (ae *AppArmorEnforcer) AllowedProcessMatchDirectories(dir tp.ProcessDirectoryType, rules *ruleList) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processWhiteList, line) {
				(*rules).elements.processWhiteList = append((*rules).elements.processWhiteList, line)
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processWhiteList, line) {
				(*rules).elements.processWhiteList = append((*rules).elements.processWhiteList, line)
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processWhiteList, line) {
				(*rules).elements.processWhiteList = append((*rules).elements.processWhiteList, line)
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processWhiteList, line) {
				(*rules).elements.processWhiteList = append((*rules).elements.processWhiteList, line)
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processWhiteList, line) {
					(*rules).fromSources[source].processWhiteList = append((*rules).fromSources[source].processWhiteList, line)
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processWhiteList, line) {
					(*rules).fromSources[source].processWhiteList = append((*rules).fromSources[source].processWhiteList, line)
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processWhiteList, line) {
					(*rules).fromSources[source].processWhiteList = append((*rules).fromSources[source].processWhiteList, line)
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processWhiteList, line) {
					(*rules).fromSources[source].processWhiteList = append((*rules).fromSources[source].processWhiteList, line)
				}
			}
		}
	}
}

// AllowedProcessMatchPatterns Function
func (ae *AppArmorEnforcer) AllowedProcessMatchPatterns(pat tp.ProcessPatternType, rules *ruleList) {
	if pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.processWhiteList, line) {
			(*rules).elements.processWhiteList = append((*rules).elements.processWhiteList, line)
		}
	} else { // !pat.OwnerOnly
		line := fmt.Sprintf("  %s* ix,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.processWhiteList, line) {
			(*rules).elements.processWhiteList = append((*rules).elements.processWhiteList, line)
		}
	}
}

// AllowedFileMatchPaths Function
func (ae *AppArmorEnforcer) AllowedFileMatchPaths(path tp.FilePathType, rules *ruleList) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  owner %s r,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
				(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			line := fmt.Sprintf("  %s r,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
				(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  owner %s rw,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
				(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			line := fmt.Sprintf("  %s rw,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
				(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
					(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  %s r,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
					(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
					(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
					(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
				}
			}
		}
	}
}

// AllowedFileMatchDirectories Function
func (ae *AppArmorEnforcer) AllowedFileMatchDirectories(dir tp.FileDirectoryType, rules *ruleList) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
					(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
					(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
					(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  %s* r,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
					(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
					(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
					(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
					(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
				}
			} else {
				line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
					(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
						(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
						(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
						(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
						(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
						(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
						(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
						(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
					}
				} else {
					line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileWhiteList, line) {
						(*rules).fromSources[source].fileWhiteList = append((*rules).fromSources[source].fileWhiteList, line)
					}
				}
			}
		}
	}
}

// AllowedFileMatchPatterns Function
func (ae *AppArmorEnforcer) AllowedFileMatchPatterns(pat tp.FilePatternType, rules *ruleList) {
	if pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
			(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		line := fmt.Sprintf("  %s r,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
			(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
			(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		line := fmt.Sprintf("  %s rw,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileWhiteList, line) {
			(*rules).elements.fileWhiteList = append((*rules).elements.fileWhiteList, line)
		}
	}
}

// AllowedNetworkMatchProtocols Function
func (ae *AppArmorEnforcer) AllowedNetworkMatchProtocols(proto tp.NetworkProtocolType, rules *ruleList) {
	if len(proto.FromSource) == 0 {
		line := fmt.Sprintf("  network %s,\n", proto.Protocol)
		if !kl.ContainsElement((*rules).elements.networkWhiteList, line) {
			(*rules).elements.networkWhiteList = append((*rules).elements.networkWhiteList, line)
		}
	} else {
		for _, src := range proto.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  network %s,\n", proto.Protocol)
			if !kl.ContainsElement((*rules).fromSources[source].networkWhiteList, line) {
				(*rules).fromSources[source].networkWhiteList = append((*rules).fromSources[source].networkWhiteList, line)
			}
		}
	}
}

// AllowedCapabilitiesMatchCapabilities Function
func (ae *AppArmorEnforcer) AllowedCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, rules *ruleList) {
	if len(cap.FromSource) == 0 {
		line := fmt.Sprintf("  capability %s,\n", cap.Capability)
		if !kl.ContainsElement((*rules).elements.capabilityWhiteList, line) {
			(*rules).elements.capabilityWhiteList = append((*rules).elements.capabilityWhiteList, line)
		}
	} else {
		for _, src := range cap.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  capability %s,\n", cap.Capability)
			if !kl.ContainsElement((*rules).fromSources[source].capabilityWhiteList, line) {
				(*rules).fromSources[source].capabilityWhiteList = append((*rules).fromSources[source].capabilityWhiteList, line)
			}
		}
	}
}

//

// AuditedProcessMatchPaths Function
func (ae *AppArmorEnforcer) AuditedProcessMatchPaths(path tp.ProcessPathType, rules *ruleList) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			line := fmt.Sprintf("  owner %s ix,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.processAuditList, line) {
				(*rules).elements.processAuditList = append((*rules).elements.processAuditList, line)
			}
		} else { // !path.OwnerOnly
			line := fmt.Sprintf("  %s ix,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.processAuditList, line) {
				(*rules).elements.processAuditList = append((*rules).elements.processAuditList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].processAuditList, line) {
					(*rules).fromSources[source].processAuditList = append((*rules).fromSources[source].processAuditList, line)
				}
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].processAuditList, line) {
					(*rules).fromSources[source].processAuditList = append((*rules).fromSources[source].processAuditList, line)
				}
			}
		}
	}
}

// AuditedProcessMatchDirectories Function
func (ae *AppArmorEnforcer) AuditedProcessMatchDirectories(dir tp.ProcessDirectoryType, rules *ruleList) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processAuditList, line) {
				(*rules).elements.processAuditList = append((*rules).elements.processAuditList, line)
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processAuditList, line) {
				(*rules).elements.processAuditList = append((*rules).elements.processAuditList, line)
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processAuditList, line) {
				(*rules).elements.processAuditList = append((*rules).elements.processAuditList, line)
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processAuditList, line) {
				(*rules).elements.processAuditList = append((*rules).elements.processAuditList, line)
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processAuditList, line) {
					(*rules).fromSources[source].processAuditList = append((*rules).fromSources[source].processAuditList, line)
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processAuditList, line) {
					(*rules).fromSources[source].processAuditList = append((*rules).fromSources[source].processAuditList, line)
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processAuditList, line) {
					(*rules).fromSources[source].processAuditList = append((*rules).fromSources[source].processAuditList, line)
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processAuditList, line) {
					(*rules).fromSources[source].processAuditList = append((*rules).fromSources[source].processAuditList, line)
				}
			}
		}
	}
}

// AuditedProcessMatchPatterns Function
func (ae *AppArmorEnforcer) AuditedProcessMatchPatterns(pat tp.ProcessPatternType, rules *ruleList) {
	if pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.processAuditList, line) {
			(*rules).elements.processAuditList = append((*rules).elements.processAuditList, line)
		}
	} else { // !pat.OwnerOnly
		line := fmt.Sprintf("  %s* ix,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.processAuditList, line) {
			(*rules).elements.processAuditList = append((*rules).elements.processAuditList, line)
		}
	}
}

// AuditedFileMatchPaths Function
func (ae *AppArmorEnforcer) AuditedFileMatchPaths(path tp.FilePathType, rules *ruleList) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  owner %s r,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
				(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			line := fmt.Sprintf("  %s r,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
				(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  owner %s rw,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
				(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			line := fmt.Sprintf("  %s rw,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
				(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
					(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  %s r,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
					(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
					(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
					(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
				}
			}
		}
	}
}

// AuditedFileMatchDirectories Function
func (ae *AppArmorEnforcer) AuditedFileMatchDirectories(dir tp.FileDirectoryType, rules *ruleList) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
					(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
					(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
					(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s* r,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
					(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
					(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
					(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
					(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
					(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
						(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
						(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
						(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
						(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
						(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
						(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
						(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileAuditList, line) {
						(*rules).fromSources[source].fileAuditList = append((*rules).fromSources[source].fileAuditList, line)
					}
				}
			}
		}
	}
}

// AuditedFileMatchPatterns Function
func (ae *AppArmorEnforcer) AuditedFileMatchPatterns(pat tp.FilePatternType, rules *ruleList) {
	if pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
			(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		line := fmt.Sprintf("  %s r,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
			(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
			(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		line := fmt.Sprintf("  %s rw,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileAuditList, line) {
			(*rules).elements.fileAuditList = append((*rules).elements.fileAuditList, line)
		}
	}
}

//

// BlockedProcessMatchPaths Function
func (ae *AppArmorEnforcer) BlockedProcessMatchPaths(path tp.ProcessPathType, rules *ruleList) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			line := fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", path.Path, path.Path)
			if !kl.ContainsElement((*rules).elements.processBlackList, line) {
				(*rules).elements.processBlackList = append((*rules).elements.processBlackList, line)
			}
		} else { // !path.OwnerOnly
			line := fmt.Sprintf("  deny %s x,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.processBlackList, line) {
				(*rules).elements.processBlackList = append((*rules).elements.processBlackList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", path.Path, path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].processBlackList, line) {
					(*rules).fromSources[source].processBlackList = append((*rules).fromSources[source].processBlackList, line)
				}
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  deny %s x,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].processBlackList, line) {
					(*rules).fromSources[source].processBlackList = append((*rules).fromSources[source].processBlackList, line)
				}
			}
		}
	}
}

// BlockedProcessMatchDirectories Function
func (ae *AppArmorEnforcer) BlockedProcessMatchDirectories(dir tp.ProcessDirectoryType, rules *ruleList) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s{*,**} ix,\n  deny other %s{*,**} x,\n", dir.Directory, dir.Directory)
			if !kl.ContainsElement((*rules).elements.processBlackList, line) {
				(*rules).elements.processBlackList = append((*rules).elements.processBlackList, line)
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processBlackList, line) {
				(*rules).elements.processBlackList = append((*rules).elements.processBlackList, line)
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s* ix,\n  deny other %s* x,\n", dir.Directory, dir.Directory)
			if !kl.ContainsElement((*rules).elements.processBlackList, line) {
				(*rules).elements.processBlackList = append((*rules).elements.processBlackList, line)
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
			if !kl.ContainsElement((*rules).elements.processBlackList, line) {
				(*rules).elements.processBlackList = append((*rules).elements.processBlackList, line)
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n  deny other %s{*,**} x,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processBlackList, line) {
					(*rules).fromSources[source].processBlackList = append((*rules).fromSources[source].processBlackList, line)
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processBlackList, line) {
					(*rules).fromSources[source].processBlackList = append((*rules).fromSources[source].processBlackList, line)
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s* ix,\n  deny other %s* x,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processBlackList, line) {
					(*rules).fromSources[source].processBlackList = append((*rules).fromSources[source].processBlackList, line)
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
				if !kl.ContainsElement((*rules).fromSources[source].processBlackList, line) {
					(*rules).fromSources[source].processBlackList = append((*rules).fromSources[source].processBlackList, line)
				}
			}
		}
	}
}

// BlockedProcessMatchPatterns Function
func (ae *AppArmorEnforcer) BlockedProcessMatchPatterns(pat tp.ProcessPatternType, rules *ruleList) {
	if pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", pat.Pattern, pat.Pattern)
		if !kl.ContainsElement((*rules).elements.processBlackList, line) {
			(*rules).elements.processBlackList = append((*rules).elements.processBlackList, line)
		}
	} else { // !path.OwnerOnly
		line := fmt.Sprintf("  deny %s x,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.processBlackList, line) {
			(*rules).elements.processBlackList = append((*rules).elements.processBlackList, line)
		}
	}
}

// BlockedFileMatchPaths Function
func (ae *AppArmorEnforcer) BlockedFileMatchPaths(path tp.FilePathType, rules *ruleList) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  deny owner %s w,\n  deny other %s rw,\n", path.Path, path.Path)
			if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
				(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			line := fmt.Sprintf("  deny %s w,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
				(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  owner %s rw,\n  deny other %s rw,\n", path.Path, path.Path)
			if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
				(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			line := fmt.Sprintf("  deny %s rw,\n", path.Path)
			if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
				(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  deny owner %s w,\n  deny other %s rw,\n", path.Path, path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
					(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  deny %s w,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
					(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s rw,\n  deny other %s rw,\n", path.Path, path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
					(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  deny %s rw,\n", path.Path)
				if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
					(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
				}
			}
		}
	}
}

// BlockedFileMatchDirectories Function
func (ae *AppArmorEnforcer) BlockedFileMatchDirectories(dir tp.FileDirectoryType, rules *ruleList) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  deny owner %s{*,**} w,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
					(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny owner %s* w,\n  deny other %s* rw,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
					(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
					(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
					(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  owner %s{*,**} rw,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
					(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* rw,\n  deny other %s* w,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
					(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
					(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s* rw,\n", dir.Directory)
				if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
					(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  deny owner %s{*,**} w,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
						(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny owner %s* w,\n  deny other %s* rw,\n", dir.Directory, dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
						(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
						(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
						(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
						(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n  deny other %s* w,\n", dir.Directory, dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
						(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
						(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny %s* rw,\n", dir.Directory)
					if !kl.ContainsElement((*rules).fromSources[source].fileBlackList, line) {
						(*rules).fromSources[source].fileBlackList = append((*rules).fromSources[source].fileBlackList, line)
					}
				}
			}
		}
	}
}

// BlockedFileMatchPatterns Function
func (ae *AppArmorEnforcer) BlockedFileMatchPatterns(pat tp.FilePatternType, rules *ruleList) {
	if pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  deny owner %s w,\n  deny other %s rw,\n", pat.Pattern, pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
			(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		line := fmt.Sprintf("  deny %s w,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
			(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s rw,\n  deny other %s rw,\n", pat.Pattern, pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
			(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		line := fmt.Sprintf("  deny %s rw,\n", pat.Pattern)
		if !kl.ContainsElement((*rules).elements.fileBlackList, line) {
			(*rules).elements.fileBlackList = append((*rules).elements.fileBlackList, line)
		}
	}
}

// BlockedNetworkMatchProtocols Function
func (ae *AppArmorEnforcer) BlockedNetworkMatchProtocols(proto tp.NetworkProtocolType, rules *ruleList) {
	if len(proto.FromSource) == 0 {
		line := fmt.Sprintf("  deny network %s,\n", proto.Protocol)
		if !kl.ContainsElement((*rules).elements.networkBlackList, line) {
			(*rules).elements.networkBlackList = append((*rules).elements.networkBlackList, line)
		}
	} else {
		for _, src := range proto.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  deny network %s,\n", proto.Protocol)
			if !kl.ContainsElement((*rules).fromSources[source].networkBlackList, line) {
				(*rules).fromSources[source].networkBlackList = append((*rules).fromSources[source].networkBlackList, line)
			}
		}
	}
}

// BlockedCapabilitiesMatchCapabilities Function
func (ae *AppArmorEnforcer) BlockedCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, rules *ruleList) {
	if len(cap.FromSource) == 0 {
		line := fmt.Sprintf("  deny capability %s,\n", cap.Capability)
		if !kl.ContainsElement((*rules).elements.capabilityBlackList, line) {
			(*rules).elements.capabilityBlackList = append((*rules).elements.capabilityBlackList, line)
		}
	} else {
		for _, src := range cap.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := (*rules).fromSources[source]; !ok {
					(*rules).fromSources[source] = &elementList{}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  deny capability %s,\n", cap.Capability)
			if !kl.ContainsElement((*rules).fromSources[source].capabilityBlackList, line) {
				(*rules).fromSources[source].capabilityBlackList = append((*rules).fromSources[source].capabilityBlackList, line)
			}
		}
	}
}

// == //

// GenerateProfileHead Function
func (ae *AppArmorEnforcer) GenerateProfileHead(rules ruleList) string {
	profileHead := "  #include <abstractions/base>\n"
	profileHead = profileHead + "  umount,\n"

	if len(rules.elements.processWhiteList) == 0 && len(rules.elements.fileWhiteList) == 0 {
		profileHead = profileHead + "  file,\n"
	}

	if len(rules.elements.networkWhiteList) == 0 {
		profileHead = profileHead + "  network,\n"
	}

	if len(rules.elements.capabilityWhiteList) == 0 {
		profileHead = profileHead + "  capability,\n"
	}

	return profileHead
}

// GenerateProfileFoot Function
func (ae *AppArmorEnforcer) GenerateProfileFoot() string {
	profileFoot := "  /lib/x86_64-linux-gnu/{*,**} rm,\n"
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

type elementList struct {
	processWhiteList []string
	processAuditList []string
	processBlackList []string

	fileWhiteList []string
	fileAuditList []string
	fileBlackList []string

	networkWhiteList []string
	networkBlackList []string

	capabilityWhiteList []string
	capabilityBlackList []string
}

type ruleList struct {
	elements               elementList
	fromSources            map[string]*elementList
	nativeAppArmorRules    []string
	fusionProcessWhiteList []string
}

// GenerateProfileBody Function
func (ae *AppArmorEnforcer) GenerateProfileBody(securityPolicies []tp.SecurityPolicy) (int, string) {
	// preparation

	count := 0

	var rules ruleList

	// preparation

	for _, secPolicy := range securityPolicies {
		if len(secPolicy.Spec.AppArmor) > 0 {
			scanner := bufio.NewScanner(strings.NewReader(secPolicy.Spec.AppArmor))
			for scanner.Scan() {
				line := "  " + strings.TrimSpace(scanner.Text()) + "\n"
				rules.nativeAppArmorRules = append(rules.nativeAppArmorRules, line)
			}
		}

		if len(secPolicy.Spec.Process.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.Process.MatchPaths {
				if path.Action == "Allow" {
					ae.AllowedProcessMatchPaths(path, &rules)
				} else if path.Action == "Audit" {
					ae.AuditedProcessMatchPaths(path, &rules)
				} else if path.Action == "Block" {
					ae.BlockedProcessMatchPaths(path, &rules)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" {
					ae.AllowedProcessMatchDirectories(dir, &rules)
				} else if dir.Action == "Audit" {
					ae.AuditedProcessMatchDirectories(dir, &rules)
				} else if dir.Action == "Block" {
					ae.BlockedProcessMatchDirectories(dir, &rules)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.Process.MatchPatterns {
				if pat.Action == "Allow" {
					ae.AllowedProcessMatchPatterns(pat, &rules)
				} else if pat.Action == "Audit" {
					ae.AuditedProcessMatchPatterns(pat, &rules)
				} else if pat.Action == "Block" {
					ae.BlockedProcessMatchPatterns(pat, &rules)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" {
					ae.AllowedFileMatchPaths(path, &rules)
				} else if path.Action == "Audit" {
					ae.AuditedFileMatchPaths(path, &rules)
				} else if path.Action == "Block" {
					ae.BlockedFileMatchPaths(path, &rules)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" {
					ae.AllowedFileMatchDirectories(dir, &rules)
				} else if dir.Action == "Audit" {
					ae.AuditedFileMatchDirectories(dir, &rules)
				} else if dir.Action == "Block" {
					ae.BlockedFileMatchDirectories(dir, &rules)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.File.MatchPatterns {
				if pat.Action == "Allow" {
					ae.AllowedFileMatchPatterns(pat, &rules)
				} else if pat.Action == "Audit" {
					ae.AuditedFileMatchPatterns(pat, &rules)
				} else if pat.Action == "Block" {
					ae.BlockedFileMatchPatterns(pat, &rules)
				}
			}
		}

		if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
			for _, proto := range secPolicy.Spec.Network.MatchProtocols {
				if proto.Action == "Allow" {
					ae.AllowedNetworkMatchProtocols(proto, &rules)
				} else if proto.Action == "Block" {
					ae.BlockedNetworkMatchProtocols(proto, &rules)
				}
			}
		}

		if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
			for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
				if cap.Action == "Allow" {
					ae.AllowedCapabilitiesMatchCapabilities(cap, &rules)
				} else if cap.Action == "Block" {
					ae.BlockedCapabilitiesMatchCapabilities(cap, &rules)
				}
			}
		}
	}

	// Resolve conflicts
	ae.ResolvedProcessWhiteListConflicts(&rules)

	// head

	profileHead := "  ## == PRE START == ##\n" + ae.GenerateProfileHead(rules) + "  ## == PRE END == ##\n\n"

	// body

	profileBody := ""

	// body - white list

	for _, line := range rules.elements.processWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.processWhiteList)

	for _, line := range rules.elements.fileWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.fileWhiteList)

	for _, line := range rules.elements.networkWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.networkWhiteList)

	for _, line := range rules.elements.capabilityWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.capabilityWhiteList)

	// body - audit list

	for _, line := range rules.elements.processAuditList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.processAuditList)

	for _, line := range rules.elements.fileAuditList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.fileAuditList)

	// body - black list

	for _, line := range rules.elements.processBlackList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.processBlackList)

	for _, line := range rules.elements.fileBlackList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.fileBlackList)

	for _, line := range rules.elements.networkBlackList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.networkBlackList)

	for _, line := range rules.elements.capabilityBlackList {
		profileBody = profileBody + line
	}

	count = count + len(rules.elements.capabilityBlackList)

	// body - from source

	bodyFromSource := ""

	for source, lines := range rules.fromSources {
		if kl.ContainsElement(rules.fusionProcessWhiteList, source) {
			bodyFromSource = bodyFromSource + fmt.Sprintf("  %s cix,\n", source)
		} else {
			bodyFromSource = bodyFromSource + fmt.Sprintf("  %s cx,\n", source)
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("  profile %s {\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("    %s rix,\n", source)

		// head

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == PRE START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + "    #include <abstractions/base>\n"
		bodyFromSource = bodyFromSource + "    umount,\n"

		if len(lines.processWhiteList) == 0 && len(lines.fileWhiteList) == 0 && len(rules.elements.processWhiteList) == 0 && len(rules.elements.fileWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "    file,\n"
		}

		if len(lines.networkWhiteList) == 0 && len(rules.elements.networkWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "    network,\n"
		}

		if len(lines.capabilityWhiteList) == 0 && len(rules.elements.capabilityWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "    capability,\n"
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == PRE END (%s) == ##\n\n", source)

		// body

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + strings.Replace(profileBody, "  ", "    ", -1)

		// body - white list

		for _, line := range lines.processWhiteList {
			profileBody = profileBody + line
		}

		count = count + len(lines.processWhiteList)

		for _, line := range lines.fileWhiteList {
			profileBody = profileBody + line
		}

		count = count + len(lines.fileWhiteList)

		for _, line := range lines.networkWhiteList {
			profileBody = profileBody + line
		}

		count = count + len(lines.networkWhiteList)

		for _, line := range lines.capabilityWhiteList {
			profileBody = profileBody + line
		}

		count = count + len(lines.capabilityWhiteList)

		// body - audit list

		for _, line := range lines.processAuditList {
			profileBody = profileBody + line
		}

		count = count + len(lines.processAuditList)

		for _, line := range lines.fileAuditList {
			profileBody = profileBody + line
		}

		count = count + len(lines.fileAuditList)

		// body - black list

		for _, line := range lines.processBlackList {
			profileBody = profileBody + line
		}

		count = count + len(lines.processBlackList)

		for _, line := range lines.fileBlackList {
			profileBody = profileBody + line
		}

		count = count + len(lines.fileBlackList)

		for _, line := range lines.networkBlackList {
			profileBody = profileBody + line
		}

		count = count + len(lines.networkBlackList)

		for _, line := range lines.capabilityBlackList {
			profileBody = profileBody + line
		}

		count = count + len(lines.capabilityBlackList)

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY END (%s) == ##\n\n", source)

		// foot

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POST START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + strings.Replace(ae.GenerateProfileFoot(), "  ", "    ", -1)

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POST END (%s) == ##\n", source)
		bodyFromSource = bodyFromSource + "  }\n"
	}

	// body - together

	profileBody = "  ## == POLICY START == ##\n" + profileBody + bodyFromSource + "  ## == POLICY END == ##\n\n"

	// body - native apparmor

	if len(rules.nativeAppArmorRules) > 0 {
		profileBody = profileBody + "\n  ## == NATIVE POLICY START == ##\n"
		for _, nativeRule := range rules.nativeAppArmorRules {
			profileBody = profileBody + nativeRule
		}
		profileBody = profileBody + "  ## == NATIVE POLICY END == ##\n\n"
	}

	count = count + len(rules.nativeAppArmorRules)

	// foot

	profileFoot := "  ## == POST START == ##\n" + ae.GenerateProfileFoot() + "  ## == POST END == ##\n"

	// finalization

	return count, profileHead + profileBody + profileFoot
}

// == //

// GenerateAppArmorProfile Function
func (ae *AppArmorEnforcer) GenerateAppArmorProfile(appArmorProfile string, securityPolicies []tp.SecurityPolicy) (int, string, bool) {
	// check apparmor profile

	if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + appArmorProfile)); os.IsNotExist(err) {
		return 0, err.Error(), false
	}

	// get the old profile

	profile, err := ioutil.ReadFile(filepath.Clean("/etc/apparmor.d/" + appArmorProfile))
	if err != nil {
		return 0, err.Error(), false
	}
	oldProfile := string(profile)

	// generate a profile body

	count, newProfileBody := ae.GenerateProfileBody(securityPolicies)

	newProfile := "## == Managed by KubeArmor == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile " + appArmorProfile + " flags=(attach_disconnected,mediate_deleted) {\n" +
		newProfileBody +
		"}\n"

	// check the new profile with the old profile

	if newProfile != oldProfile {
		return count, newProfile, true
	}

	return 0, "", false
}
