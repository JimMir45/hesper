package kernel

import (
	"fmt"
	"net/netip"
	"strings"
)

// Request describes one proposed action for authorization.
type Request struct {
	Adapter     string // "lib" | "proc" | "vm"
	TechniqueID string // ATT&CK technique ID, e.g. "T1190"
	Class       string // "web" | "creds" | "lateral" | "endpoint"
	Target      string // host, IP, or domain the action will touch
}

// Decision is a kernel verdict with a planner-readable reason.
type Decision struct {
	Allowed bool
	Reason  string
}

func deny(format string, a ...any) Decision {
	return Decision{Allowed: false, Reason: fmt.Sprintf(format, a...)}
}

// Check evaluates a proposed action against the manifest. Deny-by-default:
// the gate order is target -> adapter -> deny-list -> technique/class. Any
// unloadable or empty scope denies everything before this method is reached.
func (m *ScopeManifest) Check(r Request) Decision {
	if !m.targetAllowed(r.Target) {
		return deny("target %q is outside scope", r.Target)
	}
	if !m.adapterAllowed(r.Adapter) {
		return deny("adapter %q is not allowed by scope", r.Adapter)
	}
	if m.denyMatch(r) {
		return deny("technique %q / class %q is explicitly denied", r.TechniqueID, r.Class)
	}
	if !m.techniqueAllowed(r) {
		return deny("neither technique %q nor class %q is allowed", r.TechniqueID, r.Class)
	}
	return Decision{Allowed: true, Reason: "in scope"}
}

func (m *ScopeManifest) targetAllowed(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	ip, _ := netip.ParseAddr(target)
	for _, t := range m.Targets {
		switch t.Kind {
		case "host":
			if strings.EqualFold(t.Value, target) {
				return true
			}
		case "domain":
			d := strings.ToLower(t.Value)
			if target == d || strings.HasSuffix(target, "."+d) {
				return true
			}
		case "cidr":
			if !ip.IsValid() {
				continue
			}
			p, err := netip.ParsePrefix(strings.TrimSpace(t.Value))
			if err != nil {
				continue
			}
			if p.Contains(ip.Unmap()) {
				return true
			}
		}
	}
	return false
}

func (m *ScopeManifest) adapterAllowed(adapter string) bool {
	for _, a := range m.Allow.Adapters {
		if a == adapter {
			return true
		}
	}
	return false
}

func (m *ScopeManifest) denyMatch(r Request) bool {
	for _, d := range m.Deny {
		if strings.EqualFold(d, r.TechniqueID) || strings.EqualFold(d, r.Class) {
			return true
		}
	}
	return false
}

// techniqueAllowed is fail-closed: empty allowlists deny everything.
func (m *ScopeManifest) techniqueAllowed(r Request) bool {
	if len(m.Allow.TechniqueIDs) == 0 && len(m.Allow.Classes) == 0 {
		return false
	}
	for _, id := range m.Allow.TechniqueIDs {
		if strings.EqualFold(id, r.TechniqueID) {
			return true
		}
	}
	for _, c := range m.Allow.Classes {
		if strings.EqualFold(c, r.Class) {
			return true
		}
	}
	return false
}
