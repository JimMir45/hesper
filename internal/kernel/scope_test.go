package kernel

import (
	"os"
	"path/filepath"
	"testing"
)

func writeScope(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write scope: %v", err)
	}
	return p
}

const validScope = `{
  "version": "0.1",
  "mode": "validate",
  "name": "t",
  "targets": [
    {"kind": "cidr", "value": "172.20.0.0/16"},
    {"kind": "host", "value": "target.lab"},
    {"kind": "domain", "value": "corp.lab"}
  ],
  "allow": {"classes": ["web", "lateral"], "adapters": ["proc"]},
  "deny": ["T1098"],
  "budget": {"max_actions": 5, "max_minutes": 10}
}`

func load(t *testing.T, body string) *ScopeManifest {
	t.Helper()
	m, err := LoadScope(writeScope(t, body))
	if err != nil {
		t.Fatalf("LoadScope: %v", err)
	}
	return m
}

func TestLoadScopeValid(t *testing.T) {
	m := load(t, validScope)
	if m.Mode != ModeValidate || len(m.Targets) != 3 {
		t.Fatalf("unexpected manifest: %+v", m)
	}
}

func TestLoadScopeFailClosed(t *testing.T) {
	cases := map[string]string{
		"missing version": `{"mode":"validate","targets":[{"kind":"host","value":"x"}],"allow":{"adapters":["proc"]},"budget":{"max_actions":1,"max_minutes":1}}`,
		"bad mode":        `{"version":"0.1","mode":"fuzz","targets":[{"kind":"host","value":"x"}],"allow":{"adapters":["proc"]},"budget":{"max_actions":1,"max_minutes":1}}`,
		"zero targets":    `{"version":"0.1","mode":"validate","targets":[],"allow":{"adapters":["proc"]},"budget":{"max_actions":1,"max_minutes":1}}`,
		"bad target kind": `{"version":"0.1","mode":"validate","targets":[{"kind":"galaxy","value":"m31"}],"allow":{"adapters":["proc"]},"budget":{"max_actions":1,"max_minutes":1}}`,
		"empty adapters":  `{"version":"0.1","mode":"validate","targets":[{"kind":"host","value":"x"}],"allow":{"adapters":[]},"budget":{"max_actions":1,"max_minutes":1}}`,
		"unknown adapter": `{"version":"0.1","mode":"validate","targets":[{"kind":"host","value":"x"}],"allow":{"adapters":["teleport"]},"budget":{"max_actions":1,"max_minutes":1}}`,
		"zero action budget":  `{"version":"0.1","mode":"validate","targets":[{"kind":"host","value":"x"}],"allow":{"adapters":["proc"]},"budget":{"max_actions":0,"max_minutes":1}}`,
		"negative time budget": `{"version":"0.1","mode":"validate","targets":[{"kind":"host","value":"x"}],"allow":{"adapters":["proc"]},"budget":{"max_actions":1,"max_minutes":-1}}`,
	}
	for name, body := range cases {
		if _, err := LoadScope(writeScope(t, body)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestCheckGateOrder(t *testing.T) {
	m := load(t, validScope)

	cases := []struct {
		name    string
		req     Request
		allowed bool
	}{
		{"in scope cidr", Request{Adapter: "proc", Class: "web", Target: "172.20.0.5"}, true},
		{"in scope host", Request{Adapter: "proc", TechniqueID: "T1190", Class: "web", Target: "target.lab"}, true},
		{"technique without allowed class", Request{Adapter: "proc", TechniqueID: "T1190", Target: "target.lab"}, false},
		{"domain suffix", Request{Adapter: "proc", Class: "lateral", Target: "dc01.corp.lab"}, true},
		{"target outside", Request{Adapter: "proc", Class: "web", Target: "10.0.0.1"}, false},
		{"target empty", Request{Adapter: "proc", Class: "web", Target: "  "}, false},
		{"adapter not allowed", Request{Adapter: "vm", Class: "web", Target: "172.20.0.5"}, false},
		{"deny overrides allow", Request{Adapter: "proc", TechniqueID: "T1098", Target: "172.20.0.5"}, false},
	}
	for _, c := range cases {
		d := m.Check(c.req)
		if d.Allowed != c.allowed {
			t.Errorf("%s: allowed=%v, want %v (reason=%q)", c.name, d.Allowed, c.allowed, d.Reason)
		}
	}
}

func TestEmptyAllowlistsDenyAll(t *testing.T) {
	m := load(t, validScope)
	m.Allow.TechniqueIDs, m.Allow.Classes = nil, nil
	if d := m.Check(Request{Adapter: "proc", Class: "web", Target: "172.20.0.5"}); d.Allowed {
		t.Fatalf("empty allowlists must deny everything; got %+v", d)
	}
}

func TestCheckClassOutsideAllowlist(t *testing.T) {
	m := load(t, validScope)
	// "creds" is not in allow.classes (web|lateral) and no technique — must deny.
	if d := m.Check(Request{Adapter: "proc", Class: "creds", Target: "target.lab"}); d.Allowed {
		t.Fatal("class outside allowlist must deny")
	}
	// Domain target with an allowed class passes.
	if d := m.Check(Request{Adapter: "proc", Class: "web", Target: "www.corp.lab"}); !d.Allowed {
		t.Fatalf("domain target with allowed class must pass, got %q", d.Reason)
	}
}
