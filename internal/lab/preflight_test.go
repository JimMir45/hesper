package lab

import (
	"strings"
	"testing"
)

func fakeProbes(vendor, virtFlag string, kvm bool, wslVagrant, wslVBox, hostVagrant, hostVBox bool, wslTotal, hostTotal, disk float64) Probes {
	return Probes{
		CPUVendor:    func() (string, string) { return vendor, virtFlag },
		KVMAvailable: func() bool { return kvm },
		LookPath: func(name string) bool {
			if name == "vagrant" {
				return wslVagrant
			}
			return wslVBox
		},
		HostLookPath: func(name string) bool {
			if name == "vagrant" {
				return hostVagrant
			}
			return hostVBox
		},
		HostMemTotal: func() (float64, bool) { return hostTotal, hostTotal > 0 },
		WSLMem:       func() (float64, float64) { return wslTotal, wslTotal * 0.5 },
		DiskAvailGB:  func(string) (float64, bool) { return disk, true },
	}
}

func TestPreflightIntelKVMRecommendsWSL2(t *testing.T) {
	p := &Preflight{
		LabRoot: "lab",
		Probes:  fakeProbes("GenuineIntel", "vmx", true, true, false, false, true, 32, 64, 200),
	}
	r := p.Run()
	if !r.CPU.WSL2KVMPath || r.RecommendedPath != "wsl2-kvm" {
		t.Fatalf("Intel+vmx+kvm must recommend wsl2-kvm: %+v", r.CPU)
	}
	// wsl2-kvm path: needs WSL vagrant only (VBox unused) + RAM from WSL pool.
	if !r.Ready {
		t.Fatalf("expected ready, gaps=%v", r.Gaps)
	}
	if !r.Resources.LiteVMSFits || !r.Resources.FullFits {
		t.Fatalf("32GB WSL ram + 200GB disk must fit both profiles: lite=%v full=%v", r.Resources.LiteVMSFits, r.Resources.FullFits)
	}
}

func TestPreflightWSL2PathRAMPool(t *testing.T) {
	// Host has 64GB but the wsl2-kvm path draws from the WSL pool (16GB):
	// lite-vms fits, full (24GB) does not — the pool choice must follow the
	// recommended path, not the largest number available.
	p := &Preflight{
		LabRoot: "lab",
		Probes:  fakeProbes("GenuineIntel", "vmx", true, true, false, false, true, 16, 64, 200),
	}
	r := p.Run()
	if !r.Resources.LiteVMSFits || r.Resources.FullFits {
		t.Fatalf("wsl2-kvm pool=16GB: lite=%v (want true), full=%v (want false)", r.Resources.LiteVMSFits, r.Resources.FullFits)
	}
}

func TestPreflightAMDAdvisesWindowsHost(t *testing.T) {
	p := &Preflight{
		LabRoot: "lab",
		Probes:  fakeProbes("AuthenticAMD", "svm", false, true, true, false, false, 15, 32, 200),
	}
	r := p.Run()
	if r.CPU.WSL2KVMPath {
		t.Fatal("AMD must never set wsl2-kvm feasible")
	}
	if r.RecommendedPath != "windows-host" {
		t.Fatalf("AMD must recommend windows-host, got %s", r.RecommendedPath)
	}
	if !strings.Contains(strings.Join(r.Gaps, ";"), "vagrant missing on host") ||
		!strings.Contains(strings.Join(r.Gaps, ";"), "VirtualBox missing on Windows host") {
		t.Fatalf("expected host tool gaps, got %v", r.Gaps)
	}
	if r.Ready {
		t.Fatal("missing host tools must not be ready")
	}
}

func TestPreflightIntelNoKVMFallsToWindowsHost(t *testing.T) {
	p := &Preflight{
		LabRoot: "lab",
		Probes:  fakeProbes("GenuineIntel", "vmx", false, false, false, true, true, 15, 32, 200),
	}
	r := p.Run()
	if r.CPU.WSL2KVMPath {
		t.Fatal("no /dev/kvm must disable wsl2-kvm")
	}
	if r.RecommendedPath != "windows-host" || !r.Ready {
		t.Fatalf("windows-host with host tools + resources must be ready: path=%s ready=%v gaps=%v", r.RecommendedPath, r.Ready, r.Gaps)
	}
	if !strings.Contains(r.CPU.Detail, "/dev/kvm absent") {
		t.Fatalf("detail must explain the fallback: %q", r.CPU.Detail)
	}
}

func TestPreflightResourceGapLowRAM(t *testing.T) {
	p := &Preflight{
		LabRoot: "lab",
		Probes:  fakeProbes("GenuineIntel", "vmx", true, true, false, false, false, 8, 0, 200),
	}
	r := p.Run()
	// wsl2-kvm path draws from WSL pool (8GB) < 10GB → gap; host RAM unknown.
	if r.Resources.LiteVMSFits {
		t.Fatal("8GB pool must not fit lite-vms")
	}
	found := false
	for _, g := range r.Gaps {
		if strings.Contains(g, "RAM 8.0 GB < 10 GB") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected RAM gap, got %v", r.Gaps)
	}
	if strings.Contains(strings.Join(r.Gaps, ";"), "vagrant") {
		t.Fatalf("wsl2-kvm path must not demand host tools: %v", r.Gaps)
	}
}

func TestPreflightResourceGapLowDisk(t *testing.T) {
	p := &Preflight{
		LabRoot: "lab",
		Probes:  fakeProbes("GenuineIntel", "vmx", false, false, false, true, true, 15, 32, 40),
	}
	r := p.Run()
	found := false
	for _, g := range r.Gaps {
		if strings.Contains(g, "disk 40.0 GB < 60 GB") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected disk gap, got %v", r.Gaps)
	}
}

func TestPreflightHumanOutputMentionsPath(t *testing.T) {
	// Host tools present, resources ample: ready run — gaps section absent.
	p := &Preflight{LabRoot: "lab", Probes: fakeProbes("AuthenticAMD", "svm", false, false, false, true, true, 15, 32, 200)}
	out := p.Run().Human()
	for _, want := range []string{"windows-host", "AuthenticAMD", "profiles", "ready = true"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output must mention %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "gaps:") {
		t.Fatalf("ready run must not list gaps:\n%s", out)
	}
}
