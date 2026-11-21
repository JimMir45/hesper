package lab

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Preflight implements the M4-0 gate (plan.md): detect whether this machine
// can run the Windows-VM layer, via which path, and what is missing.
// It only observes — it never installs anything.
//
// Paths (design §9):
//   - wsl2-kvm:        VMs inside WSL2 via /dev/kvm — feasible on Intel CPUs
//     with nested virtualization only.
//   - windows-host:    Vagrant/VirtualBox on the Windows host (WSL interop);
//     the required path for AMD hosts, always viable as fallback.

// Resource thresholds (advisory; from docs/research/lab-defense-stack-selection-20261120.md:
// MINILAB est. 6–8 GB RAM, GOAD-Light officially ≥20 GB host RAM, GOAD disk ≈115 GB).
const (
	liteVMSMinRAMGB  = 10.0
	fullMinRAMGB     = 24.0
	liteVMSMinDiskGB = 60.0
	fullMinDiskGB    = 120.0
)

// Probes are the injectable observation points. Every probe is fail-soft:
// an unknowable answer becomes "unknown", never an error.
type Probes struct {
	CPUVendor     func() (vendor, virtFlag string)        // /proc/cpuinfo
	KVMAvailable  func() bool                             // /dev/kvm present
	LookPath      func(name string) bool                 // WSL side PATH lookup
	HostLookPath  func(name string) bool                 // Windows host via interop
	HostMemTotal  func() (gb float64, ok bool)           // Windows host RAM
	WSLMem        func() (totalGB, availGB float64)      // /proc/meminfo
	DiskAvailGB   func(path string) (gb float64, ok bool) // statfs on lab state path
}

// SideTools is tool presence on one side of the WSL boundary.
type SideTools struct {
	Vagrant    bool `json:"vagrant"`
	VirtualBox bool `json:"virtualbox"`
}

// CPUCheck reports nested-virtualization capability.
type CPUCheck struct {
	Vendor      string `json:"vendor"`        // GenuineIntel | AuthenticAMD | other|unknown
	VirtFlag    string `json:"virt_flag"`     // vmx | svm | ""
	KVMDevice   bool   `json:"kvm_device"`    // /dev/kvm present
	WSL2KVMPath bool   `json:"wsl2_kvm_path"` // Intel + vmx + /dev/kvm
	Detail      string `json:"detail,omitempty"`
}

// ToolsCheck reports Vagrant/VirtualBox presence per side.
type ToolsCheck struct {
	WSL   SideTools `json:"wsl"`
	Host  SideTools `json:"host"`
	Probe string    `json:"probe,omitempty"` // how the host side was probed
}

// ResourceCheck reports RAM/disk against profile thresholds.
type ResourceCheck struct {
	WSLMemTotalGB  float64 `json:"wsl_mem_total_gb"`
	WSLMemAvailGB  float64 `json:"wsl_mem_avail_gb"`
	HostMemTotalGB float64 `json:"host_mem_total_gb,omitempty"`
	DiskAvailGB    float64 `json:"disk_avail_gb"`
	DiskPath       string  `json:"disk_path"`
	LiteVMSFits    bool    `json:"lite_vms_fits"`
	FullFits       bool    `json:"full_fits"`
	Detail         string  `json:"detail,omitempty"`
}

// PreflightReport is the structured verdict.
type PreflightReport struct {
	CPU            CPUCheck     `json:"cpu"`
	Tools          ToolsCheck   `json:"tools"`
	Resources      ResourceCheck `json:"resources"`
	RecommendedPath string      `json:"recommended_path"` // wsl2-kvm | windows-host
	Ready          bool         `json:"ready"`
	Gaps           []string     `json:"gaps"`
}

// Preflight runs the M4-0 gate against injectable probes.
type Preflight struct {
	Probes  Probes
	LabRoot string
}

// NewPreflight builds a Preflight with real probes.
func NewPreflight(labRoot string) *Preflight {
	return &Preflight{Probes: DefaultProbes(), LabRoot: labRoot}
}

func DefaultProbes() Probes {
	return Probes{
		CPUVendor:    probeCPUVendor,
		KVMAvailable: func() bool { _, err := os.Stat("/dev/kvm"); return err == nil },
		LookPath: func(name string) bool {
			_, err := exec.LookPath(name)
			return err == nil
		},
		HostLookPath: hostLookPath,
		HostMemTotal: hostMemTotalGB,
		WSLMem:       meminfoGB,
		DiskAvailGB:  diskAvailGB,
	}
}

func probeCPUVendor() (vendor, virtFlag string) {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "vendor_id"):
			vendor = strings.TrimSpace(strings.TrimPrefix(line, "vendor_id"))
			vendor = strings.Trim(vendor, ": \t")
		case strings.HasPrefix(line, "flags"):
			flags := strings.TrimSpace(strings.TrimPrefix(line, "flags"))
			flags = strings.Trim(flags, ": \t")
			for _, f := range strings.Fields(flags) {
				if f == "vmx" || f == "svm" {
					virtFlag = f
				}
			}
		}
	}
	if vendor == "" {
		vendor = "unknown"
	}
	return vendor, virtFlag
}

// hostLookPath probes the Windows host for a command via WSL interop
// (powershell.exe Get-Command), falling back to the default install path.
func hostLookPath(name string) bool {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		// Interop disabled: fall back to the canonical install paths only.
		return hostDefaultPathExists(name)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive",
		"-Command", "Get-Command -Name "+name+" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Name")
	if out, err := cmd.Output(); err == nil && strings.TrimSpace(string(out)) != "" {
		return true
	}
	return hostDefaultPathExists(name)
}

func hostDefaultPathExists(name string) bool {
	candidates := map[string][]string{
		"VBoxManage": {"/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"},
		"vagrant":    {"/mnt/c/HashiCorp/Vagrant/bin/vagrant.exe", "/mnt/c/Program Files/HashiCorp/Vagrant/bin/vagrant.exe"},
	}
	for _, p := range candidates[name] {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func hostMemTotalGB() (float64, bool) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		return 0, false
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive",
		"-Command", "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)")
	out, err := cmd.Output()
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

func meminfoGB() (totalGB, availGB float64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	get := func(key string) float64 {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, key+":") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kb, err := strconv.ParseFloat(fields[1], 64)
					if err == nil {
						return kb / (1024 * 1024)
					}
				}
			}
		}
		return 0
	}
	return get("MemTotal"), get("MemAvailable")
}

func diskAvailGB(path string) (float64, bool) {
	return diskFreeGB(path)
}

// Run executes all probes and derives the verdict. Fail-soft: unknown
// probes produce gaps, not errors.
func (p *Preflight) Run() PreflightReport {
	var r PreflightReport

	// --- CPU / nested virtualization ---
	vendor, virtFlag := p.Probes.CPUVendor()
	kvm := p.Probes.KVMAvailable()
	r.CPU = CPUCheck{Vendor: vendor, VirtFlag: virtFlag, KVMDevice: kvm}
	r.CPU.WSL2KVMPath = vendor == "GenuineIntel" && virtFlag == "vmx" && kvm
	if vendor == "AuthenticAMD" {
		r.CPU.Detail = "AMD host: WSL2 nested virtualization (KVM) is not usable; use the Windows-host Vagrant path (design §9)"
	} else if vendor == "GenuineIntel" && !kvm {
		r.CPU.Detail = "Intel CPU but /dev/kvm absent — WSL2 nested virtualization not enabled; Windows-host path still viable"
	}

	// --- Tools on both sides ---
	r.Tools = ToolsCheck{
		WSL:  SideTools{Vagrant: p.Probes.LookPath("vagrant"), VirtualBox: p.Probes.LookPath("VBoxManage")},
		Host: SideTools{Vagrant: p.Probes.HostLookPath("vagrant"), VirtualBox: p.Probes.HostLookPath("VBoxManage")},
	}
	if _, err := exec.LookPath("powershell.exe"); err == nil {
		r.Tools.Probe = "powershell interop + default install paths"
	} else {
		r.Tools.Probe = "interop disabled — default install paths only"
	}

	// --- Resources ---
	r.Resources.DiskPath = p.LabRoot
	r.Resources.WSLMemTotalGB, r.Resources.WSLMemAvailGB = p.Probes.WSLMem()
	if hostGB, ok := p.Probes.HostMemTotal(); ok {
		r.Resources.HostMemTotalGB = hostGB
	} else {
		r.Resources.Detail = "host RAM unknown (no powershell interop); verdict uses WSL RAM only"
	}
	if d, ok := p.Probes.DiskAvailGB(p.LabRoot); ok {
		r.Resources.DiskAvailGB = d
	} else {
		r.Resources.Detail = strings.TrimSpace(r.Resources.Detail + "; disk stat failed for " + p.LabRoot)
	}

	// --- Verdict: recommended path + the RAM pool it will draw from ---
	r.RecommendedPath = "windows-host"
	if r.CPU.WSL2KVMPath {
		r.RecommendedPath = "wsl2-kvm"
	}
	ramPool := r.Resources.HostMemTotalGB // windows-host VMs consume host RAM
	if r.RecommendedPath == "wsl2-kvm" {
		ramPool = r.Resources.WSLMemTotalGB
	}
	if ramPool <= 0 {
		ramPool = r.Resources.WSLMemTotalGB // fall back to what we can see
	}
	r.Resources.LiteVMSFits = ramPool >= liteVMSMinRAMGB && r.Resources.DiskAvailGB >= liteVMSMinDiskGB
	r.Resources.FullFits = ramPool >= fullMinRAMGB && r.Resources.DiskAvailGB >= fullMinDiskGB

	// --- Gaps against the recommended path ---
	gaps := []string{}
	need := r.Tools.Host // windows-host path needs host-side tools
	if r.RecommendedPath == "wsl2-kvm" {
		// KVM path drives vagrant from WSL (VMs via QEMU/KVM; VBox not used).
		need = SideTools{Vagrant: r.Tools.WSL.Vagrant}
	}
	if !need.Vagrant {
		side := "host"
		if r.RecommendedPath == "wsl2-kvm" {
			side = "wsl"
		}
		gaps = append(gaps, fmt.Sprintf("vagrant missing on %s side (required for %s path)", side, r.RecommendedPath))
	}
	if r.RecommendedPath == "windows-host" && !need.VirtualBox {
		gaps = append(gaps, "VirtualBox missing on Windows host (required for windows-host path)")
	}
	if !r.Resources.LiteVMSFits {
		if ramPool < liteVMSMinRAMGB {
			gaps = append(gaps, fmt.Sprintf("RAM %.1f GB < %.0f GB for the lite-vms profile (pool: %s path)", ramPool, liteVMSMinRAMGB, r.RecommendedPath))
		}
		if r.Resources.DiskAvailGB < liteVMSMinDiskGB {
			gaps = append(gaps, fmt.Sprintf("disk %.1f GB < %.0f GB for the lite-vms profile (lab/state path %s)", r.Resources.DiskAvailGB, liteVMSMinDiskGB, p.LabRoot))
		}
	}
	r.Gaps = gaps
	r.Ready = len(gaps) == 0
	return r
}

// Human renders the report for the CLI.
func (r PreflightReport) Human() string {
	var b strings.Builder
	fmt.Fprintf(&b, "preflight: recommended path = %s, ready = %v\n", r.RecommendedPath, r.Ready)
	fmt.Fprintf(&b, "  cpu: vendor=%s virt=%s /dev/kvm=%v wsl2-kvm-feasible=%v\n",
		r.CPU.Vendor, orDash(r.CPU.VirtFlag), r.CPU.KVMDevice, r.CPU.WSL2KVMPath)
	if r.CPU.Detail != "" {
		fmt.Fprintf(&b, "        %s\n", r.CPU.Detail)
	}
	fmt.Fprintf(&b, "  tools: wsl(vagrant=%v vbox=%v) host(vagrant=%v vbox=%v) [%s]\n",
		r.Tools.WSL.Vagrant, r.Tools.WSL.VirtualBox, r.Tools.Host.Vagrant, r.Tools.Host.VirtualBox, r.Tools.Probe)
	fmt.Fprintf(&b, "  resources: wsl ram %.1f/%.1f GB (avail/total)", r.Resources.WSLMemAvailGB, r.Resources.WSLMemTotalGB)
	if r.Resources.HostMemTotalGB > 0 {
		fmt.Fprintf(&b, ", host ram %.1f GB", r.Resources.HostMemTotalGB)
	}
	fmt.Fprintf(&b, ", disk %.1f GB free @ %s\n", r.Resources.DiskAvailGB, r.Resources.DiskPath)
	fmt.Fprintf(&b, "  profiles: lite-vms fits=%v, full fits=%v\n", r.Resources.LiteVMSFits, r.Resources.FullFits)
	if len(r.Gaps) > 0 {
		fmt.Fprintf(&b, "  gaps:\n")
		for _, g := range r.Gaps {
			fmt.Fprintf(&b, "    - %s\n", g)
		}
	}
	if r.Resources.Detail != "" {
		fmt.Fprintf(&b, "  note: %s\n", r.Resources.Detail)
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
