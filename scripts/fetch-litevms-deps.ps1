# Host-side dependency fetcher for the lite-vms profile.
# Downloads provision deps into D:\hesper-lab\provision-files (nothing binary
# is committed to the repo; Sysmon is fetched live from Microsoft and used
# per its EULA — install-time download, not redistribution).
#
# Usage (Git Bash): powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/fetch-litevms-deps.ps1
# Requires the local proxy env (HTTPS_PROXY) for raw.githubusercontent.com.

param([string]$Dest = "D:\hesper-lab\provision-files")

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

$items = @(
    @{ u = "https://live.sysinternals.com/Sysmon64.exe"; f = "Sysmon64.exe" },
    # sysmon-modular ships the combined config as a release asset (no xml in the repo tree)
    @{ u = "https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43/sysmonconfig-15.21.xml"; f = "sysmonconfig.xml" },
    # NOTE: upstream filename is vulnad.ps1 (lowercase) — raw URLs are case-sensitive
    @{ u = "https://raw.githubusercontent.com/safebuffer/vulnerable-AD/master/vulnad.ps1"; f = "vulnAD.ps1" }
)

foreach ($i in $items) {
    $out = Join-Path $Dest $i.f
    if ($env:HTTPS_PROXY) {
        Invoke-WebRequest -UseBasicParsing -Proxy $env:HTTPS_PROXY -Uri $i.u -OutFile $out
    } else {
        Invoke-WebRequest -UseBasicParsing -Uri $i.u -OutFile $out
    }
    "{0} -> {1} ({2} bytes)" -f $i.f, $out, (Get-Item $out).Length
}
"DEPS-OK"
