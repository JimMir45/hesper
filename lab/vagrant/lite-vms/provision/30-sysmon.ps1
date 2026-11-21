# Install Sysmon with the sysmon-modular config (olafhartong, MIT) — idempotent.
# Binaries are uploaded from the host fetcher (live.sysinternals.com at fetch
# time); nothing is redistributed from this repo.
$ErrorActionPreference = "Stop"

if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    Write-Output "SYSMON-ALREADY status=$((Get-Service Sysmon64).Status)"
    exit 0
}
if (-not (Test-Path "C:\Hesper\deps\Sysmon64.exe")) { throw "Sysmon64.exe missing (deps not uploaded)" }

Write-Output "Installing Sysmon64 with sysmon-modular config..."
& C:\Hesper\deps\Sysmon64.exe -accepteula -i C:\Hesper\deps\sysmonconfig.xml | Out-Null

$s = Get-Service Sysmon64 -ErrorAction Stop
Write-Output "SYSMON-STATUS=$($s.Status)"
if ($s.Status -ne "Running") { throw "Sysmon64 service not running: $($s.Status)" }
