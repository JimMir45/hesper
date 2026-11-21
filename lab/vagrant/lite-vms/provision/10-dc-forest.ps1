# Promote DC01 to forest root domain hesper.lab (idempotent).
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path C:\Hesper\provision | Out-Null

# Lab posture: firewall off on all profiles (GOAD does the same; this is an
# intentionally vulnerable range — detection comes from Sysmon, not the
# firewall). Without this, the host-only NIC lands in the Public profile and
# domain joins fail with "domain could not be contacted".
if ((Get-NetFirewallProfile | Where-Object Enabled).Count -gt 0) {
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
    Write-Output "FIREWALL-DISABLED all-profiles"
} else {
    Write-Output "FIREWALL-ALREADY-OFF"
}

Import-Module ServerManager -ErrorAction SilentlyContinue
if ((Get-Command Get-ADDomain -ErrorAction SilentlyContinue) -and (Get-ADDomain -ErrorAction SilentlyContinue)) {
    Write-Output "DOMAIN-ALREADY-PRESENT"
    exit 0
}

Write-Output "Installing AD-Domain-Services..."
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

$dsrm = ConvertTo-SecureString "HesperDSRM!2019" -AsPlainText -Force
Write-Output "Promoting to forest hesper.lab..."
Install-ADDSForest `
    -DomainName "hesper.lab" `
    -DomainNetBIOSName "HESPER" `
    -SafeModeAdministratorPassword $dsrm `
    -InstallDns:$true `
    -NoRebootOnCompletion:$true `
    -Force:$true | Out-Null

Write-Output "FOREST-INSTALLED-REBOOT-REQUIRED"
