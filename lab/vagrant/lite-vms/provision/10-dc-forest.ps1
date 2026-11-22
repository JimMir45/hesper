# Promote DC01 to forest root domain hesper.lab (idempotent).
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path C:\Hesper\provision | Out-Null

# Lab posture: firewall off on all profiles (GOAD does the same; this is an
# intentionally vulnerable range - detection comes from Sysmon, not the
# firewall). Without this, the host-only NIC lands in the Public profile and
# domain joins fail with "domain could not be contacted".
if ((Get-NetFirewallProfile | Where-Object Enabled).Count -gt 0) {
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
    Write-Output "FIREWALL-DISABLED all-profiles"
} else {
    Write-Output "FIREWALL-ALREADY-OFF"
}

Import-Module ServerManager -ErrorAction SilentlyContinue
# Idempotency check via try/catch: with $ErrorActionPreference=Stop a bare
# Get-ADDomain on a non-DC escalates past -ErrorAction SilentlyContinue and
# kills the provisioner before promotion (attempt-6 finding).
$domainOk = $false
try {
    if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
        $domainOk = [bool](Get-ADDomain -ErrorAction SilentlyContinue)
    }
} catch {
    $domainOk = $false
}
if ($domainOk) {
    Write-Output "DOMAIN-ALREADY-PRESENT"
    exit 0
}

# StefanScherer boxes ship a blank local Administrator password; AD promotion
# prerequisites refuse a blank admin password. Lab-only credential, set
# before promotion (also what WinRM/SMB fall back to post-promotion).
net user Administrator 'Hesper-L4b-Adm1n!' | Out-Null
Write-Output "ADMIN-PASSWORD-SET"

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
