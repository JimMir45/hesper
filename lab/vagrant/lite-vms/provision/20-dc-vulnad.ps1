# Inject AD misconfigurations via vulnerable-AD (safebuffer, MIT) - idempotent.
$ErrorActionPreference = "Stop"

# AD services warm up across the post-promotion reboot; the AD PowerShell
# provider's InitializeDefaultDrives fails transiently right after boot
# (attempt-13). Poll until ADWS answers, then import.
for ($i = 1; $i -le 30; $i++) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $null = Get-ADDomain -ErrorAction Stop
        Write-Output "AD-READY after $i try/tries"
        break
    } catch {
        Write-Output "AD-NOT-READY try $i : $($_.Exception.Message.Substring(0, [Math]::Min(60, $_.Exception.Message.Length)))"
        Start-Sleep -Seconds 10
        if ($i -eq 30) { throw "AD never became ready: $($_.Exception.Message)" }
        # re-enter loop; Import-Module retries inside the try
    }
}

$marker = "C:\Hesper\provision\vulnad.done"
if (Test-Path $marker) { Write-Output "VULNAD-ALREADY"; exit 0 }

if (-not (Test-Path "C:\Hesper\deps\vulnAD.ps1")) { throw "vulnAD.ps1 missing (deps not uploaded)" }

Write-Output "Running Invoke-VulnAD against hesper.lab (creates ~140 misconfigured objects; takes minutes)..."
. C:\Hesper\deps\vulnAD.ps1
Invoke-VulnAD -DomainName "hesper.lab" -UsersLimit 100

New-Item -ItemType File -Path $marker -Force | Out-Null
$users = (Get-ADUser -Filter * -SearchBase (Get-ADDomain).DistinguishedName).Count
Write-Output "VULNAD-DONE domain-user-count=$users"
