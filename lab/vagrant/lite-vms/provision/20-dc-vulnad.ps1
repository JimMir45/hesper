# Inject AD misconfigurations via vulnerable-AD (safebuffer, MIT) — idempotent.
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory -ErrorAction Stop

$marker = "C:\Hesper\provision\vulnad.done"
if (Test-Path $marker) { Write-Output "VULNAD-ALREADY"; exit 0 }

if (-not (Test-Path "C:\Hesper\deps\vulnAD.ps1")) { throw "vulnAD.ps1 missing (deps not uploaded)" }

Write-Output "Running Invoke-VulnAD against hesper.lab (creates ~140 misconfigured objects; takes minutes)..."
. C:\Hesper\deps\vulnAD.ps1
Invoke-VulnAD -DomainName "hesper.lab" -UsersLimit 100

New-Item -ItemType File -Path $marker -Force | Out-Null
$users = (Get-ADUser -Filter * -SearchBase (Get-ADDomain).DistinguishedName).Count
Write-Output "VULNAD-DONE domain-user-count=$users"
