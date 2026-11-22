# Host-side pre-step for the m4-live run: resolve the DC IPv4, export the
# guest credential as CliXml. Outputs VM_IP into vm-ip.txt (the WSL
# orchestrator reads it via /mnt/c).
$ErrorActionPreference = "Stop"
$ip = ((Get-VM hesper-litevms-dc01 | Get-VMNetworkAdapter).IPAddresses | Where-Object { $_ -match "^\d" } | Select-Object -First 1)
if (-not $ip) { Write-Output "FATAL: DC01 has no IPv4"; exit 1 }
$pw = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("vagrant", $pw)
$cred | Export-CliXml -Path C:\hesper-lab\vm-cred.xml
Set-Content -Path C:\hesper-lab\vm-ip.txt -Value "VM_IP=$ip" -Encoding ascii
Write-Output "PRE-STEP-OK ip=$ip"
