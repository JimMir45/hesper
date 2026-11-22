# Devbox-side pre-step for the m4-live run: resolve the DC IP, generate the
# credential CliXml, and hand both to the WSL engine via WSLENV.
$ip = ((Get-VM hesper-litevms-dc01 | Get-VMNetworkAdapter).IPAddresses | Where-Object { $_ -match "^\d" } | Select-Object -First 1)
if (-not $ip) { Write-Output "FATAL: DC01 has no IPv4"; exit 1 }
$pw = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("vagrant", $pw)
$cred | Export-CliXml -Path C:\hesper-lab\vm-cred.xml
Write-Output "VM_IP=$ip"
Write-Output "CRED_OK"
