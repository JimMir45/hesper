# Devbox-side: run the guest probe (EncodedCommand from file), then pull probe.txt
$env:VAGRANT_HOME = "C:\hesper-lab\vagrant-home"
Set-Location C:\hesper-lab\lite-vms
$b64 = Get-Content C:\hesper-lab\probe-b64.txt -Raw
& "C:\Program Files\Vagrant\bin\vagrant.exe" winrm dc -c "powershell -NoProfile -EncodedCommand $b64" | Out-Null
Write-Output "PROBE-RAN"
$ips = @((Get-VM hesper-litevms-dc01 | Get-VMNetworkAdapter).IPAddresses) | Where-Object { $_ -match "^\d" }
$dcip = [string]($ips | Select-Object -First 1)
$pw = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("hesper\vagrant", $pw)
$opt = New-PSSessionOption -OpenTimeout 15000
Invoke-Command -ComputerName $dcip -Credential $cred -SessionOption $opt -ScriptBlock {
    if (Test-Path C:\Hesper\velo\probe.txt) { Get-Content C:\Hesper\velo\probe.txt -Raw } else { Write-Output "NO-PROBE-FILE" }
}
