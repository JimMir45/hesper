$env:VAGRANT_HOME = "C:\hesper-lab\vagrant-home"
Set-Location C:\hesper-lab\lite-vms
$b64 = Get-Content C:\hesper-lab\dir-b64.txt -Raw
& "C:\Program Files\Vagrant\bin\vagrant.exe" winrm dc -c "powershell -NoProfile -EncodedCommand $b64" | Out-Null
Write-Output "DIR-RAN"
