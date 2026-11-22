# Devbox-side: run a guest ps1 (b64 from file) via vagrant winrm, silent.
param(
    [string]$B64File = "C:\hesper-lab\guest-b64.txt"
)
$env:VAGRANT_HOME = "C:\hesper-lab\vagrant-home"
Set-Location C:\hesper-lab\lite-vms
$b64 = Get-Content $B64File -Raw
& "C:\Program Files\Vagrant\bin\vagrant.exe" winrm dc -c "powershell -NoProfile -EncodedCommand $b64" | Out-Null
Write-Output "GUEST-RAN"
