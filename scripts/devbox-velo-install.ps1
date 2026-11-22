# Devbox-side: run the velo install inside the VM via vagrant winrm
# (EncodedCommand, no quoting layers), output silent; the guest writes its
# own log which we pull separately.
$env:VAGRANT_HOME = "C:\hesper-lab\vagrant-home"
Set-Location C:\hesper-lab\lite-vms
$b64 = Get-Content C:\hesper-lab\velo-b64.txt -Raw
& "C:\Program Files\Vagrant\bin\vagrant.exe" winrm dc -c "powershell -NoProfile -EncodedCommand $b64" | Out-Null
Write-Output "INSTALL-RAN"
