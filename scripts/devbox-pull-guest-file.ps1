# Devbox-side: pull a guest file (base64 via host remoting) and decode.
param(
    [string]$GuestPath = "C:\Hesper\velo\install-log.txt",
    [string]$LocalOut = "C:\hesper-lab\pulled-file.txt"
)
$ips = @((Get-VM hesper-litevms-dc01 | Get-VMNetworkAdapter).IPAddresses) | Where-Object { $_ -match "^\d" }
$dcip = [string]($ips | Select-Object -First 1)
$pw = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("hesper\vagrant", $pw)
$opt = New-PSSessionOption -OpenTimeout 15000
Invoke-Command -ComputerName $dcip -Credential $cred -SessionOption $opt -ScriptBlock {
    param($p)
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($p))
} -ArgumentList $GuestPath | ForEach-Object {
    [IO.File]::WriteAllBytes($LocalOut, [Convert]::FromBase64String($_))
}
Get-Content $LocalOut -Raw
