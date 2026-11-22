# Devbox-side: pull the velo install log from the VM (via host remoting).
$ips = @((Get-VM hesper-litevms-dc01 | Get-VMNetworkAdapter).IPAddresses) | Where-Object { $_ -match "^\d" }
$dcip = [string]($ips | Select-Object -First 1)
$pw = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("hesper\vagrant", $pw)
$opt = New-PSSessionOption -OpenTimeout 15000
Invoke-Command -ComputerName $dcip -Credential $cred -SessionOption $opt -ScriptBlock {
  if (Test-Path C:\Hesper\velo\install-log.txt) { Get-Content C:\Hesper\velo\install-log.txt -Raw }
  $svc = Get-Service Velociraptor -ErrorAction SilentlyContinue
  Write-Output "SVC=$(if ($svc) { $svc.Status } else { 'MISSING' })"
}
