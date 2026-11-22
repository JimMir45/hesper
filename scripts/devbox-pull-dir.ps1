# Devbox-side: pull C:\hesper\out listing + marker status from the VM.
$ips = @((Get-VM hesper-litevms-dc01 | Get-VMNetworkAdapter).IPAddresses) | Where-Object { $_ -match "^\d" }
$dcip = [string]($ips | Select-Object -First 1)
$pw = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("hesper\vagrant", $pw)
$opt = New-PSSessionOption -OpenTimeout 15000
Invoke-Command -ComputerName $dcip -Credential $cred -SessionOption $opt -ScriptBlock {
    Get-ChildItem C:\hesper\out -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String
    Write-Output ("marker_exists=" + (Test-Path C:\hesper\out\snapshot.marker))
}
