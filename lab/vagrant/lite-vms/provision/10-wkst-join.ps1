# Point DNS at the DC and join hesper.lab (idempotent).
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path C:\Hesper\provision | Out-Null

# DNS on the host-only NIC (the one holding 192.168.56.20)
$ip = Get-NetIPAddress -IPAddress 192.168.56.20 -ErrorAction SilentlyContinue
if ($ip) {
    Set-DnsClientServerAddress -InterfaceIndex $ip.InterfaceIndex -ServerAddresses "192.168.56.10"
    Write-Output "DNS-SET interface=$($ip.InterfaceIndex) -> 192.168.56.10"
} else {
    Write-Output "DNS-SKIP host-only IP not found (already re-run?)"
}

if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
    Write-Output "ALREADY-DOMAIN-JOINED"
    exit 0
}

$pass = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$joined = $false
foreach ($u in @("HESPER\vagrant", "HESPER\Administrator", "hesper.lab\vagrant")) {
    try {
        $cred = New-Object System.Management.Automation.PSCredential($u, $pass)
        Add-Computer -DomainName "hesper.lab" -Credential $cred -Restart:$false -ErrorAction Stop
        Write-Output "DOMAIN-JOINED-AS $u"
        $joined = $true
        break
    } catch {
        Write-Output "JOIN-TRY $u failed: $($_.Exception.Message)"
    }
}
if (-not $joined) { throw "domain join failed with all credential variants" }
Write-Output "JOIN-DONE-REBOOT-REQUIRED"
