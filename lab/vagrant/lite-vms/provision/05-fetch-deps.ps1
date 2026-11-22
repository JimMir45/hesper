# Fetch provision deps over the gateway path (VM -> default gateway = host,
# on both VBox NAT (10.0.2.2) and Hyper-V Default Switch (host vNIC IP) ->
# portproxy/mirrored-loopback -> WSL http.server on provision-files/). WinRM
# file transfer proved too slow for the 3.2MB Sysmon binary on slow guests
# (M4-1 finding); this path is also the M4-2 topology under test.
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path C:\Hesper\deps | Out-Null

# Dynamic gateway: works for VBox NAT and Hyper-V Default Switch alike.
$gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric |
       Select-Object -First 1).NextHop
if (-not $gw) { throw "no default gateway — cannot locate dep server" }
# Port 48999: verified free on the original shared host (18080 is owned by a
# company SPA answering 200-with-index.html to every path; 47807 shows "in
# use" only inside mirrored-WSL — M4-1 findings).
$base = "http://${gw}:48999"
Write-Output "DEP-SERVER $base"

foreach ($f in @("Sysmon64.exe", "sysmonconfig.xml", "vulnAD.ps1")) {
    $out = "C:\Hesper\deps\$f"
    # always re-fetch: cache may hold a junk 585-byte index.html from the
    # port-collision incident
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$f" -OutFile $out
    $len = (Get-Item $out).Length
    if ($len -lt 1000) { throw "dep $f suspiciously small ($len bytes) — server wrong?" }
    Write-Output "DEP-FETCHED $f $len bytes"
}
Write-Output "DEPS-FETCH-DONE"
