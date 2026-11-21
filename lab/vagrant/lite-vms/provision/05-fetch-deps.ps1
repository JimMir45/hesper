# Fetch provision deps over the VBox NAT gateway path (10.0.2.2 -> host
# loopback -> WSL mirrored -> http.server on provision-files/). WinRM file
# transfer proved too slow for the 3.2MB Sysmon binary on nested-virt guests
# (M4-1 finding); this path is also the M4-2 topology under test.
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path C:\Hesper\deps | Out-Null

# Port 47807: verified free on this shared host (18080 is owned by a company
# SPA that answers 200-with-index.html to every path — M4-1 finding).
$base = "http://10.0.2.2:47807"
$expected = @{ "Sysmon64.exe" = 3203368; "sysmonconfig.xml" = 360048; "vulnAD.ps1" = 65052 }
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
