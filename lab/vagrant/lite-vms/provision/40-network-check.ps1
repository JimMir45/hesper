# M4-2 evidence: VM -> default gateway (host) -> portproxy/mirrored loopback
# -> WSL lab containers. Works for VBox NAT (10.0.2.2) and Hyper-V Default
# Switch (host vNIC IP) alike. Informational (exit 0 either way) — the run
# log carries the facts.
$ErrorActionPreference = "Continue"

$gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric |
       Select-Object -First 1).NextHop
Write-Output "NETCHECK-GATEWAY $gw"

foreach ($t in @(@{p=18000; n="velociraptor-frontend"}, @{p=8889; n="velociraptor-gui"}, @{p=4280; n="dvwa"})) {
    $r = Test-NetConnection -ComputerName $gw -Port $t.p -WarningAction SilentlyContinue
    Write-Output "M4-2-NETCHECK $($t.n) ${gw}:$($t.p) TcpTestSucceeded=$($r.TcpTestSucceeded)"
}
Write-Output "M4-2-NETCHECK-DONE host=$env:COMPUTERNAME"
