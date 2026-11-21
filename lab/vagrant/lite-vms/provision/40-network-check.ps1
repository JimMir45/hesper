# M4-2 evidence: VM -> VBox NAT gateway (10.0.2.2) -> host loopback -> WSL
# mirrored -> lab containers. Informational (exit 0 either way) — the run log
# carries the facts.
$ErrorActionPreference = "Continue"

foreach ($t in @(@{p=18000; n="velociraptor-frontend"}, @{p=8889; n="velociraptor-gui"}, @{p=4280; n="dvwa"})) {
    $r = Test-NetConnection -ComputerName 10.0.2.2 -Port $t.p -WarningAction SilentlyContinue
    Write-Output "M4-2-NETCHECK $($t.n) 10.0.2.2:$($t.p) TcpTestSucceeded=$($r.TcpTestSucceeded)"
}
Write-Output "M4-2-NETCHECK-DONE host=$env:COMPUTERNAME"
