# Install the Velociraptor client and enroll this host with the lab's
# Velociraptor server (WSL docker, reached via the default-gateway portproxy).
# Idempotent via marker file. Assets come from the dep server (gateway:48999):
#   velo-client.exe  - windows client binary (v0.77.3, matches server)
#   velo-client.yaml - client config; ServerUrls are patched per-boot to the
#                      dynamic gateway (Default Switch host IP or VBox NAT GW).
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path C:\Hesper\provision | Out-Null

$marker = "C:\Hesper\provision\velo-agent.done"
if (Test-Path $marker) { Write-Output "VELO-AGENT-ALREADY"; exit 0 }

$gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric |
       Select-Object -First 1).NextHop
$base = "http://${gw}:48999"
Write-Output "DEP-SERVER $base"

New-Item -ItemType Directory -Force -Path C:\Hesper\velo | Out-Null

Invoke-WebRequest -UseBasicParsing -Uri "$base/velo-client.exe" -OutFile C:\Hesper\velo\velociraptor.exe
Invoke-WebRequest -UseBasicParsing -Uri "$base/velo-client.yaml" -OutFile C:\Hesper\velo\client.yaml

# Patch ServerUrls: the server-generated config points at localhost:8000;
# the VM reaches the frontend through the gateway's portproxy (18000).
$cfg = Get-Content C:\Hesper\velo\client.yaml -Raw
$cfg = $cfg.Replace("wss://localhost:8000/", "wss://${gw}:18000/")
$cfg = $cfg.Replace("https://localhost:8000/", "https://${gw}:18000/")
Set-Content -Path C:\Hesper\velo\client.yaml -Value $cfg -Encoding ascii

$exeLen = (Get-Item C:\Hesper\velo\velociraptor.exe).Length
if ($exeLen -lt 10000000) { throw "velociraptor.exe suspiciously small ($exeLen bytes)" }
Write-Output "VELO-ASSETS-OK exe=$exeLen urls-patched=$gw"

# Enroll: run once in foreground (config API url must not block), then install
# as a service and start it.
& C:\Hesper\velo\velociraptor.exe service create -c C:\Hesper\velo\client.yaml 2>&1 | Out-Null
Start-Service -Name Velociraptor -ErrorAction SilentlyContinue
$s = Get-Service -Name Velociraptor -ErrorAction SilentlyContinue
if ($s) { Write-Output "VELO-SERVICE=$($s.Status)" } else { Write-Output "VELO-SERVICE-MISSING" }

New-Item -ItemType File -Path $marker -Force | Out-Null
Write-Output "VELO-AGENT-DONE"
