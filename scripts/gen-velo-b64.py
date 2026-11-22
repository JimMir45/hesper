import base64

cmd = r'''
$log = @()
try {
  $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).NextHop
  $base = "http://${gw}:48999"
  $log += "GW=$gw"
  if (-not (Test-Path C:\Hesper\velo\velociraptor.exe)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri "$base/velo-client.exe" -OutFile C:\Hesper\velo\velociraptor.exe
  }
  if (-not (Test-Path C:\Hesper\velo\client.yaml)) {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/velo-client.yaml" -OutFile C:\Hesper\velo\client.yaml
  }
  $log += "exe=" + (Get-Item C:\Hesper\velo\velociraptor.exe).Length
  $c = Get-Content C:\Hesper\velo\client.yaml -Raw
  $c = $c.Replace("wss://localhost:8000/", "wss://${gw}:18000/").Replace("https://localhost:8000/", "https://${gw}:18000/")
  Set-Content -Path C:\Hesper\velo\client.yaml -Value $c -Encoding ascii
  $log += "urls-patched-to=$gw"
  & C:\Hesper\velo\velociraptor.exe service install -c C:\Hesper\velo\client.yaml 2>&1 | ForEach-Object { $log += "svc-install: $_" }
  Start-Service Velociraptor -ErrorAction SilentlyContinue
  Start-Sleep 5
  $svc = Get-Service Velociraptor -ErrorAction SilentlyContinue
  $log += "SVC=" + $(if ($svc) { $svc.Status } else { "MISSING" })
} catch {
  $log += "FAIL: " + $_.Exception.Message
}
$log += "INSTALL-DONE"
Set-Content -Path C:\Hesper\velo\install-log.txt -Value ($log -join "`n") -Encoding ascii
'''

print(base64.b64encode(cmd.encode("utf-16le")).decode())
