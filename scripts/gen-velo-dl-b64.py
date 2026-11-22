import base64

cmd = r'''
$ErrorActionPreference = "Stop"
$gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).NextHop
$base = "http://${gw}:48999"
New-Item -ItemType Directory -Force -Path C:\Hesper\velo | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ok = $false
for ($i = 1; $i -le 5; $i++) {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/velo-client.exe" -OutFile C:\Hesper\velo\velociraptor.exe
        Invoke-WebRequest -UseBasicParsing -Uri "$base/velo-client.yaml" -OutFile C:\Hesper\velo\client.yaml
        $exeLen = (Get-Item C:\Hesper\velo\velociraptor.exe).Length
        if ($exeLen -gt 50000000) { $ok = $true; Write-Output "DL-OK try=$i exe=$exeLen"; break }
        Write-Output "DL-RETRY try=$i exe=$exeLen too small"
    } catch {
        Write-Output "DL-RETRY try=$i : $($_.Exception.Message.Substring(0, [Math]::Min(50, $_.Exception.Message.Length)))"
    }
    Start-Sleep 5
}
if (-not $ok) { throw "download failed after 5 tries" }
'''

print(base64.b64encode(cmd.encode("utf-16le")).decode())
