# Guest-side: probe the dep server for velo-client.exe, write probe.txt
$gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).NextHop
$result = @("GW=$gw")
try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "http://${gw}:48999/velo-client.exe" -Method Head -TimeoutSec 10
    $result += "HEAD-STATUS=$($r.StatusCode)"
    $result += "SRV=$($r.Headers.Server)"
} catch {
    $resp = $_.Exception.Response
    if ($resp) {
        $result += "HEAD-STATUS=$([int]$resp.StatusCode)"
        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
        $body = $sr.ReadToEnd()
        $result += "BODY404=" + $body.Substring(0, [Math]::Min(200, $body.Length))
    } else {
        $result += "NO-RESP: " + $_.Exception.Message
    }
}
New-Item -ItemType Directory -Force -Path C:\Hesper\velo | Out-Null
Set-Content -Path C:\Hesper\velo\probe.txt -Value ($result -join "`n") -Encoding ascii
