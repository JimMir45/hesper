# Guest-side: velo install with full logging to C:\Hesper\velo\install-log.txt
$log = @()
try {
    $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).NextHop
    $base = "http://${gw}:48999"
    $log += "GW=$gw BASE=$base"
    New-Item -ItemType Directory -Force -Path C:\Hesper\velo | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    foreach ($f in @("velo-client.exe", "velo-client.yaml")) {
        $dst = "C:\Hesper\velo\$f"
        $url = "$base/$f"
        if (Test-Path $dst) { $log += "SKIP $f (exists, $((Get-Item $dst).Length) bytes)"; continue }
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dst
            $log += "FETCH-OK $f url=$url bytes=$((Get-Item $dst).Length)"
        } catch {
            $resp = $_.Exception.Response
            if ($resp) {
                $log += "FETCH-FAIL $f url=$($resp.ResponseUri) status=$([int]$resp.StatusCode)"
                $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                $log += "BODY=" + $sr.ReadToEnd().Substring(0, [Math]::Min(150, $sr.ReadToEnd().Length))
            } else {
                $log += "FETCH-FAIL $f no-resp: $($_.Exception.Message)"
            }
        }
    }

    $c = Get-Content C:\Hesper\velo\velo-client.yaml -Raw
    $c = $c.Replace("wss://localhost:8000/", "wss://${gw}:18000/").Replace("https://localhost:8000/", "https://${gw}:18000/")
    Set-Content -Path C:\Hesper\velo\velo-client.yaml -Value $c -Encoding ascii
    $log += "URLS-PATCHED-TO=$gw"

    & C:\Hesper\velo\velociraptor.exe service install -c C:\Hesper\velo\velo-client.yaml 2>&1 | ForEach-Object { $log += "svc-install: $_" }
    Start-Service Velociraptor -ErrorAction SilentlyContinue
    Start-Sleep 5
    $svc = Get-Service Velociraptor -ErrorAction SilentlyContinue
    $log += "SVC=" + $(if ($svc) { $svc.Status } else { "MISSING" })
} catch {
    $log += "OUTER-FAIL: " + $_.Exception.Message
    if ($_.Exception.Response) { $log += "OUTER-URL=" + $_.Exception.Response.ResponseUri }
}
$log += "INSTALL-LOGGED-DONE"
Set-Content -Path C:\Hesper\velo\install-log.txt -Value ($log -join "`n") -Encoding ascii
