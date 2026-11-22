# Guest-side diagnostic: reproduce the card execution and capture everything.
$log = @()
$log += "=== uploaded script head ==="
$log += (Get-Content C:\hesper\m4-ntdsutil-susp.ps1 -TotalCount 6 -ErrorAction SilentlyContinue | Out-String)
$log += "=== params file ==="
$log += (Get-Content C:\hesper\m4-ntdsutil-susp.params.json -Raw -ErrorAction SilentlyContinue)
$log += "=== run -File ==="
$out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\hesper\m4-ntdsutil-susp.ps1 -ParamsFile C:\hesper\m4-ntdsutil-susp.params.json 2>&1
$code = $LASTEXITCODE
$log += ("exit=" + $code)
foreach ($l in $out) { $log += "OUT| $l" }
$log += "=== ntdsutil presence ==="
$log += (Get-Command ntdsutil -ErrorAction SilentlyContinue | Out-String)
$log += "=== out dir ==="
$log += (Get-ChildItem C:\hesper -Recurse -ErrorAction SilentlyContinue | Out-String)
Set-Content -Path C:\hesper\diag.txt -Value ($log -join "`r`n") -Encoding ascii
Write-Output "DIAG-WRITTEN"
