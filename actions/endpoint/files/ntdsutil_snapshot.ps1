# Hesper lab action: ntdsutil snapshot operations (T1003.003, light variant).
# Technique source: redcanaryco/atomic-red-team (MIT), technique T1003.003.
# Runs ONLY inside the bundled lab VMs, gated by the Hesper scope kernel.
#
# Contract with the vm adapter: parameters arrive via -ParamsFile (JSON).
# Expected params: { "out_dir": "C:\\hesper\\out", "marker": "snapshot.marker" }

param(
    [Parameter(Mandatory = $true)]
    [string]$ParamsFile
)

$ErrorActionPreference = "Continue"
$params = Get-Content -Raw -Path $ParamsFile | ConvertFrom-Json
$outDir = if ($params.out_dir) { $params.out_dir } else { "C:\hesper\out" }
$marker = if ($params.marker) { $params.marker } else { "snapshot.marker" }
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Snapshot create + list via ntdsutil — no dump material produced.
ntdsutil "ac i ntds" "snaps" "create" "list all" "q" "q" |
    Tee-Object -FilePath "$outDir\ntdsutil_snapshot.log"

# Proof artifact (must_capture kind: file).
Copy-Item "$outDir\ntdsutil_snapshot.log" (Join-Path $outDir $marker)

Write-Output "ntdsutil snapshot cycle complete"
