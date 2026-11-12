# Scan a real folder of Windows programs (by default C:\Windows\System32, only the files directly in it) in Docker: the folder
# is mounted read-only, the container has no network, no capabilities and a read-only root, and nothing is executed. Every
# file is also read by pefile and compared, and the YARA rules run next to the Python traits.
# Usage: .\tools\run_real.ps1 [-Path C:\Windows\System32] [-Depth 0] [-Workers <CPUs>] [-Out results\system32]
param(
    [string]$Path = "$env:WINDIR\System32",
    [int]$Depth = 0,
    [int]$Workers = [int]$env:NUMBER_OF_PROCESSORS,
    [string]$Out = "results\system32"
)
$ErrorActionPreference = "Continue"
$inFull = (Resolve-Path -LiteralPath $Path).Path
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$outFull = (Resolve-Path -LiteralPath $Out).Path
if ($Workers -lt 1) { $Workers = 1 }

docker build -t pescan .
if ($LASTEXITCODE -ne 0) { Write-Host "docker build failed"; exit 1 }

$os = Get-CimInstance Win32_OperatingSystem
$name = "$inFull ($($os.Caption.Trim()), build $($os.BuildNumber))"
Write-Host "== scan: $name, depth $Depth, $Workers workers (a few minutes; a progress line every 500 files) =="
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --network none `
    -v "${inFull}:/in:ro" -v "${outFull}:/out" `
    pescan scan /in --depth $Depth --workers $Workers --reference --name $name --out /out
if ($LASTEXITCODE -ne 0) { Write-Host "scan failed (exit code $LASTEXITCODE)"; exit 1 }
Write-Host "Done. Send me $Out\report.json, $Out\report.md, $Out\summary.png and the lines printed above."
Write-Host "($Out\files.jsonl has one line per file: keep it, it is large and lists the files of your system.)"
