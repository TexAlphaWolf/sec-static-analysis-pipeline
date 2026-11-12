# The benchmark on your own computer, in Docker (no network, read-only root, no capabilities), from Windows PowerShell: the
# time of each step, the whole scan with more and more workers, the fast against the literal entropy and checksum, and the
# verification on generated and damaged files. It takes a few minutes.
# Usage: .\tools\run_full.ps1 [-Sizes 200,1000] [-Workers 1,2,4,8] [-Repeat 3] [-VerifyFiles 1000] [-Out results]
param(
    [string]$Sizes = "200,1000",
    [string]$Workers = "1,2,4,8",
    [int]$Repeat = 3,
    [int]$VerifyFiles = 1000,
    [string]$Out = "results"
)
# Windows PowerShell 5.1 turns anything a program writes on stderr into an error under "Stop": docker prints its progress
# there, so only the exit code is looked at.
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$outFull = (Resolve-Path -LiteralPath $Out).Path

docker build -t pescan .
if ($LASTEXITCODE -ne 0) { Write-Host "docker build failed"; exit 1 }

Write-Host "== bench (sizes $Sizes files, workers $Workers, $Repeat runs each, $VerifyFiles files verified) =="
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --network none -v "${outFull}:/out" pescan bench --sizes $Sizes --workers $Workers --repeat $Repeat --verify-files $VerifyFiles --out /out
if ($LASTEXITCODE -ne 0) { Write-Host "bench failed (exit code $LASTEXITCODE)"; exit 1 }
Write-Host "Done. Send me $Out\bench.json, $Out\bench.md and $Out\bench.png."
