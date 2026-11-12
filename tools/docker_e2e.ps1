# End to end inside the image, from Windows PowerShell: a corpus of generated PE files with damaged copies is written, scanned
# against its truth with YARA and pefile, scanned again from a read-only mount, a report is rebuilt exactly from its JSON, the
# two ways of computing are verified and the benchmark runs small (read-only root, no capabilities, no network).
# Needs Docker Desktop. Usage: .\tools\docker_e2e.ps1 [-Image pescan]
param([string]$Image = "pescan")
$ErrorActionPreference = "Stop"

$id = Get-Random
$vol = "pescan-e2e-$id"
$base = @("--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--network", "none")
$secure = $base + @("-v", "${vol}:/data")

# Windows PowerShell 5.1 turns a program's message on stderr into an error under "Stop" (and pescan writes its progress
# there): every command runs with errors not terminating, and only its exit code and standard output are looked at.
function Invoke-PescanCode([int[]]$Allowed, [string[]]$Mounts, [string[]]$PescanArgs) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = docker run --rm @Mounts $Image @PescanArgs 2>$null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    if ($Allowed -notcontains $code) { throw "pescan $PescanArgs exited with $code : $out" }
    ($out | Out-String)
}
function Invoke-Pescan([string[]]$PescanArgs) { Invoke-PescanCode @(0) $secure $PescanArgs }
function Read-Volume($path) {
    $out = docker run --rm --entrypoint cat -v "${vol}:/data" $Image $path 2>$null
    if ($LASTEXITCODE -ne 0) { throw "cannot read $path" }
    ($out | Out-String)
}
function Assert-Contains($text, $needle) { if ($text -notmatch [regex]::Escape($needle)) { throw "expected '$needle' in: $text" } }

try {
    docker volume create $vol | Out-Null
    docker run --rm --user 0 -v "${vol}:/data" --entrypoint chown $Image 10001 /data
    if ($LASTEXITCODE -ne 0) { throw "could not prepare the volume" }

    Assert-Contains (Invoke-Pescan @("corpus", "/data/c", "--files", "60", "--seed", "3", "--damaged", "1")) "60 files, 60 damaged copies"
    $rep = Invoke-Pescan @("scan", "/data/c", "--reference", "--workers", "2", "--out", "/data/r")
    Assert-Contains $rep "121 files, 104 PE"
    Assert-Contains $rep "against the truth: 60 of 60 files exactly right (Python), 60 (YARA)"
    Assert-Contains $rep "pefile: 102 of 103 files read identically, 1 refused by pefile"
    Assert-Contains (Read-Volume "/data/r/report.json") '"kind": "scan"'
    $md = Read-Volume "/data/r/report.md"
    Invoke-Pescan @("render", "/data/r/report.json", "-o", "/data/r/again.md") | Out-Null
    if ((Read-Volume "/data/r/again.md") -ne $md) { throw "the report rebuilt from the JSON is not identical" }

    # the files to analyse mounted read-only, the way a real folder is scanned
    $ro = $base + @("-v", "${vol}:/in:ro")
    Assert-Contains (Invoke-PescanCode @(0) $ro @("scan", "/in/c", "--depth", "0", "--name", "read-only")) "read-only: 61 files, 60 PE"

    Assert-Contains (Invoke-Pescan @("show", "/data/c/sample00001.exe")) '"kind": "pe"'
    Assert-Contains (Invoke-Pescan @("rules")) "rule overlay : indicator"
    Assert-Contains (Invoke-Pescan @("verify", "--files", "40")) "6 of 6 checks passed"

    Invoke-Pescan @("bench", "--sizes", "20", "--workers", "1,2", "--repeat", "1", "--verify-files", "20", "--out", "/data/bench") | Out-Null
    Assert-Contains (Read-Volume "/data/bench/bench.json") '"ok": true'

    Invoke-PescanCode @(2) $secure @("scan", "/data/nope") | Out-Null
    Write-Host "docker end-to-end: OK"
}
finally {
    $ErrorActionPreference = "Continue"
    docker volume rm -f $vol 2>&1 | Out-Null
}
