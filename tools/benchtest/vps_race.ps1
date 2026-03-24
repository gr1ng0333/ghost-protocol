## VPS race detector script — runs remotely via SSH
## Executes: build, test, race detect on VPS, saves results locally

$outDir = "$PSScriptRoot\..\.."
$vps = "ghost-vps"

function VPS-Run {
    param([string]$cmd)
    $result = ssh $vps $cmd 2>&1
    return ($result | Out-String)
}

Write-Host "=== Step 1: Build ===" -ForegroundColor Cyan
$build = VPS-Run 'cd /root/ghost && /usr/local/go/bin/go build ./... 2>&1; echo BUILD_RC=$?'
Write-Host $build
$build | Out-File "$outDir\vps_build.txt" -Encoding utf8

Write-Host "=== Step 2: Test (no race) ===" -ForegroundColor Cyan
$test = VPS-Run 'cd /root/ghost && /usr/local/go/bin/go test -count=1 -timeout=300s ./... 2>&1; echo TEST_RC=$?'
Write-Host $test
$test | Out-File "$outDir\vps_test.txt" -Encoding utf8

Write-Host "=== Step 3: Race Detector ===" -ForegroundColor Cyan
$race = VPS-Run 'cd /root/ghost && CGO_ENABLED=1 /usr/local/go/bin/go test -race -count=1 -timeout=300s ./... 2>&1; echo RACE_RC=$?'
Write-Host $race
$race | Out-File "$outDir\vps_race.txt" -Encoding utf8

Write-Host "=== Done. Results saved to vps_build.txt, vps_test.txt, vps_race.txt ===" -ForegroundColor Green
