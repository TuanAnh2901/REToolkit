# Non-live acceptance runner. Exits non-zero on any failure.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

Write-Output "=== retoolkit acceptance ==="

Write-Output "[1/4] Python acceptance suite"
& py -3.13 -m pytest (Join-Path $repo 'tests\acceptance') -q
if ($LASTEXITCODE -ne 0) { throw "acceptance tests failed" }

Write-Output "[2/4] Full non-live pytest suite"
& py -3.13 -m pytest (Join-Path $repo 'tests') -q
if ($LASTEXITCODE -ne 0) { throw "pytest suite failed" }

Write-Output "[3/4] Node resolver tests"
Push-Location $repo
& node --test (Join-Path $repo 'tests\js\*.test.mjs')
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "node tests failed" }
Pop-Location

Write-Output "[4/4] CLI determinism + stdout purity"
$out1 = & py -3.13 -m retoolkit doctor --json 2>$null | Out-String
$out2 = & py -3.13 -m retoolkit doctor --json 2>$null | Out-String
if ($out1 -cne $out2) { throw "doctor output not byte-deterministic" }
$null = $out1 | ConvertFrom-Json  # must parse as one JSON document

Write-Output "ACCEPTANCE PASSED"
