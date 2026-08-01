param([string]$Output = "ghidra-benchmark.json")
$ErrorActionPreference = "Stop"
& py -3.13 -m retoolkit ghidra benchmark --output $Output
if ($LASTEXITCODE -ne 0) { throw "benchmark exited $LASTEXITCODE" }
