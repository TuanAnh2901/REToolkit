param(
    [Parameter(Mandatory = $true)][string]$Output
)
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'tool.cs'
Add-Type -TypeDefinition (Get-Content -Raw -LiteralPath $source) -OutputAssembly $Output
Write-Output "built $Output"
