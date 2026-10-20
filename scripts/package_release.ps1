# Packages the prebuilt deobfuscator binaries checked into this repo into flat,
# user-ready zips for a GitHub release.
#   pwsh -File scripts/package_release.ps1 -Version 1.0.0
param(
    [string]$Version = '1.0.0',
    [string]$OutDir = '.tmp/release'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$out = Join-Path $root $OutDir
New-Item -ItemType Directory -Force -Path $out | Out-Null
$work = Join-Path $out '_stage'
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null

# Extract a zip into flat, user-ready layout: pick the shallowest folder that
# actually holds the executable (skips de4dot-cex\de4dot-cex style wrappers).
function Expand-Flat([string]$Zip, [string]$Dest) {
    $tmp = Join-Path $work ([guid]::NewGuid())
    [IO.Compression.ZipFile]::ExtractToDirectory($Zip, $tmp)
    $src = $tmp
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($tmp)
    while ($queue.Count -gt 0) {
        $dir = $queue.Dequeue()
        if (@(Get-ChildItem $dir -File -Filter *.exe).Count -gt 0) { $src = $dir; break }
        Get-ChildItem $dir -Directory -Force | Sort-Object Name | ForEach-Object { $queue.Enqueue($_.FullName) }
    }
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    Copy-Item (Join-Path $src '*') $Dest -Recurse -Force
    Remove-Item $tmp -Recurse -Force
}

function Compress-Dir([string]$Dir, [string]$Name) {
    $zip = Join-Path $out "$Name.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    [IO.Compression.ZipFile]::CreateFromDirectory($Dir, $zip, [IO.Compression.CompressionLevel]::Optimal, $true)
    $zip
}

# name -> @{ From = path; Kind = 'zip'|'dir' }
$assets = [ordered]@{
    'de4dot-cex'             = @{ From = 'NoFuserEx/de4dot-cex.zip';                        Kind = 'zip' }
    'de4dotEx-3.2.2-net8.0'  = @{ From = 'NoFuserEx/de4dotEx-3.2.2-net8.0-win-x64.zip';     Kind = 'zip' }
    'NoFuserEx'              = @{ From = 'NoFuserEx/NoFuserEx/NoFuserEx/bin.zip';           Kind = 'zip' }
    'UnConfuserEx'           = @{ From = 'UnConfuserEx/bin.zip';                            Kind = 'zip' }
    'UnConfuserExTools'      = @{ From = 'NoFuserEx/UnconfuserExTools-main.zip';            Kind = 'zip' }
    'NETReactorSlayer'       = @{ From = 'NETReactorSlayer/bin/Release/net48';              Kind = 'dir'; Extra = @('NETReactorSlayer/LICENSE') }
    'EazFixer'               = @{ From = 'Deobfuscators/EazFixer';                          Kind = 'dir' }
    'ProxyFixCli'            = @{ From = 'Deobfuscators/ProxyFixCli/bin/Debug/net9.0';      Kind = 'dir'; Extra = @('Deobfuscators/ProxyFixCli/README.md') }
    'VMUnprotect.Dumper'     = @{ From = 'NoFuserEx/VMUnprotect.Dumper-net472.zip';         Kind = 'zip' }
    'ExtremeDumper'          = @{ From = 'NoFuserEx/ExtremeDumper.zip';                     Kind = 'zip' }
    'DetectItEasy'           = @{ From = 'NoFuserEx/die_win64_portable_3.11_x64.zip';       Kind = 'zip' }
    'GDRE-tools-1.0.2'       = @{ From = 'NoFuserEx/GDRE_tools-v1.0.2-windows.zip';         Kind = 'zip' }
    'Cpp2IL-cppdumper'       = @{ From = 'NoFuserEx/cppdumper-main/cppdumper-bin.zip';      Kind = 'zip' }
}

$built = @()
foreach ($name in $assets.Keys) {
    $a = $assets[$name]
    if (-not (Test-Path $a.From)) { Write-Warning "skip $name (missing $($a.From))"; continue }
    $dest = Join-Path $work $name
    if ($a.Kind -eq 'zip') { Expand-Flat (Resolve-Path $a.From) $dest }
    else { New-Item -ItemType Directory -Force -Path $dest | Out-Null; Copy-Item (Join-Path $a.From '*') $dest -Recurse -Force }
    foreach ($extra in $a.Extra) { if (Test-Path $extra) { Copy-Item $extra $dest -Force } }
    $exes = @(Get-ChildItem $dest -Recurse -Filter *.exe)
    if ($exes.Count -eq 0) { throw "$name contains no .exe - not a usable build" }
    $zip = Compress-Dir $dest "REToolkit-v$Version-$name"
    $built += [pscustomobject]@{ Asset = Split-Path $zip -Leaf; MB = [math]::Round((Get-Item $zip).Length / 1MB, 1); Exes = $exes.Count }
}

# single download that contains everything
$bundle = Join-Path $work 'bundle'
New-Item -ItemType Directory -Force -Path $bundle | Out-Null
foreach ($name in $assets.Keys) {
    $dest = Join-Path $work $name
    if (Test-Path $dest) { Copy-Item $dest (Join-Path $bundle $name) -Recurse -Force }
}
$bundleZip = Compress-Dir $bundle "REToolkit-v$Version-Deobfuscators-ALL"
$built += [pscustomobject]@{ Asset = Split-Path $bundleZip -Leaf; MB = [math]::Round((Get-Item $bundleZip).Length / 1MB, 1); Exes = 'bundle' }

$built | Format-Table -AutoSize
$built | ConvertTo-Json | Set-Content (Join-Path $out 'assets.json') -Encoding utf8
Write-Host "assets in $out"
