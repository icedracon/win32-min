$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $repoRoot 'Cargo.toml'
$metadata = cargo metadata --format-version 1 --no-deps --manifest-path $manifest | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw 'cargo metadata failed.'
}

$package = $metadata.packages | Where-Object manifest_path -EQ $manifest | Select-Object -First 1
if (-not $package) {
    throw 'win32-min was absent from cargo metadata.'
}
if ($package.dependencies.Count -ne 0) {
    $names = $package.dependencies | Select-Object -ExpandProperty name
    throw "win32-min must remain dependency-free; found: $($names -join ', ')"
}

Write-Output 'Dependency policy passed: zero normal, development, and build dependencies.'
