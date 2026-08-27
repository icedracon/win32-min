param(
    [ValidateRange(1, 20)]
    [int]$Runs = 3
)

$ErrorActionPreference = 'Stop'
$benchmarkRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$variants = @('win32-min', 'windows-sys', 'windows')
$results = @()

function Remove-ExactDirectory {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ExpectedParent
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a directory outside $ExpectedParent`: $resolved"
    }
    if (Test-Path -LiteralPath $resolved) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

foreach ($variant in $variants) {
    $variantRoot = [IO.Path]::GetFullPath((Join-Path $benchmarkRoot $variant))
    $manifest = Join-Path $variantRoot 'Cargo.toml'
    $targetDir = Join-Path $variantRoot 'target'
    $packageName = "bench-$variant"
    $coldDurations = @()

    for ($run = 1; $run -le $Runs; $run++) {
        Remove-ExactDirectory -Path $targetDir -ExpectedParent $variantRoot

        $timer = [Diagnostics.Stopwatch]::StartNew()
        cargo build --release --manifest-path $manifest
        if ($LASTEXITCODE -ne 0) {
            throw "Cold benchmark build failed for $variant."
        }
        $timer.Stop()
        $coldDurations += $timer.Elapsed.TotalSeconds
    }

    cargo clean --manifest-path $manifest -p $packageName
    if ($LASTEXITCODE -ne 0) {
        throw "Application-only clean failed for $variant."
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    cargo build --release --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) {
        throw "Incremental benchmark build failed for $variant."
    }
    $timer.Stop()
    $incrementalSeconds = $timer.Elapsed.TotalSeconds

    Remove-ExactDirectory -Path (Join-Path $targetDir 'doc') -ExpectedParent $targetDir
    $timer = [Diagnostics.Stopwatch]::StartNew()
    cargo doc --release --no-deps --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) {
        throw "Rustdoc benchmark failed for $variant."
    }
    $timer.Stop()
    $rustdocSeconds = $timer.Elapsed.TotalSeconds

    $metadata = cargo metadata --format-version 1 --manifest-path $manifest | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for $variant."
    }
    $bindingPackageName = if ($variant -eq 'win32-min') { 'win32-min' } else { $variant }
    $bindingPackage = $metadata.packages | Where-Object name -EQ $bindingPackageName | Select-Object -First 1
    if (-not $bindingPackage) {
        throw "Binding package $bindingPackageName was absent from metadata."
    }
    $bindingRoot = Split-Path -Parent $bindingPackage.manifest_path
    $sourceFiles = Get-ChildItem -LiteralPath $bindingRoot -Recurse -File -Filter '*.rs' |
        Where-Object FullName -NotLike '*\target\*'

    $binary = Join-Path $targetDir "release\$packageName.exe"
    $results += [pscustomobject]@{
        variant = $variant
        runs = $Runs
        cold_build_seconds_mean = [math]::Round(($coldDurations | Measure-Object -Average).Average, 3)
        incremental_rebuild_seconds = [math]::Round($incrementalSeconds, 3)
        rustdoc_seconds = [math]::Round($rustdocSeconds, 3)
        executable_bytes = (Get-Item -LiteralPath $binary).Length
        dependency_package_count = $metadata.packages.Count - 1
        binding_source_files = $sourceFiles.Count
        binding_source_bytes = ($sourceFiles | Measure-Object Length -Sum).Sum
        rustc = (rustc --version)
        host = [Runtime.InteropServices.RuntimeInformation]::OSDescription
    }
}

$output = Join-Path $benchmarkRoot 'results.csv'
$results | Export-Csv -NoTypeInformation -Path $output
$results | Format-Table -AutoSize
Write-Output "Results written to $output"
