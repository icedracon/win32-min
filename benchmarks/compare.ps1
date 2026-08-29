param(
    [ValidateRange(3, 20)]
    [int]$Runs = 5
)

$ErrorActionPreference = 'Stop'
$benchmarkRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$variants = @('win32-min', 'windows-sys', 'windows')
$results = @()
$coldDurations = @{}
$timestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
$rustcVersion = (rustc --version)
$cargoVersion = (cargo --version)
$hostDescription = [Runtime.InteropServices.RuntimeInformation]::OSDescription
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim()

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
    cargo fetch --locked --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency prefetch failed for $variant."
    }
    $coldDurations[$variant] = @()
}

# Rotate the order every run so no binding always benefits from going first or
# suffers from going last. "Clean-target" deliberately means Cargo artifacts
# are removed while the registry and operating-system file caches stay warm.
for ($run = 0; $run -lt $Runs; $run++) {
    for ($offset = 0; $offset -lt $variants.Count; $offset++) {
        $variant = $variants[($run + $offset) % $variants.Count]
        $variantRoot = [IO.Path]::GetFullPath((Join-Path $benchmarkRoot $variant))
        $manifest = Join-Path $variantRoot 'Cargo.toml'
        $targetDir = Join-Path $variantRoot 'target'
        Remove-ExactDirectory -Path $targetDir -ExpectedParent $variantRoot

        $timer = [Diagnostics.Stopwatch]::StartNew()
        cargo build --release --locked --manifest-path $manifest
        if ($LASTEXITCODE -ne 0) {
            throw "Clean-target benchmark build failed for $variant."
        }
        $timer.Stop()
        $coldDurations[$variant] += $timer.Elapsed.TotalSeconds
    }
}

foreach ($variant in $variants) {
    $variantRoot = [IO.Path]::GetFullPath((Join-Path $benchmarkRoot $variant))
    $manifest = Join-Path $variantRoot 'Cargo.toml'
    $targetDir = Join-Path $variantRoot 'target'
    $packageName = "bench-$variant"

    $applicationSource = Join-Path $variantRoot 'src\main.rs'
    $originalWriteTimeUtc = (Get-Item -LiteralPath $applicationSource).LastWriteTimeUtc
    try {
        # Cargo's dependency artifacts remain cached, but a newer source mtime
        # forces the tiny application package itself to rebuild.
        (Get-Item -LiteralPath $applicationSource).LastWriteTimeUtc = [DateTime]::UtcNow.AddSeconds(1)
        $timer = [Diagnostics.Stopwatch]::StartNew()
        cargo build --release --locked --manifest-path $manifest
        if ($LASTEXITCODE -ne 0) {
            throw "Incremental benchmark build failed for $variant."
        }
        $timer.Stop()
        $incrementalSeconds = $timer.Elapsed.TotalSeconds
    }
    finally {
        (Get-Item -LiteralPath $applicationSource).LastWriteTimeUtc = $originalWriteTimeUtc
    }

    Remove-ExactDirectory -Path (Join-Path $targetDir 'doc') -ExpectedParent $targetDir
    $timer = [Diagnostics.Stopwatch]::StartNew()
    cargo doc --release --no-deps --locked --manifest-path $manifest
    if ($LASTEXITCODE -ne 0) {
        throw "Rustdoc benchmark failed for $variant."
    }
    $timer.Stop()
    $rustdocSeconds = $timer.Elapsed.TotalSeconds

    $metadata = cargo metadata --format-version 1 --locked --manifest-path $manifest | ConvertFrom-Json
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

    $coldMean = ($coldDurations[$variant] | Measure-Object -Average).Average
    $squaredDifferences = $coldDurations[$variant] | ForEach-Object {
        [math]::Pow($_ - $coldMean, 2)
    }
    $coldStandardDeviation = [math]::Sqrt(
        ($squaredDifferences | Measure-Object -Sum).Sum / ($Runs - 1)
    )
    $binary = Join-Path $targetDir "release\$packageName.exe"
    $results += [pscustomobject]@{
        variant = $variant
        binding_version = $bindingPackage.version
        runs = $Runs
        clean_target_build_seconds_mean = [math]::Round($coldMean, 3)
        clean_target_build_seconds_sample_stddev = [math]::Round($coldStandardDeviation, 3)
        clean_target_build_seconds_raw = (($coldDurations[$variant] | ForEach-Object {
            $_.ToString('0.000', [Globalization.CultureInfo]::InvariantCulture)
        }) -join ';')
        incremental_rebuild_seconds = [math]::Round($incrementalSeconds, 3)
        rustdoc_seconds = [math]::Round($rustdocSeconds, 3)
        executable_bytes = (Get-Item -LiteralPath $binary).Length
        dependency_package_count = $metadata.packages.Count - 1
        binding_source_files = $sourceFiles.Count
        binding_source_bytes = ($sourceFiles | Measure-Object Length -Sum).Sum
        timestamp_utc = $timestampUtc
        rustc = $rustcVersion
        cargo = $cargoVersion
        host = $hostDescription
        cpu = $cpu
    }
}

$output = Join-Path $benchmarkRoot 'results.csv'
$results | Export-Csv -NoTypeInformation -Path $output
$results | Format-Table -AutoSize
Write-Output "Results written to $output"
