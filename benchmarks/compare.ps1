param(
    [ValidateRange(1, 20)]
    [int]$Runs = 3
)

$ErrorActionPreference = 'Stop'
$benchmarkRoot = $PSScriptRoot
$variants = @('win32-min', 'windows-sys', 'windows')
$results = @()

foreach ($variant in $variants) {
    $manifest = Join-Path $benchmarkRoot "$variant\Cargo.toml"
    $targetDir = Join-Path $benchmarkRoot "$variant\target"
    $durations = @()

    for ($run = 1; $run -le $Runs; $run++) {
        if (Test-Path -LiteralPath $targetDir) {
            Remove-Item -LiteralPath $targetDir -Recurse -Force
        }

        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        cargo build --release --manifest-path $manifest
        if ($LASTEXITCODE -ne 0) {
            throw "Benchmark build failed for $variant."
        }
        $timer.Stop()
        $durations += $timer.Elapsed.TotalSeconds
    }

    $metadata = cargo metadata --format-version 1 --manifest-path $manifest | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for $variant."
    }

    $binary = Join-Path $targetDir "release\bench-$variant.exe"
    $results += [pscustomobject]@{
        variant = $variant
        runs = $Runs
        cold_build_seconds_mean = [math]::Round(($durations | Measure-Object -Average).Average, 3)
        executable_bytes = (Get-Item -LiteralPath $binary).Length
        dependency_package_count = $metadata.packages.Count - 1
        rustc = (rustc --version)
    }
}

$output = Join-Path $benchmarkRoot 'results.csv'
$results | Export-Csv -NoTypeInformation -Path $output
$results | Format-Table -AutoSize
Write-Output "Results written to $output"
