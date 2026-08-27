$ErrorActionPreference = 'Stop'

$sourceRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'src'
$failures = @()

foreach ($file in Get-ChildItem -LiteralPath $sourceRoot -File -Filter '*.rs') {
    $lines = Get-Content -LiteralPath $file.FullName
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -cnotmatch '^\s*pub fn [A-Z][A-Za-z0-9_]*') {
            continue
        }

        $documentation = @()
        for ($cursor = $index - 1; $cursor -ge 0; $cursor--) {
            if ($lines[$cursor] -match '^\s*///') {
                $documentation = @($lines[$cursor]) + $documentation
                continue
            }
            break
        }
        if (($documentation -join "`n") -notmatch '# Safety') {
            $name = [regex]::Match($lines[$index], 'pub fn ([A-Za-z0-9_]+)').Groups[1].Value
            $failures += "$($file.Name):$($index + 1): $name"
        }
    }
}

if ($failures.Count -ne 0) {
    throw "Public FFI functions missing a # Safety section:`n$($failures -join "`n")"
}

Write-Output 'Every public Win32 FFI function has a # Safety contract.'
