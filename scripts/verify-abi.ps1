param(
    [ValidateSet('x64', 'x86', 'arm64')]
    [string]$Arch = 'x64'
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repoRoot 'tests\sdk\abi.c'
$outputDir = Join-Path $repoRoot "target\abi-$Arch"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer (vswhere.exe) was not found.'
}

$installationPath = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $installationPath) {
    throw "A Visual Studio installation with the MSVC $Arch C++ tools was not found."
}

$devCmd = Join-Path $installationPath 'Common7\Tools\VsDevCmd.bat'
$object = Join-Path $outputDir 'abi.obj'
$command = "`"$devCmd`" -no_logo -arch=$Arch -host_arch=x64 && cl.exe /nologo /W4 /WX /c `"$source`" /Fo`"$object`""

& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0) {
    throw "Windows SDK ABI verification failed for $Arch."
}

Write-Output "Windows SDK ABI verification passed for $Arch."
