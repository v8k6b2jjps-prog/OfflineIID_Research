Clear-Host
Write-Host

$ErrorActionPreference = 'Stop'

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
Set-Location -LiteralPath $ScriptDir

$Project   = Join-Path $ScriptDir 'PkeyApp\PkeyApp.vcxproj'
$Platforms = @('x64', 'Win32', 'ARM64')   # PROJECT platform names (match the .vcxproj)
$Rebuild   = $true                        # $true = clean + build
$Edition   = 'Community'                  # Community | Professional | Enterprise
# ----------------------------------------------------------------------

$msbuild = "${env:ProgramFiles}\Microsoft Visual Studio\2022\$Edition\MSBuild\Current\Bin\MSBuild.exe"
if (-not (Test-Path -LiteralPath $msbuild)) { throw "MSBuild not found - check `$Edition. Looked in: $msbuild" }
if (-not (Test-Path -LiteralPath $Project)) { throw "Project not found: $Project" }


$env:SolutionDir = $ScriptDir.TrimEnd('\') + '\'
$target  = if ($Rebuild) { 'Rebuild' } else { 'Build' }
$results = @()

foreach ($p in $Platforms) {
    Write-Host "`n=== Release | $p ($target) ===" -ForegroundColor Cyan
    & $msbuild $Project `
        /t:$target `
        /p:Configuration=Release `
        /p:Platform=$p `
        /m /nologo /v:minimal
    $ok = ($LASTEXITCODE -eq 0)
    $results += [pscustomobject]@{ Platform = $p; Result = if ($ok) { 'OK' } else { 'FAILED' } }
}

Write-Host "`n--- Summary ---" -ForegroundColor Yellow
$results | Format-Table -AutoSize
if ($results.Result -contains 'FAILED') { exit 1 } else { exit 0 }
