<#
.SYNOPSIS
    Lints the repository with PSScriptAnalyzer, exactly as CI does.

.DESCRIPTION
    Runs PSScriptAnalyzer over every script in the repository with
    PSScriptAnalyzerSettings.psd1. Errors and warnings fail (exit 1); Information
    findings are reported but do not. It also builds the Gallery module
    (tools/Build-Module.ps1) in a temporary folder and lints that, since the
    module's commands are generated.

    Pinned to the analyzer version the settings were tuned against, because a
    newer analyzer can add rules and fail the build with no code change. Installs
    that version for the current user if it is missing: from the PowerShell
    Gallery, then from the analyzer's GitHub release (checked against a pinned
    SHA-256), then from -PackagePath, whichever works first.

    Inside GitHub Actions each finding becomes an annotation on its file and
    line; anywhere else it prints file:line [rule] message.

.PARAMETER PackagePath
    A folder holding PSScriptAnalyzer.1.25.0.nupkg, used if the analyzer is
    missing and can't be downloaded.

.EXAMPLE
    .\Test-ComplianceScanLint.ps1
    powershell.exe -File .\Test-ComplianceScanLint.ps1      # Windows PowerShell 5.1
    .\Test-ComplianceScanLint.ps1 -PackagePath D:\packages  # no internet access
#>

[CmdletBinding()]
param(
    [string]$PackagePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$version = '1.25.0'
$edition = "PowerShell $($PSVersionTable.PSVersion)"

if (-not (Get-Module -ListAvailable PSScriptAnalyzer | Where-Object Version -eq $version)) {
    . (Join-Path $PSScriptRoot 'tools/Install-PinnedModule.ps1')
    Install-PinnedModule -Name PSScriptAnalyzer -Version $version -PackagePath $PackagePath
}
Import-Module PSScriptAnalyzer -RequiredVersion $version

$settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
$findings = @(Invoke-ScriptAnalyzer -Path $PSScriptRoot -Recurse -Settings $settings)

# The Gallery module too, since its commands are generated: built in a temporary
# folder, and its findings named module/<file>.
$moduleOut = Join-Path ([IO.Path]::GetTempPath()) "ecs-lint-$([guid]::NewGuid().ToString('n'))"
try {
    $built = & (Join-Path $PSScriptRoot 'tools/Build-Module.ps1') -OutputPath $moduleOut 6>$null
    $moduleRoot = @($built)[-1].FullName
    $findings += @(Invoke-ScriptAnalyzer -Path $moduleRoot -Recurse -Settings $settings)
} finally {
    if (Test-Path -LiteralPath $moduleOut) { Remove-Item -LiteralPath $moduleOut -Recurse -Force }
}
$inActions = $env:GITHUB_ACTIONS -eq 'true'

Push-Location $PSScriptRoot
try {
    foreach ($f in $findings) {
        # repo-relative with forward slashes, so GitHub links the annotation to the file
        if ($f.ScriptPath.StartsWith($moduleRoot)) {
            $file = 'module/' + ($f.ScriptPath.Substring($moduleRoot.Length).TrimStart('\', '/') -replace '\\', '/')
        } else {
            $file = (Resolve-Path -Relative $f.ScriptPath) -replace '^\.[\\/]', '' -replace '\\', '/'
        }
        if ($inActions) {
            $level = if ("$($f.Severity)" -eq 'Information') { 'notice' } else { 'error' }
            Write-Output "::$level file=$file,line=$($f.Line)::[$($f.RuleName)] $($f.Message)"
        } else {
            Write-Output "$($file):$($f.Line) [$($f.Severity)] [$($f.RuleName)] $($f.Message)"
        }
    }
} finally { Pop-Location }

$blocking = @($findings | Where-Object { "$($_.Severity)" -in 'Error', 'Warning', 'ParseError' })
Write-Output "PSScriptAnalyzer $version on ${edition}: $($findings.Count) finding(s), $($blocking.Count) blocking."
if ($blocking.Count -gt 0) { exit 1 }
