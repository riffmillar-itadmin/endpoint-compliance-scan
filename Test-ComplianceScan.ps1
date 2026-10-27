<#
.SYNOPSIS
    Runs the Pester suite, exactly as CI does.

.DESCRIPTION
    Runs tests\*.Tests.ps1 with Pester, pinned to the version the suite was written
    against. Installs that version for the current user if it is missing.

    -BothEditions runs the suite here and again under the other PowerShell edition
    (powershell.exe 5.1 from pwsh, or pwsh from 5.1). A pass on one edition says
    nothing about the other, so if the other edition can't be found the run fails
    rather than reporting half a result.

    Pester is installed from the PowerShell Gallery, then from nuget.org (checked
    against a pinned SHA-256), then from -PackagePath, whichever works first.

    Exit code 0 only when every test passed and none was skipped. A skipped test
    is counted and fails the run: a test that can't apply must say so, not pass.

.PARAMETER PackagePath
    A folder holding Pester.6.2.0.nupkg, used if Pester is missing and can't be
    downloaded.

.EXAMPLE
    .\Test-ComplianceScan.ps1 -BothEditions
    pwsh -File ./Test-ComplianceScan.ps1          # one edition, any OS
    .\Test-ComplianceScan.ps1 -PackagePath D:\packages   # no internet access
#>

[CmdletBinding()]
param(
    [switch]$BothEditions,
    [string]$PackagePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$version = '6.2.0'
$edition = "PowerShell $($PSVersionTable.PSVersion)"

if ($PackagePath) { $PackagePath = (Resolve-Path -LiteralPath $PackagePath).Path }
if (-not (Get-Module -ListAvailable Pester | Where-Object { "$($_.Version)" -eq $version })) {
    . (Join-Path $PSScriptRoot 'tools/Install-PinnedModule.ps1')
    Install-PinnedModule -Name Pester -Version $version -PackagePath $PackagePath `
        -GalleryParameters @{ SkipPublisherCheck = $true; AllowClobber = $true }
}
Import-Module Pester -RequiredVersion $version

$config = New-PesterConfiguration
$config.Run.Path = Join-Path $PSScriptRoot 'tests'
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Normal'
$result = Invoke-Pester -Configuration $config

$failed = 0
Write-Output ("Pester $version on ${edition}: $($result.PassedCount) passed, $($result.FailedCount) failed, " +
    "$($result.SkippedCount) skipped, $($result.NotRunCount) not run.")
if ($result.FailedCount -gt 0 -or $result.SkippedCount -gt 0 -or $result.NotRunCount -gt 0 -or $result.PassedCount -eq 0) {
    $failed = 1
}

if ($BothEditions) {
    if ($PSVersionTable.PSEdition -eq 'Core') { $other = 'powershell.exe' } else { $other = 'pwsh' }
    if (-not (Get-Command $other -ErrorAction SilentlyContinue)) {
        Write-Output "-BothEditions: $other not found, so the other edition was not tested. Failing the run."
        $failed = 1
    } else {
        $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        if ($PackagePath) { $childArgs += '-PackagePath', $PackagePath }
        & $other @childArgs
        if ($LASTEXITCODE -ne 0) { $failed = 1 }
    }
}

exit $failed
