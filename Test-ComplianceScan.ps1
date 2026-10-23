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

    Exit code 0 only when every test passed and none was skipped. A skipped test
    is counted and fails the run: a test that can't apply must say so, not pass.

.EXAMPLE
    .\Test-ComplianceScan.ps1 -BothEditions
    pwsh -File ./Test-ComplianceScan.ps1          # one edition, any OS
#>

[CmdletBinding()]
param(
    [switch]$BothEditions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$version = '6.2.0'
$edition = "PowerShell $($PSVersionTable.PSVersion)"

if (-not (Get-Module -ListAvailable Pester | Where-Object { "$($_.Version)" -eq $version })) {
    # Windows PowerShell 5.1 needs TLS 1.2 and the NuGet provider for the Gallery.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($PSVersionTable.PSEdition -ne 'Core' -and -not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
    }
    Install-Module Pester -RequiredVersion $version -Scope CurrentUser -Force -SkipPublisherCheck -AllowClobber
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
        & $other -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        if ($LASTEXITCODE -ne 0) { $failed = 1 }
    }
}

exit $failed
