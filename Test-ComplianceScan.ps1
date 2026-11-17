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

    Every run ends with the summary banner from tools/Write-TestSummary.ps1: one
    row per test file, or with -BothEditions one row per edition. A Pester run
    that throws counts as a failure and the summary still prints.

.PARAMETER BothEditions
    Also run the suite under the other PowerShell edition: powershell.exe (5.1)
    from pwsh, or pwsh from Windows PowerShell. The run fails if that edition
    can't be found. Use it before every commit.

.PARAMETER PackagePath
    A folder holding Pester.6.2.0.nupkg, used if Pester is missing and can't be
    downloaded.

.PARAMETER ResultPath
    Where a run writes its counts as JSON. -BothEditions sets this for each
    edition it runs; you never need to.

.EXAMPLE
    .\Test-ComplianceScan.ps1 -BothEditions
    pwsh -File ./Test-ComplianceScan.ps1          # one edition, any OS
    .\Test-ComplianceScan.ps1 -PackagePath D:\packages   # no internet access
#>

[CmdletBinding()]
param(
    [switch]$BothEditions,
    [string]$PackagePath,
    [string]$ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$version = '6.2.0'
$edition = "PowerShell $($PSVersionTable.PSVersion)"
. (Join-Path $PSScriptRoot 'tools/Write-TestSummary.ps1')

if ($PackagePath) { $PackagePath = (Resolve-Path -LiteralPath $PackagePath).Path }

# Each edition runs in its own process and writes its counts to a temp file, so
# the summary is one table that holds the whole result. A missing edition is a
# failure, not a skip: half a result is the silent pass this suite exists to
# prevent. A run that dies before writing its counts shows '-' and fails on its
# exit code.
if ($BothEditions) {
    $results = foreach ($exe in 'powershell.exe', 'pwsh') {
        Write-Host "`n==== $exe ====" -ForegroundColor Cyan
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
            Write-Host "$exe not found, so this edition can't be tested." -ForegroundColor Red
            [pscustomobject][ordered]@{ Edition = $exe; Version = '-'; Pester = $version; Passed = '-'; Failed = '-'; Skipped = '-'; NotRun = '-'; Result = 'MISSING' }
            continue
        }
        $out = Join-Path ([IO.Path]::GetTempPath()) ("ecs-tests-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        $ver = & $exe -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
        $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-ResultPath', $out)
        if ($PackagePath) { $childArgs += '-PackagePath', $PackagePath }
        & $exe @childArgs | Out-Host
        $code = $LASTEXITCODE
        $r = $null
        if (Test-Path -LiteralPath $out) {
            try { $r = Get-Content -Raw -LiteralPath $out | ConvertFrom-Json }
            catch { Write-Host "Could not read the $exe result file: $($_.Exception.Message)" -ForegroundColor Red }
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        }
        [pscustomobject][ordered]@{
            Edition = $exe
            Version = "$ver"
            Pester  = $version
            Passed  = $(if ($r) { $r.Passed } else { '-' })
            Failed  = $(if ($r) { $r.Failed } else { '-' })
            Skipped = $(if ($r) { $r.Skipped } else { '-' })
            NotRun  = $(if ($r) { $r.NotRun } else { '-' })
            Result  = $(if ($code -eq 0 -and $r) { 'PASS' } elseif ($code -eq 0) { 'FAIL (no counts written)' } elseif ($r) { $r.Result } else { "FAIL (exit $code)" })
        }
    }

    $results = @($results)
    $num = { param($v) if ("$v" -match '^\d+$') { [int]$v } else { 0 } }
    $sumPass = 0; $sumFail = 0; $sumSkip = 0
    foreach ($r in $results) { $sumPass += & $num $r.Passed; $sumFail += & $num $r.Failed; $sumSkip += (& $num $r.Skipped) + (& $num $r.NotRun) }
    # An edition that is missing, died, or skipped tests fails even with no failed tests.
    $bad = @($results | Where-Object { $_.Result -ne 'PASS' }).Count
    if ($bad -gt 0 -and $sumFail -eq 0) { $sumFail = $bad }
    Write-TestSummary -Script 'Test-ComplianceScan.ps1 -BothEditions' -Target "Pester $version, $PSScriptRoot" `
        -Rows $results -Pass $sumPass -Fail $sumFail -Skip $sumSkip
    if ($bad -gt 0) { exit 1 }
    exit 0
}

$result = $null
$stoppedBy = ''
try {
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
} catch {
    # A suite that can't start or throws is a failure, and the summary still prints.
    $stoppedBy = "$($_.Exception.Message)"
    Write-Host "Pester stopped: $stoppedBy" -ForegroundColor Red
}

if ($result) {
    $passed = $result.PassedCount; $failedCount = $result.FailedCount
    $skipped = $result.SkippedCount; $notRun = $result.NotRunCount
    Write-Output ("Pester $version on ${edition}: $passed passed, $failedCount failed, $skipped skipped, $notRun not run.")
} else {
    $passed = 0; $failedCount = 1; $skipped = 0; $notRun = 0
}

# Skipped and not-run tests fail the run: a test that can't apply must say so, not pass.
$ok = -not $stoppedBy -and $failedCount -eq 0 -and $skipped -eq 0 -and $notRun -eq 0 -and $passed -gt 0
$verdict = if ($ok) { 'PASS' }
    elseif ($stoppedBy) { 'FAIL (Pester stopped)' }
    elseif ($failedCount -gt 0) { 'FAIL' }
    elseif ($passed -eq 0) { 'FAIL (no tests ran)' }
    else { 'FAIL (skipped tests)' }

if ($ResultPath) {
    # A -BothEditions child leaves the banner to the parent, which prints one for both.
    [ordered]@{ Passed = $passed; Failed = $failedCount; Skipped = $skipped; NotRun = $notRun; Result = $verdict } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultPath -Encoding utf8
} else {
    # One row per test file, so the table says where a failure is.
    $rows = @()
    if ($result) {
        $rows = @(foreach ($c in @($result.Containers)) {
                $file = "$($c.Item)"
                if ($file.StartsWith($PSScriptRoot)) { $file = $file.Substring($PSScriptRoot.Length).TrimStart('\', '/') -replace '\\', '/' }
                [pscustomobject][ordered]@{
                    File    = $file
                    Passed  = $c.PassedCount
                    Failed  = $c.FailedCount
                    Skipped = $c.SkippedCount
                    NotRun  = $c.NotRunCount
                    Result  = $(if ("$($c.Result)" -eq 'Passed' -and $c.SkippedCount -eq 0 -and $c.NotRunCount -eq 0) { 'PASS' } else { "FAIL ($($c.Result))" })
                }
            })
    }
    if ($stoppedBy) { $rows += [pscustomobject][ordered]@{ File = '(Pester)'; Passed = 0; Failed = 1; Skipped = 0; NotRun = 0; Result = "FAIL: $stoppedBy" } }
    $failCount = $failedCount
    if (-not $ok -and $failCount -eq 0) { $failCount = 1 }
    Write-TestSummary -Script 'Test-ComplianceScan.ps1' -Target "Pester $version on $edition, $PSScriptRoot" `
        -Rows $rows -Pass $passed -Fail $failCount -Skip ($skipped + $notRun)
}

if ($ok) { exit 0 }
exit 1
