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

.PARAMETER BothEditions
    Run the lint under powershell.exe (5.1) AND pwsh (7), each in its own
    process, and print one summary for both. A missing edition is a failure,
    not a skip.

.PARAMETER ResultPath
    Where a run writes its counts as JSON. -BothEditions sets this for each
    edition it runs; you never need to.

.PARAMETER PackagePath
    A folder holding PSScriptAnalyzer.1.25.0.nupkg, used if the analyzer is
    missing and can't be downloaded.

.EXAMPLE
    .\Test-ComplianceScanLint.ps1
    powershell.exe -File .\Test-ComplianceScanLint.ps1      # Windows PowerShell 5.1
    .\Test-ComplianceScanLint.ps1 -BothEditions             # both, one summary table
    .\Test-ComplianceScanLint.ps1 -PackagePath D:\packages  # no internet access

    Every run ends with the summary banner from tools/Write-TestSummary.ps1. A
    lint run that throws counts as a failure and the summary still prints.
#>

[CmdletBinding()]
param(
    [switch]$BothEditions,
    [string]$ResultPath,
    [string]$PackagePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$version = '1.25.0'
$edition = "PowerShell $($PSVersionTable.PSVersion)"
. (Join-Path $PSScriptRoot 'tools/Write-TestSummary.ps1')

if ($BothEditions) {
    $results = foreach ($exe in 'powershell.exe', 'pwsh') {
        Write-Host "`n==== $exe ====" -ForegroundColor Cyan
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
            Write-Host "$exe not found, so this edition can't be linted." -ForegroundColor Red
            [pscustomobject][ordered]@{ Edition = $exe; Version = '-'; Analyzer = $version; Findings = '-'; Blocking = '-'; Result = 'MISSING' }
            continue
        }
        $out = Join-Path ([IO.Path]::GetTempPath()) ("ecs-lint-{0}.json" -f ([guid]::NewGuid().ToString('N')))
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
            Edition  = $exe
            Version  = "$ver"
            Analyzer = $version
            Findings = $(if ($r) { $r.Findings } else { '-' })
            Blocking = $(if ($r) { $r.Blocking } else { '-' })
            Result   = $(if ($code -eq 0 -and $r) { 'PASS' } elseif ($code -eq 0) { 'FAIL (no counts written)' } else { "FAIL (exit $code)" })
        }
    }
    $results = @($results)
    $okRuns = @($results | Where-Object { $_.Result -eq 'PASS' }).Count
    Write-TestSummary -Script 'Test-ComplianceScanLint.ps1 -BothEditions' -Target "PSScriptAnalyzer $version, $PSScriptRoot" `
        -Rows $results -Pass $okRuns -Fail ($results.Count - $okRuns) -Skip 0
    if ($okRuns -ne $results.Count) { exit 1 }
    exit 0
}

$findings = @()
$stoppedBy = ''
try {
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
} catch {
    # An analyzer that can't install or throws is a failure, and the summary still prints.
    $stoppedBy = "$($_.Exception.Message)"
    Write-Host "Lint stopped: $stoppedBy" -ForegroundColor Red
}

$blocking = @($findings | Where-Object { "$($_.Severity)" -in 'Error', 'Warning', 'ParseError' })
$failed = $stoppedBy -or $blocking.Count -gt 0
Write-Output "PSScriptAnalyzer $version on ${edition}: $($findings.Count) finding(s), $($blocking.Count) blocking."
if ($ResultPath) {
    # A -BothEditions child leaves the banner to the parent, which prints one for both.
    if (-not $stoppedBy) {
        [ordered]@{ Findings = $findings.Count; Blocking = $blocking.Count } |
            ConvertTo-Json -Compress | Set-Content -LiteralPath $ResultPath -Encoding utf8
    }
} else {
    # One row per rule that fired, so the table says what to fix.
    $rows = @($findings | Group-Object RuleName, Severity | ForEach-Object {
            [pscustomobject][ordered]@{ Rule = $_.Group[0].RuleName; Severity = "$($_.Group[0].Severity)"; Count = $_.Count
                Blocking = $(if ("$($_.Group[0].Severity)" -in 'Error', 'Warning', 'ParseError') { 'yes' } else { 'no' }) } })
    if ($stoppedBy) {
        $rows = @([pscustomobject][ordered]@{ Edition = $edition; Analyzer = $version; Findings = '-'; Blocking = '-'; Result = "FAIL: $stoppedBy" })
    } elseif ($rows.Count -eq 0) {
        $rows = @([pscustomobject][ordered]@{ Edition = $edition; Analyzer = $version; Findings = 0; Blocking = 0; Result = 'PASS' })
    }
    Write-TestSummary -Script 'Test-ComplianceScanLint.ps1' -Target "PSScriptAnalyzer $version on $edition, $PSScriptRoot" `
        -Rows $rows -Pass $(if ($failed) { 0 } else { 1 }) -Fail $(if ($failed) { 1 } else { 0 }) -Skip 0
}
if ($failed) { exit 1 }
