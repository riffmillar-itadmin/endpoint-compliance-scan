<#
.SYNOPSIS
    The closing summary every test script, lint run and CI check prints.

.DESCRIPTION
    Dot-sourced by Test-ComplianceScan.ps1, Test-ComplianceScanLint.ps1 and
    tests/ci/Test-ScheduledScanTask.ps1. Write-TestSummary prints, after two
    blank lines:

      a full-width '#' banner with the script name, status and Pass/Fail/Skip
      counts; the target, run time and PowerShell version; the table; and a
      RESULT bar that matches the banner.

    The bars are green when everything passed, dark yellow when something was
    skipped, and red when anything failed, so the result is findable at a glance
    and the block between the bars copies cleanly. The format is the one the
    JobSweep repository uses, so every repository's results read the same way.
#>

function Get-TestStatus {
    <# PASS, PASS WITH SKIPS or FAIL from the counts. Any failure wins. #>
    param([int]$Fail, [int]$Skip)
    if ($Fail -gt 0) { return 'FAIL' }
    if ($Skip -gt 0) { return 'PASS WITH SKIPS' }
    return 'PASS'
}

function Write-TestSummary {
    <# Prints the summary block. -PassThru also returns its lines, for a caller
       that writes them to a file, and for the tests. #>
    param(
        [Parameter(Mandatory)][string] $Script,
        [string]   $Target = '',
        [object[]] $Rows = @(),
        [int]      $Pass,
        [int]      $Fail,
        [int]      $Skip,
        [switch]   $PassThru
    )
    $status = Get-TestStatus -Fail $Fail -Skip $Skip
    $color  = switch ($status) { 'FAIL' { 'Red' } 'PASS WITH SKIPS' { 'DarkYellow' } default { 'Green' } }
    $width  = 100
    try { $width = [Math]::Max(60, [Math]::Min(160, $Host.UI.RawUI.WindowSize.Width - 1)) }
    catch { Write-Verbose "console width unknown, using $width" }
    $bar    = '#' * $width
    $counts = "Pass $Pass  Fail $Fail  Skip $Skip"
    $table  = ''
    if (@($Rows).Count -gt 0) { $table = (@($Rows) | Format-Table -AutoSize -Wrap | Out-String -Width 400).Trim() }
    $lines = @('', '', $bar, "##  $Script  |  $status  |  $counts", $bar)
    if ($Target) { $lines += "Target:  $Target" }
    $lines += "Run:     $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    $lines += "PS:      $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    if ($table) { $lines += ''; $lines += $table }
    $lines += @('', $bar, "##  RESULT: $status  ($counts)", $bar)
    foreach ($l in $lines) {
        if ($l -like '##*') { Write-Host $l -ForegroundColor $color } else { Write-Host $l }
    }
    if ($PassThru) { return $lines }
}
