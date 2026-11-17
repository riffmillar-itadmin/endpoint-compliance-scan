<#
.SYNOPSIS
    Registers the scheduled scan on a CI runner, checks the task, and removes it.

.DESCRIPTION
    Used by the live-scan job of the Tests workflow, on a throwaway Windows
    runner where the job is elevated. Registers the task with
    Register-ComplianceScanTask.ps1 and checks what Task Scheduler holds, and
    that the data folder is limited to SYSTEM and Administrators. With
    -Run it also starts the task twice: once with a writable share, which must
    receive a report per framework, and once with a share that can't be written,
    whose reports must land in the fallback folder. Then it unregisters the task
    and removes the installed copy.

    Each check is a row in the summary banner from tools/Write-TestSummary.ps1.
    The first check that fails stops the ones after it, which are counted as
    skipped; unregistering is still tried. Without -Run the run checks are
    skipped and counted. Exit code 1 if any check failed.
#>

[CmdletBinding()]
param(
    # A scratch folder for the install, data and share folders.
    [Parameter(Mandatory)][string]$WorkPath,
    # Also run the task, to a writable share and to one that can't be written.
    [switch]$Run
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$shell = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$taskName = 'Endpoint compliance scan (CI)'
$install = Join-Path $WorkPath 'install'
$data = Join-Path $WorkPath 'data'
$share = Join-Path $WorkPath 'share'
$blocker = Join-Path $WorkPath 'blocker.txt'
$frameworks = 'CMMC,DISA-STIG-WS2025-MS'
. (Join-Path $repo 'tools/Write-TestSummary.ps1')

function Register-CiTask {
    param([string]$OutputPath)
    & $shell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'Register-ComplianceScanTask.ps1') -Framework $frameworks -OutputPath $OutputPath `
        -RandomDelayMinutes 0 -TaskName $taskName -InstallPath $install -DataPath $data
    if ($LASTEXITCODE -ne 0) { throw "Register-ComplianceScanTask.ps1 exited $LASTEXITCODE." }
}

function Invoke-CiTask {
    # Starts the task and waits for it to finish; returns the scan's exit code.
    $before = (Get-ScheduledTaskInfo -TaskName $taskName).LastRunTime
    Start-ScheduledTask -TaskName $taskName
    $deadline = [datetime]::UtcNow.AddMinutes(12)
    do {
        Start-Sleep -Seconds 10
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        $state = (Get-ScheduledTask -TaskName $taskName).State
    } while (("$state" -eq 'Running' -or $info.LastRunTime -eq $before) -and [datetime]::UtcNow -lt $deadline)
    if ("$state" -eq 'Running') { throw 'The task was still running after 12 minutes.' }
    Write-Host "Task finished with result $($info.LastTaskResult)."
    $info.LastTaskResult
}

function Get-LastLogRow {
    @(Import-Csv -LiteralPath (Join-Path $data 'scan-log.csv'))[-1]
}

# Each check runs in this scope (dot-sourced), so later checks see what earlier
# ones set. A check throws when something is wrong.
$checks = [Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name, [scriptblock]$Body, [switch]$NeedsRun, [switch]$Always)
    $checks.Add([pscustomobject]@{ Name = $Name; Body = $Body; NeedsRun = [bool]$NeedsRun; Always = [bool]$Always })
}

Add-Check 'Register the task, writing to a share' {
    Register-CiTask -OutputPath $share
    $script:task = Get-ScheduledTask -TaskName $taskName
    Write-Host "Registered: $($task.Actions[0].Execute) $($task.Actions[0].Arguments)"
}
Add-Check 'Task runs as SYSTEM at the highest run level' {
    if ($task.Principal.UserId -notmatch 'SYSTEM') { throw "The task runs as $($task.Principal.UserId), not SYSTEM." }
    if ("$($task.Principal.RunLevel)" -ne 'Highest') { throw "The task's run level is $($task.Principal.RunLevel), not Highest." }
}
Add-Check 'Task arguments name the frameworks' {
    if ($task.Actions[0].Arguments -notmatch [regex]::Escape("-Framework `"$frameworks`"")) { throw "Unexpected arguments: $($task.Actions[0].Arguments)" }
}
Add-Check 'Scanner installed with its catalogs' {
    if (-not (Test-Path -LiteralPath (Join-Path $install 'frameworks/cmmc.psd1'))) { throw "The scanner isn't installed in $install." }
}
Add-Check 'Data folder limited to SYSTEM and Administrators' {
    # The data folder is SYSTEM's and Administrators' only, not inherited.
    $acl = Get-Acl -LiteralPath $data
    if (-not $acl.AreAccessRulesProtected) { throw "$data still inherits access from its parent." }
    $who = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    if (($who -join ',') -ne 'S-1-5-18,S-1-5-32-544') { throw "$data grants access to $($who -join ', '), not only SYSTEM and Administrators." }
}
Add-Check 'Fallback folder created' {
    if (-not (Test-Path -LiteralPath (Join-Path $data 'Pending') -PathType Container)) { throw "No fallback folder in $data." }
}
Add-Check 'Run to a writable share: one report per framework' -NeedsRun {
    $result = Invoke-CiTask
    if ($result -gt 1) { throw "The scheduled scan exited $result." }
    foreach ($fw in 'cmmc', 'disa-stig-ws2025-ms') {
        if (@(Get-ChildItem -LiteralPath $share -Filter "compliance-scan-*-$fw.csv").Count -ne 1) { throw "No $fw report in $share." }
    }
}
Add-Check 'Run log names the share' -NeedsRun {
    $row = Get-LastLogRow
    if ($row.Destination -ne $share) { throw "The run log says the reports went to $($row.Destination)." }
}
Add-Check 'Share away: reports wait in the fallback folder' -NeedsRun {
    # A share that can't be written sends the reports to the fallback folder.
    Set-Content -LiteralPath $blocker -Value 'x'
    Register-CiTask -OutputPath (Join-Path $blocker 'share')
    $result = Invoke-CiTask
    if ($result -gt 1) { throw "The scheduled scan with the share away exited $result." }
    if (@(Get-ChildItem -LiteralPath (Join-Path $data 'Pending') -Filter 'compliance-scan-*.csv').Count -ne 2) { throw "Expected two waiting CSV reports in $(Join-Path $data 'Pending')." }
}
Add-Check 'Run log names the fallback folder' -NeedsRun {
    $pending = Join-Path $data 'Pending'
    $row = Get-LastLogRow
    if ($row.Destination -ne $pending) { throw "The run log says the reports went to $($row.Destination), not $pending." }
}
Add-Check 'Unregister and remove the installed copy' -Always {
    & $shell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'Register-ComplianceScanTask.ps1') -Unregister -RemoveFiles -TaskName $taskName -InstallPath $install
    if ($LASTEXITCODE -ne 0) { throw "Unregistering exited $LASTEXITCODE." }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'The task is still registered.' }
    if (Test-Path -LiteralPath $install) { throw "$install is still there." }
}

$rows = [Collections.Generic.List[object]]::new()
$stopped = ''
foreach ($c in $checks) {
    $outcome = 'PASS'; $note = ''
    if ($c.NeedsRun -and -not $Run) {
        $outcome = 'SKIP'; $note = 'needs -Run'
    } elseif ($stopped -and -not $c.Always) {
        $outcome = 'SKIP'; $note = "not run: '$stopped' failed"
    } else {
        Write-Host "`n-- $($c.Name)" -ForegroundColor Cyan
        try {
            . $c.Body
        } catch {
            $outcome = 'FAIL'; $note = "$($_.Exception.Message)"
            Write-Host "FAIL: $note" -ForegroundColor Red
            if (-not $stopped) { $stopped = $c.Name }
        }
    }
    $rows.Add([pscustomobject][ordered]@{ Check = $c.Name; Result = $outcome; Note = $note })
}

$pass = @($rows | Where-Object Result -eq 'PASS').Count
$fail = @($rows | Where-Object Result -eq 'FAIL').Count
$skip = @($rows | Where-Object Result -eq 'SKIP').Count
$label = 'tests/ci/Test-ScheduledScanTask.ps1'
if ($Run) { $label += ' -Run' }
Write-TestSummary -Script $label -Target "Register-ComplianceScanTask.ps1, task '$taskName', $WorkPath" `
    -Rows $rows -Pass $pass -Fail $fail -Skip $skip
if ($fail -gt 0) { exit 1 }
exit 0
