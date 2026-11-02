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
    and removes the installed copy. Throws on the first thing that's wrong.
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

try {
    Register-CiTask -OutputPath $share
    $task = Get-ScheduledTask -TaskName $taskName
    if ($task.Principal.UserId -notmatch 'SYSTEM') { throw "The task runs as $($task.Principal.UserId), not SYSTEM." }
    if ("$($task.Principal.RunLevel)" -ne 'Highest') { throw "The task's run level is $($task.Principal.RunLevel), not Highest." }
    if ($task.Actions[0].Arguments -notmatch [regex]::Escape("-Framework `"$frameworks`"")) { throw "Unexpected arguments: $($task.Actions[0].Arguments)" }
    if (-not (Test-Path -LiteralPath (Join-Path $install 'frameworks/cmmc.psd1'))) { throw "The scanner isn't installed in $install." }
    Write-Host "Registered: $($task.Actions[0].Execute) $($task.Actions[0].Arguments)"

    # The data folder is SYSTEM's and Administrators' only, not inherited.
    $acl = Get-Acl -LiteralPath $data
    if (-not $acl.AreAccessRulesProtected) { throw "$data still inherits access from its parent." }
    $who = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    if (($who -join ',') -ne 'S-1-5-18,S-1-5-32-544') { throw "$data grants access to $($who -join ', '), not only SYSTEM and Administrators." }
    if (-not (Test-Path -LiteralPath (Join-Path $data 'Pending') -PathType Container)) { throw "No fallback folder in $data." }
    Write-Host "Data folder $data is limited to SYSTEM and Administrators."

    if ($Run) {
        # A writable share gets one report set per framework, from one run.
        $result = Invoke-CiTask
        if ($result -gt 1) { throw "The scheduled scan exited $result." }
        foreach ($fw in 'cmmc', 'disa-stig-ws2025-ms') {
            if (@(Get-ChildItem -LiteralPath $share -Filter "compliance-scan-*-$fw.csv").Count -ne 1) { throw "No $fw report in $share." }
        }
        $row = Get-LastLogRow
        if ($row.Destination -ne $share) { throw "The run log says the reports went to $($row.Destination)." }

        # A share that can't be written sends the reports to the fallback folder.
        Set-Content -LiteralPath $blocker -Value 'x'
        Register-CiTask -OutputPath (Join-Path $blocker 'share')
        $result = Invoke-CiTask
        if ($result -gt 1) { throw "The scheduled scan with the share away exited $result." }
        $pending = Join-Path $data 'Pending'
        if (@(Get-ChildItem -LiteralPath $pending -Filter 'compliance-scan-*.csv').Count -ne 2) { throw "Expected two waiting CSV reports in $pending." }
        $row = Get-LastLogRow
        if ($row.Destination -ne $pending) { throw "The run log says the reports went to $($row.Destination), not $pending." }
        Write-Host "Share away: the reports waited in $pending, as expected."
    }

    & $shell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'Register-ComplianceScanTask.ps1') -Unregister -RemoveFiles -TaskName $taskName -InstallPath $install
    if ($LASTEXITCODE -ne 0) { throw "Unregistering exited $LASTEXITCODE." }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'The task is still registered.' }
    if (Test-Path -LiteralPath $install) { throw "$install is still there." }
    Write-Host 'Unregistered, and the installed copy removed.'
    exit 0
} catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    exit 1
}
