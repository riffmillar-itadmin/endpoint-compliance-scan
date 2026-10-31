<#
.SYNOPSIS
    Schedules Invoke-EndpointComplianceScan.ps1 to scan this machine and write its
    reports to a shared folder.

.DESCRIPTION
    Copies the scanner, its frameworks folder and the profile files beside it to
    an install folder (by default %ProgramFiles%\EndpointComplianceScan), so the
    task never runs code from a user folder or a share. Then it registers one
    scheduled task that runs the scan as SYSTEM, elevated, so every collector can
    read what it needs. The scan only reads; the task, the installed copy and the
    files under %ProgramData%\EndpointComplianceScan are all this leaves.

    Each run writes to -OutputPath. When that can't be written (the share is down,
    or the machine is off the network), the reports go to a fallback folder,
    %ProgramData%\EndpointComplianceScan\Pending, and the next run that reaches
    the share moves them there, oldest first. Waiting reports older than
    -KeepDays are removed. Each run adds a row to
    %ProgramData%\EndpointComplianceScan\scan-log.csv.

    The task runs as the computer account, so on a share it writes as
    DOMAIN\COMPUTER$. The README gives share permissions that let machines add
    their reports without reading anyone else's.

    Run elevated. Running it again replaces the task and refreshes the installed
    copy. -Unregister removes the task; add -RemoveFiles to remove the installed
    copy too. -WhatIf shows what would change.

.PARAMETER Framework
    One or more frameworks to evaluate, as for the scanner. The machine is
    collected once per run and evaluated against each.

.PARAMETER Level
    The level, as for the scanner. It applies to every framework given; without
    it each framework uses its highest level.

.PARAMETER OutputPath
    The shared folder for the reports, such as \\fileserver\scans.

.PARAMETER StigPath
    The DISA STIG zip or XCCDF file, as for the scanner. It is copied to the
    install folder, since the task can't read a user's folder.

.PARAMETER ProfilePath
    A thresholds file to install as the scanner's ComplianceScan.local.psd1.
    Without it, a ComplianceScan.local.psd1 beside this script is installed if
    there is one.

.PARAMETER Schedule
    Weekly (the default) or Daily.

.PARAMETER At
    The start time, as HH:mm in local time. Defaults to 02:00.

.PARAMETER DaysOfWeek
    The days a weekly task runs. Defaults to Monday.

.PARAMETER RandomDelayMinutes
    Up to this many minutes are added to each start at random, so a fleet doesn't
    reach the share at once. Defaults to 120; 0 turns it off.

.PARAMETER KeepDays
    Days a report may wait in the fallback folder before it's removed. Defaults to 90.

.PARAMETER InstallPath
    Where to install the scanner. Defaults to %ProgramFiles%\EndpointComplianceScan.

.PARAMETER DataPath
    Where the fallback folder and run log live. Defaults to
    %ProgramData%\EndpointComplianceScan.

.PARAMETER TaskName
    The task's name. Defaults to 'Endpoint compliance scan'.

.PARAMETER Unregister
    Remove the task instead of registering it.

.PARAMETER RemoveFiles
    With -Unregister, also remove the installed copy. The fallback folder and run
    log stay, since they may hold reports not yet delivered.

.EXAMPLE
    .\Register-ComplianceScanTask.ps1 -Framework CMMC -OutputPath \\fileserver\scans
    Weekly CMMC scan, Mondays from 02:00 with up to two hours' random delay.

.EXAMPLE
    .\Register-ComplianceScanTask.ps1 -Framework CMMC, DISA-STIG-WS2022-MS -StigPath .\U_MS_Windows_Server_2022_STIG.zip -OutputPath \\fileserver\scans -Schedule Daily -At 22:00
    Daily scan against two frameworks, with STIG Viewer checklists for the STIG.

.EXAMPLE
    .\Register-ComplianceScanTask.ps1 -Unregister -RemoveFiles
    Remove the task and the installed copy.

.NOTES
    Part of endpoint-compliance-scan. Windows PowerShell 5.1 or PowerShell 7 on
    Windows; the task itself runs Windows PowerShell 5.1, which every Windows has.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Register')]
param(
    [Parameter(ParameterSetName = 'Register', Mandatory)][string[]]$Framework,
    [Parameter(ParameterSetName = 'Register')][string]$Level,
    [Parameter(ParameterSetName = 'Register', Mandatory)][string]$OutputPath,
    [Parameter(ParameterSetName = 'Register')][string]$StigPath,
    [Parameter(ParameterSetName = 'Register')][string]$ProfilePath,
    [Parameter(ParameterSetName = 'Register')][ValidateSet('Weekly', 'Daily')][string]$Schedule = 'Weekly',
    [Parameter(ParameterSetName = 'Register')][ValidatePattern('^([01]?\d|2[0-3]):[0-5]\d$')][string]$At = '02:00',
    [Parameter(ParameterSetName = 'Register')][ValidateSet('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')][string[]]$DaysOfWeek = @('Monday'),
    [Parameter(ParameterSetName = 'Register')][ValidateRange(0, 1440)][int]$RandomDelayMinutes = 120,
    [Parameter(ParameterSetName = 'Register')][ValidateRange(1, 3650)][int]$KeepDays = 90,
    [string]$InstallPath,
    [Parameter(ParameterSetName = 'Register')][string]$DataPath,
    [string]$TaskName = 'Endpoint compliance scan',
    [Parameter(ParameterSetName = 'Unregister', Mandatory)][switch]$Unregister,
    [Parameter(ParameterSetName = 'Unregister')][switch]$RemoveFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScannerFile = 'Invoke-EndpointComplianceScan.ps1'

function Get-TaskArgument {
    # The powershell.exe command line for the task. Each value is quoted; a value
    # holding a double quote can't be passed safely, so it's refused. Frameworks
    # go as one comma-separated value, since -File passes an array as one string.
    param([string]$ScriptPath, [string[]]$Framework, [string]$Level, [string]$OutputPath, [string]$FallbackPath,
        [int]$KeepDays, [string]$LogPath, [string]$StigPath)
    $values = [ordered]@{
        Framework    = ($Framework -join ',')
        Level        = $Level
        OutputPath   = $OutputPath
        FallbackPath = $FallbackPath
        KeepDays     = "$KeepDays"
        LogPath      = $LogPath
        StigPath     = $StigPath
    }
    foreach ($v in @($ScriptPath) + @($values.Values)) {
        if ("$v" -match '"') { throw "Can't pass a value holding a double quote to the task: $v" }
    }
    $parts = [Collections.Generic.List[string]]::new()
    foreach ($p in '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"") { $parts.Add($p) }
    foreach ($k in $values.Keys) {
        if ("$($values[$k])") { $parts.Add("-$k"); $parts.Add("`"$($values[$k])`"") }
    }
    $parts -join ' '
}

function Get-ComplianceTaskDefinition {
    # Everything the task is made of, as plain values, so it can be checked
    # without the ScheduledTasks module. Register-ComplianceTask builds the task
    # from it.
    param([string]$InstallPath, [string]$DataPath, [string[]]$Framework, [string]$Level, [string]$OutputPath,
        [string]$StigFile, [string]$Schedule, [string]$At, [string[]]$DaysOfWeek, [int]$RandomDelayMinutes,
        [int]$KeepDays, [string]$TaskName)
    $fallback = Join-Path $DataPath 'Pending'
    $log = Join-Path $DataPath 'scan-log.csv'
    $stig = if ($StigFile) { Join-Path (Join-Path $InstallPath 'stig') $StigFile } else { '' }
    [pscustomobject]@{
        TaskName           = $TaskName
        Description        = "Scans this machine with endpoint-compliance-scan ($($Framework -join ', ')) and writes the reports to $OutputPath. Read-only."
        Execute            = 'powershell.exe'
        Argument           = Get-TaskArgument -ScriptPath (Join-Path $InstallPath $ScannerFile) -Framework $Framework -Level $Level -OutputPath $OutputPath -FallbackPath $fallback -KeepDays $KeepDays -LogPath $log -StigPath $stig
        WorkingDirectory   = $InstallPath
        Schedule           = $Schedule
        At                 = $At
        DaysOfWeek         = @(if ($Schedule -eq 'Weekly') { $DaysOfWeek })
        RandomDelayMinutes = $RandomDelayMinutes
        UserId             = 'SYSTEM'
        RunLevel           = 'Highest'
        ExecutionTimeLimit = [timespan]::FromHours(2)
        StartWhenAvailable = $true
        MultipleInstances  = 'IgnoreNew'
        FallbackPath       = $fallback
        LogPath            = $log
    }
}

function Get-InstallFile {
    # The files to install, as Source and the path under the install folder.
    param([string]$SourceRoot, [string]$ProfilePath, [string]$StigPath)
    $files = [Collections.Generic.List[object]]::new()
    foreach ($name in $ScannerFile, 'ComplianceScan.example.psd1') {
        $files.Add([pscustomobject]@{ Source = Join-Path $SourceRoot $name; Target = $name })
    }
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $SourceRoot 'frameworks') -File -Filter '*.psd1' | Sort-Object Name)) {
        $files.Add([pscustomobject]@{ Source = $f.FullName; Target = Join-Path 'frameworks' $f.Name })
    }
    $profileSource = $ProfilePath
    if (-not $profileSource) {
        $local = Join-Path $SourceRoot 'ComplianceScan.local.psd1'
        if (Test-Path -LiteralPath $local) { $profileSource = $local }
    }
    if ($profileSource) { $files.Add([pscustomobject]@{ Source = $profileSource; Target = 'ComplianceScan.local.psd1' }) }
    if ($StigPath) { $files.Add([pscustomobject]@{ Source = $StigPath; Target = Join-Path 'stig' (Split-Path $StigPath -Leaf) }) }
    foreach ($f in $files) {
        if (-not (Test-Path -LiteralPath $f.Source -PathType Leaf)) { throw "Can't find $($f.Source)." }
    }
    $files.ToArray()
}

function Install-ScannerCopy {
    # Copies the scanner to the install folder. Frameworks no longer shipped are
    # removed, so the installed copy matches the source.
    [CmdletBinding(SupportsShouldProcess)]
    param([object[]]$File, [string]$InstallPath)
    if (-not $PSCmdlet.ShouldProcess($InstallPath, "Install $($File.Count) scanner files")) { return }
    $frameworks = Join-Path $InstallPath 'frameworks'
    if (Test-Path -LiteralPath $frameworks) {
        $keep = @($File | ForEach-Object { Split-Path $_.Target -Leaf })
        Get-ChildItem -LiteralPath $frameworks -File -Filter '*.psd1' | Where-Object { $keep -notcontains $_.Name } | Remove-Item -Force
    }
    foreach ($f in $File) {
        $dest = Join-Path $InstallPath $f.Target
        $parent = Split-Path $dest -Parent
        if (-not (Test-Path -LiteralPath $parent)) { $null = New-Item -ItemType Directory -Path $parent }
        Copy-Item -LiteralPath $f.Source -Destination $dest -Force
    }
}

function Register-ComplianceTask {
    # Builds the task from its definition and registers it, replacing one of the
    # same name.
    [CmdletBinding(SupportsShouldProcess)]
    param($Definition)
    if (-not $PSCmdlet.ShouldProcess($Definition.TaskName, 'Register scheduled task')) { return }
    $action = New-ScheduledTaskAction -Execute $Definition.Execute -Argument $Definition.Argument -WorkingDirectory $Definition.WorkingDirectory
    $time = [datetime]::ParseExact($Definition.At, 'H:mm', [Globalization.CultureInfo]::InvariantCulture)
    $when = @{ At = $time }
    if ($Definition.RandomDelayMinutes -gt 0) { $when.RandomDelay = [timespan]::FromMinutes($Definition.RandomDelayMinutes) }
    $trigger = if ($Definition.Schedule -eq 'Weekly') {
        New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Definition.DaysOfWeek @when
    } else {
        New-ScheduledTaskTrigger -Daily @when
    }
    $principal = New-ScheduledTaskPrincipal -UserId $Definition.UserId -LogonType ServiceAccount -RunLevel $Definition.RunLevel
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit $Definition.ExecutionTimeLimit -MultipleInstances $Definition.MultipleInstances
    $null = Register-ScheduledTask -TaskName $Definition.TaskName -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $Definition.Description -Force
}

function Unregister-ComplianceTask {
    # Removes the task, and with -RemoveFiles the installed copy. The install
    # folder is removed only when it holds the scanner, so a wrong -InstallPath
    # can't delete something else.
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$TaskName, [string]$InstallPath, [switch]$RemoveFiles)
    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($task) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) { Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false }
    } else {
        Write-Host "No scheduled task named '$TaskName'."
    }
    if (-not $RemoveFiles) { return }
    if (-not (Test-Path -LiteralPath $InstallPath)) { Write-Host "Nothing installed at $InstallPath."; return }
    if (-not (Test-Path -LiteralPath (Join-Path $InstallPath $ScannerFile))) {
        throw "$InstallPath doesn't hold $ScannerFile, so it isn't removed."
    }
    if ($PSCmdlet.ShouldProcess($InstallPath, 'Remove installed scanner')) { Remove-Item -LiteralPath $InstallPath -Recurse -Force }
}

function Assert-CanSchedule {
    # Scheduling needs Windows and an elevated session: the copy goes to Program
    # Files and the task runs as SYSTEM.
    param([bool]$OnWindows, [bool]$Elevated)
    if (-not $OnWindows) { throw 'Scheduling a scan needs Windows.' }
    if (-not $Elevated) { throw 'Run this elevated (as Administrator): it installs to Program Files and registers a task that runs as SYSTEM.' }
}

# Dot-sourced (as the tests do): define the functions above and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $onWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    $elevated = $onWindows -and ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Assert-CanSchedule -OnWindows $onWindows -Elevated $elevated
    if (-not $InstallPath) { $InstallPath = Join-Path $env:ProgramFiles 'EndpointComplianceScan' }

    if ($Unregister) {
        Unregister-ComplianceTask -TaskName $TaskName -InstallPath $InstallPath -RemoveFiles:$RemoveFiles
    } else {
        if (-not $DataPath) { $DataPath = Join-Path $env:ProgramData 'EndpointComplianceScan' }
        $names = @($Framework | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        # Check the frameworks and level now, with the scanner's own rules, rather
        # than at 02:00 on Monday. Dot-sourcing the scanner defines its parameters
        # too, several named like this script's, so it happens in a child scope.
        & {
            param([string]$Root, [string[]]$Names, [string]$Wanted)
            . (Join-Path $Root $ScannerFile)
            $catalogs = @(Get-FrameworkCatalog (Join-Path $Root 'frameworks'))
            foreach ($n in $Names) { $null = Resolve-FrameworkLevel (Resolve-Framework $catalogs $n) $Wanted }
        } $PSScriptRoot $names $Level
        if ($names.Count -eq 0) { throw 'Give at least one framework with -Framework.' }
        if ($StigPath) { $StigPath = (Resolve-Path -LiteralPath $StigPath).ProviderPath }
        if ($ProfilePath) { $ProfilePath = (Resolve-Path -LiteralPath $ProfilePath).ProviderPath }
        if ($OutputPath -notmatch '^\\\\') { Write-Warning "$OutputPath isn't a UNC path. The task runs as SYSTEM, which sees local folders and shares but not a user's mapped drives." }

        $files = @(Get-InstallFile -SourceRoot $PSScriptRoot -ProfilePath $ProfilePath -StigPath $StigPath)
        $definition = Get-ComplianceTaskDefinition -InstallPath $InstallPath -DataPath $DataPath -Framework $names -Level $Level -OutputPath $OutputPath `
            -StigFile $(if ($StigPath) { Split-Path $StigPath -Leaf } else { '' }) -Schedule $Schedule -At $At -DaysOfWeek $DaysOfWeek `
            -RandomDelayMinutes $RandomDelayMinutes -KeepDays $KeepDays -TaskName $TaskName
        Install-ScannerCopy -File $files -InstallPath $InstallPath
        Register-ComplianceTask -Definition $definition
        if ($WhatIfPreference) { exit 0 }

        $when = if ($Schedule -eq 'Weekly') { "every $($DaysOfWeek -join ', ') at $At" } else { "daily at $At" }
        if ($RandomDelayMinutes -gt 0) { $when += " (plus up to $RandomDelayMinutes minutes)" }
        Write-Host ''
        Write-Host "Scheduled '$TaskName': $($names -join ', ') $when, as SYSTEM." -ForegroundColor Cyan
        Write-Host "  Scanner    $InstallPath"
        Write-Host "  Reports    $OutputPath"
        Write-Host "  Fallback   $($definition.FallbackPath)"
        Write-Host "  Run log    $($definition.LogPath)"
        Write-Host "To scan now: Start-ScheduledTask -TaskName '$TaskName'"
    }
    $code = 0
} catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    $code = 2
}
exit $code
