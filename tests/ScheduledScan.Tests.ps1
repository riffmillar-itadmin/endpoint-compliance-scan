# Pester tests for scheduled scans: Register-ComplianceScanTask.ps1, and the
# scanner's several frameworks per run, fallback folder and run log. The
# ScheduledTasks cmdlets are mocked, so nothing is registered and no Windows is
# needed. The live-scan CI job registers and runs a real task on the runner.
#
# Run through ..\Test-ComplianceScan.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:ScriptPath = Join-Path $Root 'Invoke-EndpointComplianceScan.ps1'
    $script:RegisterPath = Join-Path $Root 'Register-ComplianceScanTask.ps1'
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures/compliant.json'
    $script:Exe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    . $ScriptPath
    # The Unregister parameter set has no mandatory values, so dot-sourcing
    # with it defines the functions without prompting.
    . $RegisterPath -Unregister

    # Linux and macOS have no ScheduledTasks module. Stand-ins with the
    # parameters the scripts use let Pester mock the cmdlets everywhere; on
    # Windows the real ones are mocked instead. Register-ScheduledTask keeps the
    # real cmdlet's CIM type checks, so a mock that doesn't remove them fails
    # here too. The bodies read $PSBoundParameters only so lint counts the
    # parameters as used.
    $standIns = @{
        'New-ScheduledTaskAction'      = { param($Execute, $Argument, $WorkingDirectory) $null = $PSBoundParameters }
        'New-ScheduledTaskTrigger'     = { param([switch]$Weekly, [switch]$Daily, $DaysOfWeek, $At, $RandomDelay) $null = $PSBoundParameters }
        'New-ScheduledTaskPrincipal'   = { param($UserId, $LogonType, $RunLevel) $null = $PSBoundParameters }
        'New-ScheduledTaskSettingsSet' = { param([switch]$StartWhenAvailable, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, $ExecutionTimeLimit, $MultipleInstances) $null = $PSBoundParameters }
        'Register-ScheduledTask'       = {
            param($TaskName, $TaskPath,
                [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction')][object[]]$Action,
                [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')][object[]]$Trigger,
                [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskPrincipal2')][object]$Principal,
                [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings3')][object]$Settings,
                $Description, [switch]$Force)
            $null = $PSBoundParameters
        }
        'Get-ScheduledTask'            = { [CmdletBinding()] param($TaskName, $TaskPath) $null = $PSBoundParameters }
        'Unregister-ScheduledTask'     = { [CmdletBinding(SupportsShouldProcess)] param($TaskName, $TaskPath) $null = $PSBoundParameters }
    }
    foreach ($name in $standIns.Keys) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            $null = New-Item -Path "Function:\global:$name" -Value $standIns[$name]
        }
    }

    function Get-TestFolder {
        # A new, empty folder under TestDrive.
        $p = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $p
        $p
    }

    function Get-UnwritableFolder {
        # A folder path that can't be created on any OS: its parent is a file.
        $file = Join-Path (Get-TestFolder) 'blocker.txt'
        Set-Content -LiteralPath $file -Value 'x'
        Join-Path $file 'share'
    }

    function Add-PendingFile {
        # A file in the fallback folder, last written the given days ago.
        param([string]$Folder, [string]$Name, [double]$DaysAgo)
        $path = Join-Path $Folder $Name
        Set-Content -LiteralPath $path -Value $Name
        (Get-Item -LiteralPath $path).LastWriteTimeUtc = [datetime]::UtcNow.AddDays(-$DaysAgo)
        $path
    }

    function Split-TaskArgument {
        # The task's command line as Windows hands it to powershell.exe: quoted
        # values are one argument, without their quotes.
        param([string]$Argument)
        @([regex]::Matches($Argument, '"([^"]*)"|(\S+)') | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } })
    }
}

Describe 'Several frameworks per run' {
    It 'splits commas, trims, and drops duplicates ignoring case, keeping the order' {
        Split-FrameworkList 'CMMC,HIPAA' | Should -Be @('CMMC', 'HIPAA')
        Split-FrameworkList @('cmmc', ' NIST-800-171r3 , CMMC', '') | Should -Be @('cmmc', 'NIST-800-171r3')
        @(Split-FrameworkList @()).Count | Should -Be 0
    }

    It 'evaluates one snapshot against each framework, through -File, and exits with the worst result' {
        $s = Read-Snapshot $FixturePath
        $s.BitLocker.ProtectionStatus = 'Off'
        $path = Join-Path (Get-TestFolder) 'fail.json'
        $s | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        $out = Get-TestFolder
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework 'CMMC,PCI-DSS-4.0.1' -FromSnapshot $path -OutputPath $out
        $LASTEXITCODE | Should -Be 1
        @(Get-ChildItem -LiteralPath $out -Filter '*-cmmc.csv').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $out -Filter '*-pci-dss-4.0.1.csv').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $out -Filter '*.html').Count | Should -Be 2
    }

    It 'applies -Level to each framework, and refuses one the framework lacks before writing anything' {
        $out = Join-Path (Get-TestFolder) 'out'
        $ErrorActionPreference = 'Continue'
        $output = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework 'CMMC,NIST-800-53r5' -Level L1 -FromSnapshot $FixturePath -OutputPath $out 2>&1
        $LASTEXITCODE | Should -Be 2
        "$output" | Should -Match 'NIST-800-53r5'
        Test-Path -LiteralPath $out | Should -BeFalse
    }

    It 'refuses a STIG file that matches no framework in the list, before writing anything' {
        $out = Join-Path (Get-TestFolder) 'out'
        $ErrorActionPreference = 'Continue'
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework 'CMMC,DISA-STIG-Win11' -FromSnapshot $FixturePath -OutputPath $out -StigPath (Join-Path $PSScriptRoot 'fixtures/stig-sample-xccdf.xml') 2>&1
        $LASTEXITCODE | Should -Be 2
        Test-Path -LiteralPath $out | Should -BeFalse
    }
}

Describe 'Fallback folder' {
    It 'creates a missing folder and reports it writable' {
        $p = Join-Path (Get-TestFolder) 'new/deeper'
        Test-FolderWritable $p | Should -BeTrue
        Test-Path -LiteralPath $p -PathType Container | Should -BeTrue
        @(Get-ChildItem -LiteralPath $p -Force).Count | Should -Be 0
    }

    It 'reports a folder that cannot be created as not writable' {
        Test-FolderWritable (Get-UnwritableFolder) | Should -BeFalse
    }

    It 'uses -OutputPath when it can be written' {
        $out = Get-TestFolder
        $t = Resolve-ReportFolder -OutputPath $out -FallbackPath (Get-TestFolder)
        $t.Destination | Should -Be 'Output'
        $t.Folder | Should -Be $out
    }

    It 'falls back, and says why, when -OutputPath cannot be written' {
        $bad = Get-UnwritableFolder
        $fallback = Join-Path (Get-TestFolder) 'Pending'
        $t = Resolve-ReportFolder -OutputPath $bad -FallbackPath $fallback
        $t.Destination | Should -Be 'Fallback'
        $t.Folder | Should -Be $fallback
        $t.Reason | Should -BeLike "*Can't write to $bad*next run*"
    }

    It 'stops when neither folder can be written, or there is no fallback' {
        { Resolve-ReportFolder -OutputPath (Get-UnwritableFolder) -FallbackPath '' } | Should -Throw '*give -FallbackPath*'
        { Resolve-ReportFolder -OutputPath (Get-UnwritableFolder) -FallbackPath (Get-UnwritableFolder) } | Should -Throw '*or to the fallback folder*'
    }

    It 'lists waiting reports oldest first, and only scan reports' {
        $f = Get-TestFolder
        $null = Add-PendingFile $f 'compliance-scan-b.json' 1
        $null = Add-PendingFile $f 'compliance-scan-a.json' 3
        $null = Add-PendingFile $f 'notes.txt' 5
        @(Get-PendingReport $f | ForEach-Object Name) | Should -Be @('compliance-scan-a.json', 'compliance-scan-b.json')
        @(Get-PendingReport (Join-Path $f 'missing')).Count | Should -Be 0
    }

    It 'moves every waiting report to -OutputPath and replaces one of the same name' {
        $f = Get-TestFolder
        $out = Get-TestFolder
        $null = Add-PendingFile $f 'compliance-scan-a.json' 3
        $null = Add-PendingFile $f 'compliance-scan-b.json' 1
        Set-Content -LiteralPath (Join-Path $out 'compliance-scan-b.json') -Value 'old'
        $sent = Send-PendingReport -FallbackPath $f -OutputPath $out
        $sent.Delivered | Should -Be 2
        $sent.Remaining | Should -Be 0
        $sent.Problem | Should -BeNullOrEmpty
        (Get-Content -LiteralPath (Join-Path $out 'compliance-scan-b.json')) | Should -Be 'compliance-scan-b.json'
        @(Get-PendingReport $f).Count | Should -Be 0
    }

    It 'keeps the waiting reports, and says where it stopped, when they cannot be moved' {
        $f = Get-TestFolder
        $null = Add-PendingFile $f 'compliance-scan-a.json' 3
        $null = Add-PendingFile $f 'compliance-scan-b.json' 1
        $sent = Send-PendingReport -FallbackPath $f -OutputPath (Get-UnwritableFolder)
        $sent.Delivered | Should -Be 0
        $sent.Remaining | Should -Be 2
        $sent.Problem | Should -BeLike '*compliance-scan-a.json*'
        @(Get-PendingReport $f).Count | Should -Be 2
    }

    It 'removes only waiting reports older than KeepDays' {
        $f = Get-TestFolder
        $null = Add-PendingFile $f 'compliance-scan-old.json' 100
        $null = Add-PendingFile $f 'compliance-scan-new.json' 10
        $null = Add-PendingFile $f 'other-old.txt' 100
        Remove-StalePendingReport -FallbackPath $f -KeepDays 90 -Now ([datetime]::UtcNow) | Should -Be @('compliance-scan-old.json')
        @(Get-ChildItem -LiteralPath $f | ForEach-Object Name | Sort-Object) | Should -Be @('compliance-scan-new.json', 'other-old.txt')
    }

    It 'removes nothing under -WhatIf' {
        $f = Get-TestFolder
        $null = Add-PendingFile $f 'compliance-scan-old.json' 100
        @(Remove-StalePendingReport -FallbackPath $f -KeepDays 90 -Now ([datetime]::UtcNow) -WhatIf).Count | Should -Be 0
        Test-Path -LiteralPath (Join-Path $f 'compliance-scan-old.json') | Should -BeTrue
    }
}

Describe 'Run log' {
    It 'creates the log and its folder, then appends a row per run' {
        $log = Join-Path (Get-TestFolder) 'logs/scan-log.csv'
        $now = [datetime]::new(2026, 10, 29, 9, 0, 0, [DateTimeKind]::Utc)
        Write-ScanLog -LogPath $log -Row ([ordered]@{ Computer = 'WESTMARK-PC01'; ExitCode = 0 }) -Now $now
        Write-ScanLog -LogPath $log -Row ([ordered]@{ Computer = 'WESTMARK-PC01'; ExitCode = 1 }) -Now $now.AddDays(7)
        $rows = @(Import-Csv -LiteralPath $log)
        $rows.Count | Should -Be 2
        $rows[0].TimeUtc | Should -Be '2026-10-29T09:00:00Z'
        $rows[1].ExitCode | Should -Be '1'
        @($rows[0].PSObject.Properties.Name) | Should -Be @('TimeUtc', 'Computer', 'ExitCode')
    }

    It 'keeps commas and quotes in a value' {
        $log = Join-Path (Get-TestFolder) 'scan-log.csv'
        Write-ScanLog -LogPath $log -Row ([ordered]@{ Message = 'Can''t read "x", or y' }) -Now ([datetime]::UtcNow)
        @(Import-Csv -LiteralPath $log)[0].Message | Should -Be 'Can''t read "x", or y'
    }

    It 'drops rows older than a year' {
        $log = Join-Path (Get-TestFolder) 'scan-log.csv'
        $now = [datetime]::new(2026, 10, 29, 9, 0, 0, [DateTimeKind]::Utc)
        Write-ScanLog -LogPath $log -Row ([ordered]@{ ExitCode = 0 }) -Now $now.AddDays(-400)
        Write-ScanLog -LogPath $log -Row ([ordered]@{ ExitCode = 0 }) -Now $now.AddDays(-30)
        Write-ScanLog -LogPath $log -Row ([ordered]@{ ExitCode = 0 }) -Now $now
        @(Import-Csv -LiteralPath $log | ForEach-Object TimeUtc) | Should -Be @('2026-09-29T09:00:00Z', '2026-10-29T09:00:00Z')
    }
}

Describe 'A scheduled-style run' {
    It 'writes to the fallback folder when the share is away, logs it, then delivers on the next run' {
        $bad = Get-UnwritableFolder
        $fallback = Join-Path (Get-TestFolder) 'Pending'
        $log = Join-Path (Get-TestFolder) 'scan-log.csv'
        $ErrorActionPreference = 'Continue'
        $output = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework 'CMMC,HIPAA' -FromSnapshot $FixturePath -OutputPath $bad -FallbackPath $fallback -LogPath $log 2>&1
        $LASTEXITCODE | Should -Be 0
        "$output" | Should -Match 'next run'
        @(Get-ChildItem -LiteralPath $fallback -Filter '*.csv').Count | Should -Be 2
        $row = @(Import-Csv -LiteralPath $log)[-1]
        $row.Frameworks | Should -Be 'CMMC;HIPAA'
        $row.ExitCode | Should -Be '0'
        $row.Destination | Should -Be $fallback
        [int]$row.Pending | Should -Be @(Get-ChildItem -LiteralPath $fallback).Count

        $share = Get-TestFolder
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework CMMC -FromSnapshot $FixturePath -OutputPath $share -FallbackPath $fallback -LogPath $log 2>&1
        $LASTEXITCODE | Should -Be 0
        @(Get-ChildItem -LiteralPath $fallback).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $share -Filter '*-hipaa.csv').Count | Should -Be 1
        $row = @(Import-Csv -LiteralPath $log)[-1]
        $row.Destination | Should -Be $share
        [int]$row.Delivered | Should -BeGreaterThan 0
        $row.Pending | Should -Be '0'
    }

    It 'exits 2 when the share is away and there is no fallback folder' {
        $ErrorActionPreference = 'Continue'
        $output = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework CMMC -FromSnapshot $FixturePath -OutputPath (Get-UnwritableFolder) 2>&1
        $LASTEXITCODE | Should -Be 2
        "$output" | Should -Match 'FallbackPath'
    }

    It 'logs a run that could not start, with its reason' {
        $log = Join-Path (Get-TestFolder) 'scan-log.csv'
        $ErrorActionPreference = 'Continue'
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework CMMC -FromSnapshot (Join-Path $TestDrive 'missing.json') -OutputPath (Get-TestFolder) -LogPath $log 2>&1
        $LASTEXITCODE | Should -Be 2
        $row = @(Import-Csv -LiteralPath $log)[-1]
        $row.ExitCode | Should -Be '2'
        $row.Message | Should -Not -BeNullOrEmpty
    }
}

Describe 'The task definition' {
    BeforeAll {
        $script:Install = Join-Path $TestDrive 'Program Files/EndpointComplianceScan'
        $script:Data = Join-Path $TestDrive 'ProgramData/EndpointComplianceScan'
        function Get-Definition {
            param([string]$Schedule = 'Weekly', [int]$Delay = 120, [string]$Stig = '', [string]$Level = '')
            Get-ComplianceTaskDefinition -InstallPath $Install -DataPath $Data -Framework @('CMMC', 'HIPAA') -Level $Level -OutputPath '\\fileserver\scans' `
                -StigFile $Stig -Schedule $Schedule -At '02:00' -DaysOfWeek @('Monday') -RandomDelayMinutes $Delay -KeepDays 90 -TaskName 'Endpoint compliance scan'
        }
    }

    It 'runs Windows PowerShell as SYSTEM, elevated, for at most two hours, one run at a time' {
        $d = Get-Definition
        $d.Execute | Should -Be 'powershell.exe'
        $d.UserId | Should -Be 'SYSTEM'
        $d.RunLevel | Should -Be 'Highest'
        $d.ExecutionTimeLimit | Should -Be ([timespan]::FromHours(2))
        $d.StartWhenAvailable | Should -BeTrue
        $d.MultipleInstances | Should -Be 'IgnoreNew'
        $d.WorkingDirectory | Should -Be $Install
        $d.Description | Should -BeLike '*CMMC, HIPAA*\\fileserver\scans*Read-only*'
    }

    It 'passes the installed scanner the frameworks as one value, the share, the fallback folder and the log' {
        $a = Split-TaskArgument (Get-Definition).Argument
        $a[0..5] | Should -Be @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Install 'Invoke-EndpointComplianceScan.ps1'))
        $pairs = @{}
        for ($i = 6; $i -lt $a.Count; $i += 2) { $pairs[$a[$i]] = $a[$i + 1] }
        $pairs['-Framework'] | Should -Be 'CMMC,HIPAA'
        $pairs['-OutputPath'] | Should -Be '\\fileserver\scans'
        $pairs['-FallbackPath'] | Should -Be (Join-Path $Data 'Pending')
        $pairs['-LogPath'] | Should -Be (Join-Path $Data 'scan-log.csv')
        $pairs['-KeepDays'] | Should -Be '90'
        $pairs.Keys | Should -Not -Contain '-Level'
        $pairs.Keys | Should -Not -Contain '-StigPath'
    }

    It 'passes -Level and the installed STIG file when given' {
        $a = Split-TaskArgument (Get-Definition -Level L2 -Stig 'U_STIG.zip').Argument
        $a[[array]::IndexOf($a, '-Level') + 1] | Should -Be 'L2'
        $a[[array]::IndexOf($a, '-StigPath') + 1] | Should -Be (Join-Path (Join-Path $Install 'stig') 'U_STIG.zip')
    }

    It 'refuses a value holding a double quote' {
        { Get-TaskArgument -ScriptPath 'x.ps1' -Framework 'CMMC' -OutputPath '\\server\"share' -KeepDays 90 } | Should -Throw '*double quote*'
    }

    It 'keeps the days only for a weekly task' {
        (Get-Definition).DaysOfWeek | Should -Be @('Monday')
        @((Get-Definition -Schedule Daily).DaysOfWeek).Count | Should -Be 0
    }

    It 'gives the installed scanner arguments it runs with' {
        $install = Get-TestFolder
        Install-ScannerCopy -File (Get-InstallFile -SourceRoot $Root) -InstallPath $install
        $data = Get-TestFolder
        $share = Get-TestFolder
        $d = Get-ComplianceTaskDefinition -InstallPath $install -DataPath $data -Framework @('CMMC', 'HIPAA') -OutputPath $share -Schedule Weekly -At '02:00' `
            -DaysOfWeek @('Monday') -RandomDelayMinutes 0 -KeepDays 90 -TaskName 'x'
        $null = & $Exe @(Split-TaskArgument $d.Argument) -FromSnapshot $FixturePath
        $LASTEXITCODE | Should -Be 0
        @(Get-ChildItem -LiteralPath $share -Filter '*.csv' | ForEach-Object { $_.Name -replace '^.*-(cmmc|hipaa)\.csv$', '$1' } | Sort-Object) | Should -Be @('cmmc', 'hipaa')
        @(Import-Csv -LiteralPath $d.LogPath).Count | Should -Be 1
    }
}

Describe 'Installing the scanner' {
    It 'lists the scanner, the example profile and every framework, and stops on a missing file' {
        $files = @(Get-InstallFile -SourceRoot $Root)
        $files.Target | Should -Contain 'Invoke-EndpointComplianceScan.ps1'
        $files.Target | Should -Contain 'ComplianceScan.example.psd1'
        @($files | Where-Object { $_.Target -like 'frameworks*' }).Count | Should -Be @(Get-ChildItem -LiteralPath (Join-Path $Root 'frameworks') -Filter '*.psd1').Count
        $files.Target | Should -Not -Contain 'Register-ComplianceScanTask.ps1'
        { Get-InstallFile -SourceRoot $Root -StigPath (Join-Path $TestDrive 'missing.zip') } | Should -Throw "*Can't find*missing.zip*"
    }

    It 'installs a profile as the local profile, and the STIG file under stig' {
        $profileFile = Join-Path (Get-TestFolder) 'site.psd1'
        Set-Content -LiteralPath $profileFile -Value '@{}'
        $files = @(Get-InstallFile -SourceRoot $Root -ProfilePath $profileFile -StigPath (Join-Path $PSScriptRoot 'fixtures/stig-sample-xccdf.xml'))
        @($files | Where-Object Target -eq 'ComplianceScan.local.psd1').Source | Should -Be $profileFile
        $files.Target | Should -Contain (Join-Path 'stig' 'stig-sample-xccdf.xml')
    }

    It 'copies the files, and removes a framework no longer shipped' {
        $install = Get-TestFolder
        $null = New-Item -ItemType Directory -Path (Join-Path $install 'frameworks')
        Set-Content -LiteralPath (Join-Path $install 'frameworks/retired.psd1') -Value '@{}'
        Install-ScannerCopy -File (Get-InstallFile -SourceRoot $Root) -InstallPath $install
        Test-Path -LiteralPath (Join-Path $install 'Invoke-EndpointComplianceScan.ps1') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $install 'frameworks/retired.psd1') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $install 'frameworks/cmmc.psd1') | Should -BeTrue
    }

    It 'copies nothing under -WhatIf' {
        $install = Join-Path (Get-TestFolder) 'EndpointComplianceScan'
        Install-ScannerCopy -File (Get-InstallFile -SourceRoot $Root) -InstallPath $install -WhatIf
        Test-Path -LiteralPath $install | Should -BeFalse
    }
}

Describe 'Registering and removing the task' {
    BeforeAll {
        $script:Def = Get-ComplianceTaskDefinition -InstallPath (Join-Path $TestDrive 'Install') -DataPath (Join-Path $TestDrive 'Data') `
            -Framework @('CMMC') -OutputPath '\\fileserver\scans' -Schedule Weekly -At '02:00' -DaysOfWeek @('Monday', 'Thursday') -RandomDelayMinutes 120 -KeepDays 90 -TaskName 'Endpoint compliance scan'
    }

    BeforeEach {
        Mock New-ScheduledTaskAction { 'action' }
        Mock New-ScheduledTaskTrigger { 'trigger' }
        Mock New-ScheduledTaskPrincipal { 'principal' }
        Mock New-ScheduledTaskSettingsSet { 'settings' }
        # The real cmdlet only takes the CIM objects the New-* cmdlets return;
        # the mocks above return strings, so the mock drops that type check.
        Mock Register-ScheduledTask { } -RemoveParameterType Action, Trigger, Principal, Settings
    }

    It 'registers the task from its definition, replacing one of the same name' {
        Register-ComplianceTask -Definition $Def
        Should -Invoke New-ScheduledTaskAction -Times 1 -Exactly -ParameterFilter { $Execute -eq 'powershell.exe' -and $Argument -eq $Def.Argument -and $WorkingDirectory -eq $Def.WorkingDirectory }
        Should -Invoke New-ScheduledTaskTrigger -Times 1 -Exactly -ParameterFilter {
            $Weekly -and "$DaysOfWeek" -eq 'Monday Thursday' -and $At.Hour -eq 2 -and $At.Minute -eq 0 -and $RandomDelay -eq [timespan]::FromMinutes(120)
        }
        Should -Invoke New-ScheduledTaskPrincipal -Times 1 -Exactly -ParameterFilter { $UserId -eq 'SYSTEM' -and "$LogonType" -eq 'ServiceAccount' -and "$RunLevel" -eq 'Highest' }
        Should -Invoke New-ScheduledTaskSettingsSet -Times 1 -Exactly -ParameterFilter {
            $StartWhenAvailable -and $AllowStartIfOnBatteries -and $DontStopIfGoingOnBatteries -and $ExecutionTimeLimit -eq [timespan]::FromHours(2) -and "$MultipleInstances" -eq 'IgnoreNew'
        }
        Should -Invoke Register-ScheduledTask -Times 1 -Exactly -ParameterFilter {
            $TaskName -eq 'Endpoint compliance scan' -and $TaskPath -eq '\' -and $Force -and $Action -eq 'action' -and $Trigger -eq 'trigger' -and $Principal -eq 'principal' -and $Settings -eq 'settings'
        }
    }

    It 'builds a daily trigger with no random delay when it is 0' {
        $daily = Get-ComplianceTaskDefinition -InstallPath (Join-Path $TestDrive 'x') -DataPath (Join-Path $TestDrive 'y') -Framework @('CMMC') -OutputPath '\\s\x' -Schedule Daily -At '22:30' `
            -DaysOfWeek @('Monday') -RandomDelayMinutes 0 -KeepDays 90 -TaskName 't'
        Register-ComplianceTask -Definition $daily
        Should -Invoke New-ScheduledTaskTrigger -Times 1 -Exactly -ParameterFilter { $Daily -and -not $Weekly -and $At.Hour -eq 22 -and $At.Minute -eq 30 -and -not $PSBoundParameters.ContainsKey('RandomDelay') }
    }

    It 'registers nothing under -WhatIf' {
        Register-ComplianceTask -Definition $Def -WhatIf
        Should -Invoke Register-ScheduledTask -Times 0 -Exactly
    }

    It 'unregisters the task, keeping the files unless -RemoveFiles' {
        $install = Get-TestFolder
        Set-Content -LiteralPath (Join-Path $install 'Invoke-EndpointComplianceScan.ps1') -Value '#'
        Mock Get-ScheduledTask { 'task' }
        Mock Unregister-ScheduledTask { }
        Unregister-ComplianceTask -TaskName 'Endpoint compliance scan' -InstallPath $install
        Should -Invoke Unregister-ScheduledTask -Times 1 -Exactly -ParameterFilter { $TaskName -eq 'Endpoint compliance scan' -and $TaskPath -eq '\' }
        Test-Path -LiteralPath $install | Should -BeTrue
        Unregister-ComplianceTask -TaskName 'Endpoint compliance scan' -InstallPath $install -RemoveFiles
        Test-Path -LiteralPath $install | Should -BeFalse
    }

    It 'says so when there is no task, and removes nothing under -WhatIf' {
        $install = Get-TestFolder
        Set-Content -LiteralPath (Join-Path $install 'Invoke-EndpointComplianceScan.ps1') -Value '#'
        Mock Get-ScheduledTask { }
        Mock Unregister-ScheduledTask { }
        Mock Write-Host { }
        Unregister-ComplianceTask -TaskName 'Endpoint compliance scan' -InstallPath $install -RemoveFiles -WhatIf
        Should -Invoke Unregister-ScheduledTask -Times 0 -Exactly
        Should -Invoke Write-Host -ParameterFilter { "$Object" -like "No scheduled task named*" }
        Test-Path -LiteralPath $install | Should -BeTrue
    }

    It 'refuses to remove a folder that does not hold the scanner' {
        $other = Get-TestFolder
        Set-Content -LiteralPath (Join-Path $other 'keep.txt') -Value 'x'
        Mock Get-ScheduledTask { }
        Mock Write-Host { }
        { Unregister-ComplianceTask -TaskName 't' -InstallPath $other -RemoveFiles } | Should -Throw "*doesn't hold*"
        Test-Path -LiteralPath (Join-Path $other 'keep.txt') | Should -BeTrue
    }

    It 'needs Windows and an elevated session' {
        { Assert-CanSchedule -OnWindows $false -Elevated $true } | Should -Throw '*needs Windows*'
        { Assert-CanSchedule -OnWindows $true -Elevated $false } | Should -Throw '*elevated*'
        { Assert-CanSchedule -OnWindows $true -Elevated $true } | Should -Not -Throw
    }
}
