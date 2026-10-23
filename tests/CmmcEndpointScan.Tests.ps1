# Pester tests for Invoke-CmmcEndpointScan.ps1. No network, no elevation, no
# Windows needed: every check is fed a fixture snapshot, never the machine.
#
# Run through ..\Test-CmmcScan.ps1, which pins the Pester version and can run
# both PowerShell editions.

BeforeDiscovery {
    # Test cases are built from the script's own registry target list.
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-CmmcEndpointScan.ps1')
}

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:ScriptPath = Join-Path $Root 'Invoke-CmmcEndpointScan.ps1'
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures/compliant.json'
    . $ScriptPath

    $script:Catalog = Import-PowerShellDataFile -LiteralPath (Join-Path $Root 'CmmcControls.psd1')
    $script:ExamplePath = Join-Path $Root 'CmmcScan.example.psd1'

    function Get-Fixture { Read-Snapshot $FixturePath }
    function Get-Threshold { Get-ScanThreshold -ExamplePath $ExamplePath }

    function Write-RegFact {
        # Sets a registry fact; $null makes the value absent.
        param($Snapshot, [string]$Key, $Value)
        $f = $Snapshot.Registry.$Key
        if ($null -eq $f) { throw "Fixture has no registry entry '$Key'." }
        $f.Present = $null -ne $Value
        $f.Value = $Value
    }

    function Get-CheckState {
        param($Snapshot, [string]$Check, $Thresholds = (Get-Threshold))
        $table = Get-CheckTable
        Invoke-Check -Name $Check -Definition $table[$Check] -Snapshot $Snapshot -Thresholds $Thresholds
    }

    function Invoke-Evaluation {
        param($Snapshot, $Thresholds = (Get-Threshold), [int]$Level = 2)
        Invoke-CmmcEvaluation -Snapshot $Snapshot -Thresholds $Thresholds -Catalog $Catalog -Level $Level
    }

    $script:Sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $script:TsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $script:Lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
}

Describe 'Control catalog' {
    It 'lists all 110 NIST SP 800-171 Rev 2 requirements exactly once' {
        $ids = @($Catalog.Requirements | ForEach-Object { $_.Id })
        $ids.Count | Should -Be 110
        @($ids | Select-Object -Unique).Count | Should -Be 110
    }

    It 'has the right number of requirements in each family' {
        $expected = @{ AC = 22; AT = 3; AU = 9; CM = 9; IA = 11; IR = 3; MA = 6; MP = 9; PS = 2; PE = 6; RA = 3; CA = 4; SC = 16; SI = 7 }
        foreach ($fam in $expected.Keys) {
            @($Catalog.Requirements | Where-Object Family -eq $fam).Count | Should -Be $expected[$fam] -Because "family $fam"
        }
    }

    It 'numbers each family under its own 800-171 section' {
        $section = @{ AC = '3.1'; AT = '3.2'; AU = '3.3'; CM = '3.4'; IA = '3.5'; IR = '3.6'; MA = '3.7'; MP = '3.8'; PS = '3.9'; PE = '3.10'; RA = '3.11'; CA = '3.12'; SC = '3.13'; SI = '3.14' }
        foreach ($r in $Catalog.Requirements) {
            $r.Id | Should -Match ('^' + [regex]::Escape($section[$r.Family]) + '\.\d+$')
        }
    }

    It 'flags exactly the 17 Level 1 requirements' {
        $l1 = @($Catalog.Requirements | Where-Object Level -eq 1 | ForEach-Object { $_.Id }) | Sort-Object
        $want = @('3.1.1', '3.1.2', '3.1.20', '3.1.22', '3.5.1', '3.5.2', '3.8.3', '3.10.1', '3.10.3',
            '3.10.4', '3.10.5', '3.13.1', '3.13.5', '3.14.1', '3.14.2', '3.14.4', '3.14.5') | Sort-Object
        $l1 | Should -Be $want
    }

    It 'names only checks that exist' {
        $known = @((Get-CheckTable).Keys)
        foreach ($r in $Catalog.Requirements) {
            foreach ($c in @($r.Checks)) { $known | Should -Contain $c -Because "requirement $($r.Id)" }
        }
    }

    It 'uses every check for at least one requirement' {
        $used = @($Catalog.Requirements | ForEach-Object { @($_.Checks) }) | Select-Object -Unique
        foreach ($c in (Get-CheckTable).Keys) { $used | Should -Contain $c }
    }

    It 'gives every manual requirement a note on the evidence to look for' {
        foreach ($r in @($Catalog.Requirements | Where-Object { @($_.Checks).Count -eq 0 })) {
            $r.Note | Should -Not -BeNullOrEmpty -Because "requirement $($r.Id) has no checks"
        }
    }
}

Describe 'Compliant snapshot' {
    BeforeAll {
        $script:Eval = Invoke-Evaluation (Get-Fixture)
    }

    It 'passes every check' {
        $notPass = @($Eval.Checks | Where-Object State -ne 'Pass' | ForEach-Object { "$($_.Check)=$($_.State): $($_.Evidence)" })
        $notPass | Should -BeNullOrEmpty
        @($Eval.Checks).Count | Should -Be @((Get-CheckTable).Keys).Count
    }

    It 'reports every requirement as Pass or Manual' {
        @($Eval.Requirements).Count | Should -Be 110
        @($Eval.Requirements | Where-Object { $_.State -notin 'Pass', 'Manual' }) | Should -BeNullOrEmpty
    }

    It 'exits 0' {
        Get-ScanExitCode $Eval.Requirements | Should -Be 0
    }

    It 'limits a Level 1 scan to the 17 Level 1 requirements' {
        $l1 = Invoke-Evaluation (Get-Fixture) -Level 1
        @($l1.Requirements).Count | Should -Be 17
    }

    It 'builds CMMC practice IDs from family, level and requirement' {
        ($Eval.Requirements | Where-Object Requirement -eq '3.1.1').Practice | Should -Be 'AC.L1-3.1.1'
        ($Eval.Requirements | Where-Object Requirement -eq '3.1.8').Practice | Should -Be 'AC.L2-3.1.8'
    }
}

Describe 'Each check fails on a bad setting' {
    It '<Check> fails when <Case>' -ForEach @(
        @{ Check = 'AC-GuestDisabled'; Case = 'Guest is enabled'; Mutate = { param($s) ($s.LocalAccounts.Users | Where-Object Name -eq 'Guest').Enabled = $true } }
        @{ Check = 'AC-NoPasswordNotRequired'; Case = 'an enabled account needs no password'; Mutate = { param($s) ($s.LocalAccounts.Users | Where-Object Name -eq 'DefaultAccount').Enabled = $true } }
        @{ Check = 'AC-UacEnabled'; Case = 'EnableLUA is 0'; Mutate = { param($s) Write-RegFact $s "$Sys\EnableLUA" 0 } }
        @{ Check = 'AC-UacSecureDesktop'; Case = 'PromptOnSecureDesktop is 0'; Mutate = { param($s) Write-RegFact $s "$Sys\PromptOnSecureDesktop" 0 } }
        @{ Check = 'AC-LocalAdminCount'; Case = 'there are three admins'; Mutate = { param($s) $s.LocalAccounts.Administrators += 'WESTMARK-PC01\extra' } }
        @{ Check = 'AC-AccountLockout'; Case = 'the threshold is 0'; Mutate = { param($s) $s.SecurityPolicy.LockoutBadCount = 0 } }
        @{ Check = 'AC-AccountLockout'; Case = 'the threshold is 50'; Mutate = { param($s) $s.SecurityPolicy.LockoutBadCount = 50 } }
        @{ Check = 'AC-AccountLockout'; Case = 'the duration is 5 minutes'; Mutate = { param($s) $s.SecurityPolicy.LockoutDuration = 5 } }
        @{ Check = 'AC-LogonBanner'; Case = 'the caption is missing'; Mutate = { param($s) Write-RegFact $s "$Sys\LegalNoticeCaption" $null } }
        @{ Check = 'AC-LogonBanner'; Case = 'the text is blank'; Mutate = { param($s) Write-RegFact $s "$Sys\LegalNoticeText" '  ' } }
        @{ Check = 'AC-InactivityLock'; Case = 'no limit is set'; Mutate = { param($s) Write-RegFact $s "$Sys\InactivityTimeoutSecs" $null } }
        @{ Check = 'AC-InactivityLock'; Case = 'the limit is 30 minutes'; Mutate = { param($s) Write-RegFact $s "$Sys\InactivityTimeoutSecs" 1800 } }
        @{ Check = 'AC-RdpProtected'; Case = 'RDP is on without NLA'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication' 0 } }
        @{ Check = 'AC-RdpProtected'; Case = 'policy turns NLA off'; Mutate = { param($s) Write-RegFact $s "$TsPol\UserAuthentication" 0 } }
        @{ Check = 'AC-RdpIdleTimeout'; Case = 'RDP has no idle limit'; Mutate = { param($s) Write-RegFact $s "$TsPol\MaxIdleTime" $null } }
        @{ Check = 'AC-RdpIdleTimeout'; Case = 'the idle limit is an hour'; Mutate = { param($s) Write-RegFact $s "$TsPol\MaxIdleTime" 3600000 } }
        @{ Check = 'AU-AuditPolicy'; Case = 'Logon audits success only'; Mutate = { param($s) $s.AuditPolicy.'{0CCE9215-69AE-11D9-BED3-505054503030}' = 1 } }
        @{ Check = 'AU-AuditPolicy'; Case = 'a subcategory is missing from the export'; Mutate = { param($s) $s.AuditPolicy.PSObject.Properties.Remove('{0CCE922B-69AE-11D9-BED3-505054503030}') } }
        @{ Check = 'AU-SensitivePrivilegeUse'; Case = 'it is not audited'; Mutate = { param($s) $s.AuditPolicy.'{0CCE9228-69AE-11D9-BED3-505054503030}' = 0 } }
        @{ Check = 'AU-SecurityLogSize'; Case = 'the log is the 20 MB default'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize' $null } }
        @{ Check = 'AU-TimeSync'; Case = 'the sync type is NoSync'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type' 'NoSync' } }
        @{ Check = 'AU-TimeSync'; Case = 'Windows Time is disabled'; Mutate = { param($s) $s.Services.W32Time.StartType = 'Disabled' } }
        @{ Check = 'CM-Smb1Disabled'; Case = 'the SMBv1 client driver is on'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start' 2 } }
        @{ Check = 'CM-Smb1Disabled'; Case = 'the SMBv1 server is on'; Mutate = { param($s) $s.Smb.ServerEnabled = $true } }
        @{ Check = 'CM-Smb1Disabled'; Case = 'the registry turns the SMBv1 server on'; Mutate = { param($s) $s.Smb.ServerEnabled = $null; Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1' 1 } }
        @{ Check = 'CM-NonessentialServices'; Case = 'Remote Registry is Manual'; Mutate = { param($s) $s.Services.RemoteRegistry.StartType = 'Manual' } }
        @{ Check = 'CM-AlwaysInstallElevated'; Case = 'the machine policy is 1'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' 1 } }
        @{ Check = 'IA-PasswordComplexity'; Case = 'the minimum length is 8'; Mutate = { param($s) $s.SecurityPolicy.MinimumPasswordLength = 8 } }
        @{ Check = 'IA-PasswordComplexity'; Case = 'complexity is off'; Mutate = { param($s) $s.SecurityPolicy.PasswordComplexity = 0 } }
        @{ Check = 'IA-PasswordHistory'; Case = 'history is 5'; Mutate = { param($s) $s.SecurityPolicy.PasswordHistorySize = 5 } }
        @{ Check = 'IA-StoredPasswordProtection'; Case = 'LM hashes are stored'; Mutate = { param($s) Write-RegFact $s "$Lsa\NoLMHash" 0 } }
        @{ Check = 'IA-StoredPasswordProtection'; Case = 'reversible encryption is on'; Mutate = { param($s) $s.SecurityPolicy.ClearTextPassword = 1 } }
        @{ Check = 'IA-NtlmV2Only'; Case = 'the level is the Windows default 3'; Mutate = { param($s) Write-RegFact $s "$Lsa\LmCompatibilityLevel" $null } }
        @{ Check = 'MP-RemovableStorage'; Case = 'no removable storage policy is set'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\Deny_Write' $null } }
        @{ Check = 'SC-FirewallEnabled'; Case = 'the Public profile is off'; Mutate = { param($s) ($s.Firewall | Where-Object Name -eq 'Public').Enabled = 'False' } }
        @{ Check = 'SC-FirewallEnabled'; Case = 'Private allows inbound'; Mutate = { param($s) ($s.Firewall | Where-Object Name -eq 'Private').DefaultInboundAction = 'Allow' } }
        @{ Check = 'SC-LegacyTlsDisabled'; Case = 'TLS 1.0 server is unset'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled' $null } }
        @{ Check = 'SC-LegacyTlsDisabled'; Case = 'TLS 1.1 client is on'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\Enabled' 1 } }
        @{ Check = 'SC-FipsMode'; Case = 'FIPS mode is off'; Mutate = { param($s) Write-RegFact $s "$Lsa\FipsAlgorithmPolicy\Enabled" 0 } }
        @{ Check = 'SC-BitLocker'; Case = 'protection is off'; Mutate = { param($s) $s.BitLocker.ProtectionStatus = 'Off' } }
        @{ Check = 'SI-UpdateRecency'; Case = 'the newest update is 80 days old'; Mutate = { param($s) $s.Hotfix.LatestInstalledOn = '2026-08-01T00:00:00Z' } }
        @{ Check = 'SI-UpdateRecency'; Case = 'no update has an install date'; Mutate = { param($s) $s.Hotfix.LatestInstalledOn = $null } }
        @{ Check = 'SI-AntivirusActive'; Case = 'Defender real-time is off and nothing else is registered'; Mutate = { param($s) $s.Defender.RealTimeProtectionEnabled = $false } }
        @{ Check = 'SI-SignatureAge'; Case = 'signatures are 19 days old'; Mutate = { param($s) $s.Defender.AntivirusSignatureLastUpdated = '2026-10-01T00:00:00Z' } }
        @{ Check = 'SI-ScanRecency'; Case = 'the last scan was 16 days ago'; Mutate = { param($s) $s.Defender.QuickScanEndTime = '2026-10-01T00:00:00Z' } }
    ) {
        $s = Get-Fixture
        & $Mutate $s
        $r = Get-CheckState $s $Check
        $r.State | Should -Be 'Fail' -Because $r.Evidence
    }
}

Describe 'States other than Pass and Fail' {
    It 'treats RDP idle limits as not applicable when RDP is off' {
        $s = Get-Fixture
        Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections' 1
        (Get-CheckState $s 'AC-RdpIdleTimeout').State | Should -Be 'NotApplicable'
        (Get-CheckState $s 'AC-RdpProtected').State | Should -Be 'Pass'
    }

    It 'rolls a requirement whose only check is not applicable up to NotApplicable, not Pass' {
        $s = Get-Fixture
        Write-RegFact $s "$TsPol\fDenyTSConnections" 1
        $e = Invoke-Evaluation $s
        ($e.Requirements | Where-Object Requirement -eq '3.1.11').State | Should -Be 'NotApplicable'
    }

    It 'accepts a lockout that lasts until an administrator unlocks it' {
        $s = Get-Fixture
        $s.SecurityPolicy.LockoutDuration = -1
        (Get-CheckState $s 'AC-AccountLockout').State | Should -Be 'Pass'
    }

    It 'uses the documented Windows default for an unset value and says so' {
        $s = Get-Fixture
        Write-RegFact $s "$Sys\EnableLUA" $null
        $r = Get-CheckState $s 'AC-UacEnabled'
        $r.State | Should -Be 'Pass'
        $r.Evidence | Should -Match 'Windows default'
    }

    It 'credits third-party antivirus reported to Security Center' {
        $s = Get-Fixture
        $s.Defender.RealTimeProtectionEnabled = $false
        $s.SecurityCenter = @([pscustomobject]@{ DisplayName = 'Contoso Antivirus'; ProductState = 0x41000 })
        (Get-CheckState $s 'SI-AntivirusActive').State | Should -Be 'Pass'
        (Get-CheckState $s 'SI-SignatureAge').State | Should -Be 'Pass'
        (Get-CheckState $s 'SI-ScanRecency').State | Should -Be 'Manual'
    }

    It 'fails third-party antivirus that reports stale signatures' {
        $s = Get-Fixture
        $s.Defender.RealTimeProtectionEnabled = $false
        $s.SecurityCenter = @([pscustomobject]@{ DisplayName = 'Contoso Antivirus'; ProductState = 0x41010 })
        (Get-CheckState $s 'SI-SignatureAge').State | Should -Be 'Fail'
    }

    It 'checks antivirus from Security Center alone when Defender is not collected' {
        $s = Get-Fixture
        $s.Collection.Defender.Status = 'Error'
        $s.Collection.Defender.Reason = 'service not running'
        $s.Defender = $null
        $s.SecurityCenter = @([pscustomobject]@{ DisplayName = 'Contoso Antivirus'; ProductState = 0x41000 })
        (Get-CheckState $s 'SI-AntivirusActive').State | Should -Be 'Pass'
    }

    It 'reports FIPS mode as Manual when the profile turns it off' {
        $t = Get-Threshold
        $t.RequireFipsMode = $false
        $s = Get-Fixture
        Write-RegFact $s "$Lsa\FipsAlgorithmPolicy\Enabled" 0
        (Get-CheckState $s 'SC-FipsMode' $t).State | Should -Be 'Manual'
    }

    It 'reports removable media as Manual when the profile turns it off' {
        $t = Get-Threshold
        $t.RequireRemovableMediaPolicy = $false
        (Get-CheckState (Get-Fixture) 'MP-RemovableStorage' $t).State | Should -Be 'Manual'
    }

    It 'skips SMBv1 when the server state is unknown' {
        $s = Get-Fixture
        $s.Smb.ServerEnabled = $null
        Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1' $null
        (Get-CheckState $s 'CM-Smb1Disabled').State | Should -Be 'Skipped'
    }

    It 'skips the Security log size when its key is not readable' {
        $s = Get-Fixture
        Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize' $null
        $f = $s.Registry.'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize'
        $f.Present = $false
        $f.Denied = $true
        (Get-CheckState $s 'AU-SecurityLogSize').State | Should -Be 'Skipped'
    }
}

Describe 'No silent passes' {
    It 'skips, never passes, the checks a non-elevated run cannot collect' {
        $s = Get-Fixture
        foreach ($sec in 'SecurityPolicy', 'AuditPolicy', 'BitLocker') {
            $s.Collection.$sec.Status = 'Skipped'
            $s.Collection.$sec.Reason = 'Needs an elevated session.'
            $s.$sec = $null
        }
        $e = Invoke-Evaluation $s
        $skipped = @($e.Checks | Where-Object State -eq 'Skipped' | ForEach-Object { $_.Check }) | Sort-Object
        $skipped | Should -Be (@('AC-AccountLockout', 'AU-AuditPolicy', 'AU-SensitivePrivilegeUse', 'IA-PasswordComplexity',
                'IA-PasswordHistory', 'IA-StoredPasswordProtection', 'SC-BitLocker') | Sort-Object)
        ($e.Requirements | Where-Object Requirement -eq '3.1.8').State | Should -Be 'Skipped'
        ($e.Requirements | Where-Object Requirement -eq '3.1.7').State | Should -Be 'Skipped'
        Get-ScanExitCode $e.Requirements | Should -Be 0
    }

    It 'errors every check that reads a section whose collector failed' {
        $s = Get-Fixture
        $s.Collection.Registry.Status = 'Error'
        $s.Collection.Registry.Reason = 'test'
        $e = Invoke-Evaluation $s
        ($e.Checks | Where-Object Check -eq 'AC-UacEnabled').State | Should -Be 'Error'
        Get-ScanExitCode $e.Requirements | Should -Be 2
    }

    It 'errors a check whose section has no collection record' {
        $s = Get-Fixture
        $s.Collection.PSObject.Properties.Remove('Firewall')
        (Get-CheckState $s 'SC-FirewallEnabled').State | Should -Be 'Error'
    }

    It 'errors a check when registry value <Key> is missing from the snapshot' -ForEach @(
        Get-RegistryTarget | ForEach-Object { @{ Key = $_ } }
    ) {
        $s = Get-Fixture
        $s.Registry.PSObject.Properties.Remove($Key)
        $e = Invoke-Evaluation $s
        $errors = @($e.Checks | Where-Object { $_.State -eq 'Error' -and $_.Evidence -like "*$Key*" })
        $errors.Count | Should -BeGreaterThan 0 -Because 'a missing fact must surface as an Error'
        @($e.Checks | Where-Object State -eq 'Pass').Count | Should -BeLessThan @($e.Checks).Count
    }

    It 'collects every registry value the fixture holds, and no other' {
        $fixtureKeys = @((Get-Fixture).Registry.PSObject.Properties.Name) | Sort-Object
        $fixtureKeys | Should -Be (@(Get-RegistryTarget) | Sort-Object)
    }

    It 'errors a check that names an unknown audit setting' {
        $t = Get-Threshold
        $t.AuditSubcategories = @(@{ Name = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Setting = 'Sometimes' })
        (Get-CheckState (Get-Fixture) 'AU-AuditPolicy' $t).State | Should -Be 'Error'
    }

    It 'errors a check that needs a missing service record' {
        $s = Get-Fixture
        $s.Services.PSObject.Properties.Remove('SNMP')
        (Get-CheckState $s 'CM-NonessentialServices').State | Should -Be 'Error'
    }

    It 'errors rather than passes when no local accounts were returned' {
        $s = Get-Fixture
        $s.LocalAccounts.Users = @()
        (Get-CheckState $s 'AC-NoPasswordNotRequired').State | Should -Be 'Error'
    }

    It 'refuses a catalog entry that names an unknown check' {
        $bad = @{ Requirements = @(@{ Id = '3.1.1'; Family = 'AC'; Level = 1; Title = 't'; Checks = @('AC-Nope') }) }
        { Invoke-CmmcEvaluation -Snapshot (Get-Fixture) -Thresholds (Get-Threshold) -Catalog $bad } | Should -Throw '*unknown check*'
    }

    It 'refuses a snapshot with another schema version' {
        $path = Join-Path $TestDrive 'old.json'
        $s = Get-Fixture
        $s.SchemaVersion = 99
        $s | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        { Read-Snapshot $path } | Should -Throw '*schema version*'
    }
}

Describe 'Exit codes' {
    It 'gives <Want> for <States>' -ForEach @(
        @{ States = @('Pass', 'Manual'); Want = 0 }
        @{ States = @('Pass', 'Skipped', 'NotApplicable'); Want = 0 }
        @{ States = @('Pass', 'Fail'); Want = 1 }
        @{ States = @('Fail', 'Error'); Want = 2 }
        @{ States = @('Error'); Want = 2 }
    ) {
        Get-ScanExitCode @($States | ForEach-Object { [pscustomobject]@{ State = $_ } }) | Should -Be $Want
    }
}

Describe 'Thresholds' {
    It 'lets a profile override a known key' {
        $path = Join-Path $TestDrive 'p.psd1'
        Set-Content -LiteralPath $path -Value '@{ MinPasswordLength = 16 }'
        (Get-ScanThreshold -ExamplePath $ExamplePath -OverridePath $path).MinPasswordLength | Should -Be 16
    }

    It 'ignores an unknown key with a warning' {
        $path = Join-Path $TestDrive 'q.psd1'
        Set-Content -LiteralPath $path -Value '@{ MinPaswordLength = 16 }'
        $t = Get-ScanThreshold -ExamplePath $ExamplePath -OverridePath $path -WarningVariable w -WarningAction SilentlyContinue
        $t.ContainsKey('MinPaswordLength') | Should -BeFalse
        "$w" | Should -Match 'Unknown threshold'
    }
}

Describe 'Running the script on a saved snapshot' {
    BeforeAll {
        $script:Exe = (Get-Process -Id $PID).Path
    }

    It 'exits 0 and writes one CSV row per requirement for the compliant fixture' {
        $out = Join-Path $TestDrive 'ok'
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -FromSnapshot $FixturePath -OutputPath $out
        $LASTEXITCODE | Should -Be 0
        $csv = @(Get-ChildItem -LiteralPath $out -Filter '*.csv')
        $csv.Count | Should -Be 1
        @(Import-Csv -LiteralPath $csv[0].FullName).Count | Should -Be 110
        $json = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $out -Filter '*.json')[0].FullName -Raw | ConvertFrom-Json
        $json.Summary.Fail | Should -Be 0
        $json.PSObject.Properties.Name | Should -Not -Contain 'Snapshot'
    }

    It 'exits 1 when a check fails' {
        $s = Get-Fixture
        $s.BitLocker.ProtectionStatus = 'Off'
        $path = Join-Path $TestDrive 'fail.json'
        $s | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -FromSnapshot $path -OutputPath (Join-Path $TestDrive 'fail')
        $LASTEXITCODE | Should -Be 1
    }

    It 'exits 2 when the snapshot cannot be read' {
        # The script writes its error to stderr. Under the Stop preference the
        # dot-sourced script sets, Windows PowerShell 5.1 turns a native command's
        # stderr into a terminating error, so relax it for this call.
        $ErrorActionPreference = 'Continue'
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -FromSnapshot (Join-Path $TestDrive 'missing.json') -OutputPath (Join-Path $TestDrive 'err') 2>&1
        $LASTEXITCODE | Should -Be 2
    }
}
