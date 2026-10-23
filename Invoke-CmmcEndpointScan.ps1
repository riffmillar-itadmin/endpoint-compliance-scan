<#
.SYNOPSIS
    Scans the local Windows endpoint for evidence against NIST SP 800-171 Rev 2,
    the requirements CMMC Level 1 and Level 2 are assessed against.

.DESCRIPTION
    Read-only. The scan changes no setting, writes nothing to the registry and makes
    no network call. Its only side effects are two temporary files (the secedit and
    auditpol exports), deleted as soon as they are read, and the report files.

    It works in two stages so that every pass/fail rule can be tested anywhere:
        1. Collect: gather raw facts about the machine into a snapshot.
        2. Evaluate: judge the snapshot against each check's threshold.

    Each check supplies evidence for one or more requirements in CmmcControls.psd1.
    A requirement's result is the worst of its checks' results:
        Fail           evidence collected and it misses the threshold
        Error          a collector or check threw; the message is in the report
        Skipped        the check applies but could not run (usually: not elevated)
        Manual         the endpoint cannot show this; the note says what can
        Pass           evidence collected and it meets the threshold
        NotApplicable  the thing checked is absent (for example, RDP is off)
    Nothing passes by default. A fact missing from the snapshot is an Error, never
    a Pass.

    This is evidence for an assessment, not a verdict. Most of the 110 requirements
    are procedural or need evidence from outside the endpoint, so the report never
    states that a machine is compliant and never computes an SPRS score.

    Writes two files per run into -OutputPath:
        cmmc-scan-<computer>-<timestamp>.csv   one row per requirement
        cmmc-scan-<computer>-<timestamp>.json  requirements, checks and thresholds

    Exit codes: 0 no Fail and no Error; 1 at least one Fail; 2 at least one Error,
    or the scan could not start. Error wins over Fail because a run with errors
    can't be relied on either way.

.PARAMETER Level
    1 assesses the 17 Level 1 requirements; 2 (the default) assesses all 110.

.PARAMETER OutputPath
    Folder for the report files. Defaults to a Reports folder beside this script.

.PARAMETER ProfilePath
    Thresholds file to use on top of CmmcScan.example.psd1. Without it, a
    CmmcScan.local.psd1 beside the script is used if present.

.PARAMETER SnapshotPath
    Also save the collected snapshot to this JSON file, for review elsewhere or as
    a test fixture. The snapshot holds the computer name and local account names.

.PARAMETER FromSnapshot
    Evaluate a saved snapshot instead of scanning this machine. Works on any
    operating system.

.PARAMETER IncludeSnapshot
    Embed the snapshot in the JSON report.

.PARAMETER PassThru
    Also write the requirement results to the pipeline.

.EXAMPLE
    .\Invoke-CmmcEndpointScan.ps1
    Full Level 2 scan. Run elevated, or the checks that need elevation are Skipped.

.EXAMPLE
    .\Invoke-CmmcEndpointScan.ps1 -Level 1 -SnapshotPath .\pc01.json
    Level 1 only, and keep the raw snapshot.

.EXAMPLE
    pwsh -File ./Invoke-CmmcEndpointScan.ps1 -FromSnapshot ./pc01.json
    Re-evaluate a saved snapshot, for example after changing a threshold.

.NOTES
    Version notes
    0.1.0  2026-10-23  First draft: catalog of all 110 requirements, 30 endpoint
                       checks, CSV and JSON reports.
#>

[CmdletBinding()]
param(
    [ValidateSet(1, 2)]
    [int]$Level = 2,
    [string]$OutputPath,
    [string]$ProfilePath,
    [string]$SnapshotPath,
    [string]$FromSnapshot,
    [switch]$IncludeSnapshot,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$CmmcScanVersion = '0.1.0'
$SnapshotSchemaVersion = 1

# Worst first. A requirement takes the worst state among its checks.
$StateRank = @{ Fail = 0; Error = 1; Skipped = 2; Manual = 3; Pass = 4; NotApplicable = 5 }

#region Helpers

function Get-Prop {
    # Reads a property from a PSCustomObject (a snapshot read from JSON) or a
    # dictionary (one being built). Returns $null when it is absent.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return $null -ne $Object.PSObject.Properties[$Name]
}

function ConvertTo-DateValue {
    # Snapshot dates are ISO 8601 UTC strings. PowerShell 7's ConvertFrom-Json turns
    # them into [datetime] already; 5.1 leaves them as strings. Accept both.
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}

function ConvertTo-IsoDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    return ([datetime]$Value).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-SnapshotAge {
    # Age relative to when the snapshot was collected, not to now, so a saved
    # snapshot evaluates the same tomorrow as today.
    param($Snapshot, [datetime]$Date)
    $collected = ConvertTo-DateValue (Get-Prop (Get-Prop $Snapshot 'Meta') 'CollectedUtc')
    if ($null -eq $collected) { throw 'Snapshot has no Meta.CollectedUtc.' }
    return [math]::Round(($collected - $Date.ToUniversalTime()).TotalDays, 1)
}

function New-CheckResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Builds an object in memory; changes no system state.')]
    param(
        [ValidateSet('Pass', 'Fail', 'Error', 'Skipped', 'Manual', 'NotApplicable')]
        [string]$State,
        [string]$Evidence,
        [string]$Note = ''
    )
    [pscustomobject]@{ State = $State; Evidence = $Evidence; Note = $Note }
}

function Get-RegFact {
    # A registry value as collected: Present, Value, Denied. Throws when the value
    # was never collected, so a gap in the snapshot is an Error, not a Pass.
    param($Snapshot, [string]$Key)
    $reg = Get-Prop $Snapshot 'Registry'
    if (-not (Test-Prop $reg $Key)) { throw "Registry value '$Key' was not collected." }
    return Get-Prop $reg $Key
}

function Get-RegSetting {
    # The value Windows acts on: the first present key in -Keys (policy before
    # local), else -Default. Source says which, for the evidence text.
    param($Snapshot, [string[]]$Keys, $Default = $null)
    # Fetch every key first, so a gap in the snapshot errors even when an
    # earlier key would have decided the answer.
    $facts = @(foreach ($k in $Keys) { [pscustomobject]@{ Key = $k; Fact = (Get-RegFact $Snapshot $k) } })
    foreach ($entry in $facts) {
        $k = $entry.Key
        $f = $entry.Fact
        if (Get-Prop $f 'Denied') { throw "Registry value '$k' was not readable (run elevated)." }
        if (Get-Prop $f 'Present') {
            return [pscustomobject]@{ Value = (Get-Prop $f 'Value'); Source = 'set'; Key = $k }
        }
    }
    if ($null -ne $Default) {
        return [pscustomobject]@{ Value = $Default; Source = 'Windows default'; Key = $Keys[0] }
    }
    return [pscustomobject]@{ Value = $null; Source = 'not set'; Key = $Keys[0] }
}

function Format-Setting {
    param($Setting, [string]$Label)
    if ($Setting.Source -eq 'not set') { return "$Label not set" }
    if ($Setting.Source -eq 'set') { return "$Label = $($Setting.Value)" }
    return "$Label = $($Setting.Value) ($($Setting.Source))"
}

function Get-SecPolValue {
    param($Snapshot, [string]$Name)
    $sp = Get-Prop $Snapshot 'SecurityPolicy'
    if (-not (Test-Prop $sp $Name)) { return $null }
    return Get-Prop $sp $Name
}

#endregion

#region Registry and audit targets

$RegSystem   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$RegTs       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$RegRdpTcp   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$RegTsPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$RegLsa      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$RegSchannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$RegRemovable = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
# Device setup class GUID for removable disks
$RemovableDiskClass = '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'

function Get-RegistryTarget {
    # Every registry value a check reads. Keys in the snapshot are "<path>\<name>".
    @(
        "$RegSystem\EnableLUA"
        "$RegSystem\PromptOnSecureDesktop"
        "$RegSystem\LegalNoticeCaption"
        "$RegSystem\LegalNoticeText"
        "$RegSystem\InactivityTimeoutSecs"
        "$RegTs\fDenyTSConnections"
        "$RegTsPolicy\fDenyTSConnections"
        "$RegRdpTcp\UserAuthentication"
        "$RegTsPolicy\UserAuthentication"
        "$RegRdpTcp\MaxIdleTime"
        "$RegTsPolicy\MaxIdleTime"
        "$RegLsa\NoLMHash"
        "$RegLsa\LmCompatibilityLevel"
        "$RegLsa\FipsAlgorithmPolicy\Enabled"
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        "$RegSchannel\TLS 1.0\Server\Enabled"
        "$RegSchannel\TLS 1.0\Client\Enabled"
        "$RegSchannel\TLS 1.1\Server\Enabled"
        "$RegSchannel\TLS 1.1\Client\Enabled"
        "$RegRemovable\Deny_All"
        "$RegRemovable\$RemovableDiskClass\Deny_Write"
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize'
        'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type'
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start'
    )
}

$AuditBits = @{ Success = 1; Failure = 2; SuccessAndFailure = 3 }
$AuditNames = @{ 0 = 'No Auditing'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }

function Test-AuditSubcategory {
    # Each required subcategory must include the required bits. Returns a result.
    param($Snapshot, [object[]]$Required)
    $ap = Get-Prop $Snapshot 'AuditPolicy'
    $short = @()
    $ok = @()
    foreach ($r in $Required) {
        $guid = "$($r.Guid)".ToUpperInvariant()
        $actual = 0
        if (Test-Prop $ap $guid) { $actual = [int](Get-Prop $ap $guid) }
        $need = $AuditBits["$($r.Setting)"]
        if ($null -eq $need) { throw "Audit setting '$($r.Setting)' for $($r.Name) must be Success, Failure or SuccessAndFailure." }
        if (($actual -band $need) -eq $need) { $ok += $r.Name }
        else { $short += "$($r.Name) is $($AuditNames[$actual]), needs $($AuditNames[$need])" }
    }
    if ($short.Count -gt 0) { return New-CheckResult Fail ($short -join '; ') }
    return New-CheckResult Pass ("Meets the required setting: " + ($ok -join ', '))
}

#endregion

#region Checks

function Get-CheckTable {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Every Test takes the same (snapshot, thresholds) pair; not every check has a threshold.')]
    param()
    # Each check names the snapshot sections it needs (Needs: all must have been
    # collected; NeedsAny: at least one) and a Test that returns New-CheckResult.
    # A Test reads only the snapshot and the thresholds, never the machine.
    [ordered]@{

        'AC-GuestDisabled' = @{
            Title = 'Built-in Guest account is disabled'
            Needs = @('LocalAccounts')
            Test  = {
                param($S, $T)
                $guest = @(@(Get-Prop (Get-Prop $S 'LocalAccounts') 'Users') | Where-Object { "$($_.Sid)" -match '-501$' })
                if ($guest.Count -eq 0) { return New-CheckResult NotApplicable 'No local account with RID 501.' }
                if ($guest[0].Enabled) { return New-CheckResult Fail "Guest account '$($guest[0].Name)' is enabled." }
                New-CheckResult Pass "Guest account '$($guest[0].Name)' is disabled."
            }
        }

        'AC-NoPasswordNotRequired' = @{
            Title = 'No enabled local account is exempt from needing a password'
            Needs = @('LocalAccounts')
            Test  = {
                param($S, $T)
                $users = @(Get-Prop (Get-Prop $S 'LocalAccounts') 'Users')
                if ($users.Count -eq 0) { throw 'No local accounts were returned; every Windows machine has some.' }
                $enabled = @($users | Where-Object { $_.Enabled })
                $bad = @($enabled | Where-Object { -not $_.PasswordRequired })
                if ($bad.Count -gt 0) {
                    return New-CheckResult Fail ('Enabled with no password required: ' + (($bad | ForEach-Object { $_.Name }) -join ', '))
                }
                New-CheckResult Pass "$($enabled.Count) enabled local account(s), all require a password."
            }
        }

        'AC-UacEnabled' = @{
            Title = 'User Account Control is on'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $v = Get-RegSetting $S @("$RegSystem\EnableLUA") -Default 1
                $ev = Format-Setting $v 'EnableLUA'
                if ("$($v.Value)" -eq '1') { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev
            }
        }

        'AC-UacSecureDesktop' = @{
            Title = 'Elevation prompts use the secure desktop'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $v = Get-RegSetting $S @("$RegSystem\PromptOnSecureDesktop") -Default 1
                $ev = Format-Setting $v 'PromptOnSecureDesktop'
                if ("$($v.Value)" -eq '1') { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev
            }
        }

        'AC-LocalAdminCount' = @{
            Title = 'Local Administrators group is small'
            Needs = @('LocalAccounts')
            Test  = {
                param($S, $T)
                $members = @(Get-Prop (Get-Prop $S 'LocalAccounts') 'Administrators')
                $ev = "$($members.Count) member(s), limit $($T.MaxLocalAdmins): " + ($members -join ', ')
                if ($members.Count -le $T.MaxLocalAdmins) { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev
            }
        }

        'AC-AccountLockout' = @{
            Title = 'Accounts lock after repeated bad passwords'
            Needs = @('SecurityPolicy')
            Test  = {
                param($S, $T)
                $count = Get-SecPolValue $S 'LockoutBadCount'
                if ($null -eq $count) { throw 'LockoutBadCount missing from the exported security policy.' }
                if ($count -eq 0) { return New-CheckResult Fail 'Lockout threshold is 0: accounts never lock.' }
                if ($count -gt $T.LockoutThresholdMax) {
                    return New-CheckResult Fail "Lockout threshold is $count attempts, limit $($T.LockoutThresholdMax)."
                }
                $duration = Get-SecPolValue $S 'LockoutDuration'
                if ($null -eq $duration) { throw 'LockoutDuration missing from the exported security policy.' }
                if ($duration -eq -1) {
                    return New-CheckResult Pass "Locks after $count attempts until an administrator unlocks it."
                }
                if ($duration -lt $T.LockoutDurationMinMinutes) {
                    return New-CheckResult Fail "Locks after $count attempts for $duration min, minimum $($T.LockoutDurationMinMinutes)."
                }
                New-CheckResult Pass "Locks after $count attempts for $duration min."
            }
        }

        'AC-LogonBanner' = @{
            Title = 'A logon banner is shown'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $cap = Get-RegSetting $S @("$RegSystem\LegalNoticeCaption")
                $txt = Get-RegSetting $S @("$RegSystem\LegalNoticeText")
                $hasCap = "$($cap.Value)".Trim() -ne ''
                $hasTxt = "$($txt.Value)".Trim() -ne ''
                if ($hasCap -and $hasTxt) {
                    return New-CheckResult Pass "Caption '$("$($cap.Value)".Trim())' and $("$($txt.Value)".Length) characters of text are set."
                }
                $missing = @()
                if (-not $hasCap) { $missing += 'caption' }
                if (-not $hasTxt) { $missing += 'text' }
                New-CheckResult Fail ('Logon banner ' + ($missing -join ' and ') + ' not set.')
            }
        }

        'AC-InactivityLock' = @{
            Title = 'Machine locks after inactivity'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $v = Get-RegSetting $S @("$RegSystem\InactivityTimeoutSecs")
                $ev = Format-Setting $v 'InactivityTimeoutSecs'
                if ($null -eq $v.Value -or [int]$v.Value -eq 0) { return New-CheckResult Fail "$ev; no machine inactivity limit." }
                if ([int]$v.Value -le $T.InactivityLockMaxSeconds) { return New-CheckResult Pass $ev }
                New-CheckResult Fail "$ev; limit $($T.InactivityLockMaxSeconds) s."
            }
        }

        'AC-RdpProtected' = @{
            Title = 'Remote Desktop is off, or requires Network Level Authentication'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $deny = Get-RegSetting $S @("$RegTsPolicy\fDenyTSConnections", "$RegTs\fDenyTSConnections") -Default 1
                if ("$($deny.Value)" -eq '1') { return New-CheckResult Pass 'Remote Desktop is off.' }
                # NLA means CredSSP over TLS, so the session is authenticated and encrypted.
                $nla = Get-RegSetting $S @("$RegTsPolicy\UserAuthentication", "$RegRdpTcp\UserAuthentication") -Default 1
                $ev = 'Remote Desktop is on; ' + (Format-Setting $nla 'UserAuthentication (NLA)')
                if ("$($nla.Value)" -eq '1') { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev
            }
        }

        'AC-RdpIdleTimeout' = @{
            Title = 'Idle Remote Desktop sessions are ended'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $deny = Get-RegSetting $S @("$RegTsPolicy\fDenyTSConnections", "$RegTs\fDenyTSConnections") -Default 1
                if ("$($deny.Value)" -eq '1') { return New-CheckResult NotApplicable 'Remote Desktop is off.' }
                $idle = Get-RegSetting $S @("$RegTsPolicy\MaxIdleTime", "$RegRdpTcp\MaxIdleTime")
                if ($null -eq $idle.Value -or [int64]$idle.Value -eq 0) {
                    return New-CheckResult Fail 'Remote Desktop is on with no idle session limit.'
                }
                $minutes = [math]::Round([int64]$idle.Value / 60000, 1)
                if ($minutes -le $T.RdpIdleMaxMinutes) { return New-CheckResult Pass "Idle sessions end after $minutes min." }
                New-CheckResult Fail "Idle sessions end after $minutes min, limit $($T.RdpIdleMaxMinutes)."
            }
        }

        'AU-AuditPolicy' = @{
            Title = 'Advanced audit policy covers the required subcategories'
            Needs = @('AuditPolicy')
            Test  = {
                param($S, $T)
                Test-AuditSubcategory $S @($T.AuditSubcategories)
            }
        }

        'AU-SensitivePrivilegeUse' = @{
            Title = 'Use of privileged functions is audited'
            Needs = @('AuditPolicy')
            Test  = {
                param($S, $T)
                $req = @($T.AuditSubcategories | Where-Object { $_.Guid -eq '{0CCE9228-69AE-11D9-BED3-505054503030}' })
                if ($req.Count -eq 0) {
                    $req = @(@{ Name = 'Sensitive Privilege Use'; Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Setting = 'SuccessAndFailure' })
                }
                Test-AuditSubcategory $S $req
            }
        }

        'AU-SecurityLogSize' = @{
            Title = 'Security event log is large enough'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $policy = Get-RegFact $S 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
                $local = Get-RegFact $S 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize'
                if ($policy.Present) {
                    $mb = [math]::Round([int64]$policy.Value / 1024)          # policy value is in KB
                    $src = 'policy'
                } elseif ($local.Denied) {
                    return New-CheckResult Skipped 'Security log settings are not readable without elevation.'
                } elseif ($local.Present) {
                    $mb = [math]::Round([int64]$local.Value / 1MB)            # service value is in bytes
                    $src = 'local'
                } else {
                    $mb = 20
                    $src = 'Windows default'
                }
                $ev = "Security log maximum $mb MB ($src), minimum $($T.MinSecurityLogMB) MB."
                if ($mb -ge $T.MinSecurityLogMB) { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev
            }
        }

        'AU-TimeSync' = @{
            Title = 'Clock synchronizes with a time source'
            Needs = @('Registry', 'Services')
            Test  = {
                param($S, $T)
                $svc = Get-Prop (Get-Prop $S 'Services') 'W32Time'
                if ($null -eq $svc) { throw "Service 'W32Time' was not collected." }
                if (-not $svc.Present) { return New-CheckResult Fail 'Windows Time service is not installed.' }
                if ("$($svc.StartType)" -eq 'Disabled') { return New-CheckResult Fail 'Windows Time service is disabled.' }
                $type = Get-RegSetting $S @('HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type')
                if ($null -eq $type.Value) { return New-CheckResult Fail 'Windows Time sync type is not set.' }
                if ("$($type.Value)" -eq 'NoSync') { return New-CheckResult Fail 'Windows Time sync type is NoSync.' }
                New-CheckResult Pass "Windows Time is $($svc.StartType) and syncs by $($type.Value)."
            }
        }

        'CM-Smb1Disabled' = @{
            Title = 'SMBv1 is off'
            Needs = @('Registry', 'Smb')
            Test  = {
                param($S, $T)
                $client = Get-RegFact $S 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start'
                $clientOn = $client.Present -and "$($client.Value)" -ne '4'
                $reg = Get-RegFact $S 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
                $server = Get-Prop (Get-Prop $S 'Smb') 'ServerEnabled'
                if ($null -eq $server -and $reg.Present) { $server = "$($reg.Value)" -ne '0' }
                $parts = @()
                if ($clientOn) { $parts += 'SMBv1 client driver is enabled' }
                if ($server -eq $true) { $parts += 'SMBv1 server is enabled' }
                if ($parts.Count -gt 0) { return New-CheckResult Fail ($parts -join '; ') }
                if ($null -eq $server) {
                    return New-CheckResult Skipped 'SMBv1 client is off; server state unknown without elevation.'
                }
                New-CheckResult Pass 'SMBv1 client and server are off.'
            }
        }

        'CM-NonessentialServices' = @{
            Title = 'Listed nonessential services are absent or disabled'
            Needs = @('Services')
            Test  = {
                param($S, $T)
                $svcs = Get-Prop $S 'Services'
                $running = @()
                $names = @($T.NonessentialServices)
                foreach ($n in $names) {
                    $e = Get-Prop $svcs $n
                    if ($null -eq $e) { throw "Service '$n' was not collected." }
                    if ($e.Present -and "$($e.StartType)" -ne 'Disabled') { $running += "$n ($($e.StartType))" }
                }
                if ($running.Count -gt 0) { return New-CheckResult Fail ('Not disabled: ' + ($running -join ', ')) }
                New-CheckResult Pass ("Absent or disabled: " + ($names -join ', '))
            }
        }

        'CM-AlwaysInstallElevated' = @{
            Title = 'Windows Installer does not elevate user installs'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $m = Get-RegSetting $S @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated')
                $u = Get-RegSetting $S @('HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated')
                # Windows needs both set to act on it, but the machine value alone is
                # one user-policy change away, so it fails on its own.
                if ("$($m.Value)" -eq '1') {
                    return New-CheckResult Fail ('AlwaysInstallElevated is 1 for the machine' + $(if ("$($u.Value)" -eq '1') { ' and the scanning user.' } else { '.' }))
                }
                New-CheckResult Pass ((Format-Setting $m 'AlwaysInstallElevated (machine)') + '.')
            }
        }

        'IA-PasswordComplexity' = @{
            Title = 'Local passwords need complexity and a minimum length'
            Needs = @('SecurityPolicy')
            Test  = {
                param($S, $T)
                $cx = Get-SecPolValue $S 'PasswordComplexity'
                $len = Get-SecPolValue $S 'MinimumPasswordLength'
                if ($null -eq $cx -or $null -eq $len) { throw 'Password policy missing from the exported security policy.' }
                $note = 'Local account policy; domain accounts follow the domain password policy.'
                $ev = "Complexity $(if ($cx -eq 1) { 'on' } else { 'off' }), minimum length $len (needs $($T.MinPasswordLength))."
                if ($cx -eq 1 -and $len -ge $T.MinPasswordLength) { return New-CheckResult Pass $ev $note }
                New-CheckResult Fail $ev $note
            }
        }

        'IA-PasswordHistory' = @{
            Title = 'Local passwords cannot be reused'
            Needs = @('SecurityPolicy')
            Test  = {
                param($S, $T)
                $h = Get-SecPolValue $S 'PasswordHistorySize'
                if ($null -eq $h) { throw 'PasswordHistorySize missing from the exported security policy.' }
                $note = 'Local account policy; domain accounts follow the domain password policy.'
                $ev = "Remembers $h passwords (needs $($T.MinPasswordHistory))."
                if ($h -ge $T.MinPasswordHistory) { return New-CheckResult Pass $ev $note }
                New-CheckResult Fail $ev $note
            }
        }

        'IA-StoredPasswordProtection' = @{
            Title = 'No LM hashes or reversibly encrypted passwords are stored'
            Needs = @('Registry', 'SecurityPolicy')
            Test  = {
                param($S, $T)
                $lm = Get-RegSetting $S @("$RegLsa\NoLMHash") -Default 1
                $clear = Get-SecPolValue $S 'ClearTextPassword'
                if ($null -eq $clear) { throw 'ClearTextPassword missing from the exported security policy.' }
                $ev = (Format-Setting $lm 'NoLMHash') + "; reversible encryption $(if ($clear -eq 1) { 'on' } else { 'off' })."
                if ("$($lm.Value)" -eq '1' -and $clear -eq 0) { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev
            }
        }

        'IA-NtlmV2Only' = @{
            Title = 'Only NTLMv2 is sent; LM and NTLMv1 are refused'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $v = Get-RegSetting $S @("$RegLsa\LmCompatibilityLevel") -Default 3
                $ev = Format-Setting $v 'LmCompatibilityLevel'
                if ([int]$v.Value -ge 5) { return New-CheckResult Pass $ev }
                New-CheckResult Fail "$ev; needs 5."
            }
        }

        'MP-RemovableStorage' = @{
            Title = 'A Windows policy restricts removable storage'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                if (-not $T.RequireRemovableMediaPolicy) {
                    return New-CheckResult Manual 'Not checked: RequireRemovableMediaPolicy is off in the profile.' 'Show the device control product and its policy instead.'
                }
                $all = Get-RegSetting $S @("$RegRemovable\Deny_All")
                $write = Get-RegSetting $S @("$RegRemovable\$RemovableDiskClass\Deny_Write")
                if ("$($all.Value)" -eq '1') { return New-CheckResult Pass 'All removable storage classes are denied.' }
                if ("$($write.Value)" -eq '1') { return New-CheckResult Pass 'Write access to removable disks is denied.' }
                New-CheckResult Fail 'No Windows policy restricts removable storage.' 'If a third-party device control product enforces this, set RequireRemovableMediaPolicy = $false and show that product instead.'
            }
        }

        'SC-FirewallEnabled' = @{
            Title = 'Host firewall is on and blocks inbound by default on every profile'
            Needs = @('Firewall')
            Test  = {
                param($S, $T)
                $profiles = @(Get-Prop $S 'Firewall')
                if ($profiles.Count -eq 0) { throw 'No firewall profiles were returned.' }
                $bad = @()
                foreach ($p in $profiles) {
                    # NotConfigured in the active store means the Windows default: on, inbound Block.
                    if ("$($p.Enabled)" -notin 'True', 'NotConfigured') { $bad += "$($p.Name) is off" }
                    if ("$($p.DefaultInboundAction)" -notin 'Block', 'NotConfigured') { $bad += "$($p.Name) allows inbound by default" }
                }
                if ($bad.Count -gt 0) { return New-CheckResult Fail ($bad -join '; ') }
                New-CheckResult Pass ('On with inbound Block: ' + (($profiles | ForEach-Object { $_.Name }) -join ', '))
            }
        }

        'SC-LegacyTlsDisabled' = @{
            Title = 'TLS 1.0 and 1.1 are turned off in Schannel'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $on = @()
                foreach ($proto in 'TLS 1.0', 'TLS 1.1') {
                    foreach ($side in 'Server', 'Client') {
                        $v = Get-RegSetting $S @("$RegSchannel\$proto\$side\Enabled")
                        if ("$($v.Value)" -ne '0') { $on += "$proto $side ($($v.Source))" }
                    }
                }
                if ($on.Count -gt 0) {
                    return New-CheckResult Fail ('Not explicitly off: ' + ($on -join ', ')) 'Whether an unset protocol is on depends on the Windows build; set Enabled = 0 to make it certain.'
                }
                New-CheckResult Pass 'TLS 1.0 and 1.1 are off for client and server.'
            }
        }

        'SC-FipsMode' = @{
            Title = 'Windows FIPS mode is on'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                if (-not $T.RequireFipsMode) {
                    return New-CheckResult Manual 'Not checked: RequireFipsMode is off in the profile.' 'Show that the cryptographic modules protecting CUI are FIPS 140 validated.'
                }
                $v = Get-RegSetting $S @("$RegLsa\FipsAlgorithmPolicy\Enabled") -Default 0
                $ev = Format-Setting $v 'FipsAlgorithmPolicy'
                if ("$($v.Value)" -eq '1') { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev 'If FIPS-validated modules are evidenced another way, set RequireFipsMode = $false.'
            }
        }

        'SC-BitLocker' = @{
            Title = 'BitLocker protects the operating system volume'
            Needs = @('BitLocker')
            Test  = {
                param($S, $T)
                $b = Get-Prop $S 'BitLocker'
                $ev = "$($b.MountPoint) protection $($b.ProtectionStatus)."
                if ("$($b.ProtectionStatus)" -eq 'On') { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev
            }
        }

        'SI-UpdateRecency' = @{
            Title = 'A Windows update was installed recently'
            Needs = @('Hotfix')
            Test  = {
                param($S, $T)
                $h = Get-Prop $S 'Hotfix'
                $d = ConvertTo-DateValue (Get-Prop $h 'LatestInstalledOn')
                if ($null -eq $d) { return New-CheckResult Fail 'No installed update reports an install date.' }
                $age = Get-SnapshotAge $S $d
                $ev = "Newest update $($h.LatestKb) installed $($d.ToString('yyyy-MM-dd')), $age days before the scan (limit $($T.MaxDaysSinceUpdate))."
                if ($age -le $T.MaxDaysSinceUpdate) { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev
            }
        }

        'SI-AntivirusActive' = @{
            Title = 'Real-time antivirus protection is on'
            NeedsAny = @('Defender', 'SecurityCenter')
            Test  = {
                param($S, $T)
                $def = Get-Prop $S 'Defender'
                if ($def -and $def.AMServiceEnabled -and $def.RealTimeProtectionEnabled) {
                    return New-CheckResult Pass 'Microsoft Defender real-time protection is on.'
                }
                $third = @(Get-ThirdPartyAntivirus $S | Where-Object { $_.Enabled })
                if ($third.Count -gt 0) {
                    return New-CheckResult Pass ('On, as reported to Security Center: ' + (($third | ForEach-Object { $_.DisplayName }) -join ', '))
                }
                New-CheckResult Fail 'No antivirus reports real-time protection on.'
            }
        }

        'SI-SignatureAge' = @{
            Title = 'Antivirus signatures are current'
            NeedsAny = @('Defender', 'SecurityCenter')
            Test  = {
                param($S, $T)
                $def = Get-Prop $S 'Defender'
                if ($def -and $def.RealTimeProtectionEnabled) {
                    $d = ConvertTo-DateValue (Get-Prop $def 'AntivirusSignatureLastUpdated')
                    if ($null -eq $d) { return New-CheckResult Fail 'Defender reports no signature update date.' }
                    $age = Get-SnapshotAge $S $d
                    $ev = "Defender signatures updated $($d.ToString('yyyy-MM-dd')), $age days before the scan (limit $($T.MaxSignatureAgeDays))."
                    if ($age -le $T.MaxSignatureAgeDays) { return New-CheckResult Pass $ev }
                    return New-CheckResult Fail $ev
                }
                $third = @(Get-ThirdPartyAntivirus $S | Where-Object { $_.Enabled })
                if ($third.Count -gt 0) {
                    $stale = @($third | Where-Object { -not $_.UpToDate })
                    if ($stale.Count -gt 0) {
                        return New-CheckResult Fail ('Out of date, as reported to Security Center: ' + (($stale | ForEach-Object { $_.DisplayName }) -join ', '))
                    }
                    return New-CheckResult Pass ('Up to date, as reported to Security Center: ' + (($third | ForEach-Object { $_.DisplayName }) -join ', '))
                }
                New-CheckResult Fail 'No active antivirus to report signature age.'
            }
        }

        'SI-ScanRecency' = @{
            Title = 'A full or quick antivirus scan ran recently'
            NeedsAny = @('Defender', 'SecurityCenter')
            Test  = {
                param($S, $T)
                $def = Get-Prop $S 'Defender'
                if ($def -and $def.RealTimeProtectionEnabled) {
                    $dates = @(@((Get-Prop $def 'QuickScanEndTime'), (Get-Prop $def 'FullScanEndTime')) |
                        ForEach-Object { ConvertTo-DateValue $_ } | Where-Object { $null -ne $_ } | Sort-Object -Descending)
                    if ($dates.Count -eq 0) { return New-CheckResult Fail 'Defender has no record of a completed scan.' }
                    $age = Get-SnapshotAge $S $dates[0]
                    $ev = "Last Defender scan finished $($dates[0].ToString('yyyy-MM-dd')), $age days before the scan (limit $($T.MaxDaysSinceScan))."
                    if ($age -le $T.MaxDaysSinceScan) { return New-CheckResult Pass $ev }
                    return New-CheckResult Fail $ev
                }
                $third = @(Get-ThirdPartyAntivirus $S | Where-Object { $_.Enabled })
                if ($third.Count -gt 0) {
                    return New-CheckResult Manual ('Third-party antivirus: ' + (($third | ForEach-Object { $_.DisplayName }) -join ', ')) 'Scan history is in that product''s console.'
                }
                New-CheckResult Fail 'No active antivirus to report scans.'
            }
        }
    }
}

function Get-ThirdPartyAntivirus {
    # Security Center entries other than Defender, with productState decoded:
    # bit 0x1000 = real-time on, bit 0x10 = signatures out of date.
    param($Snapshot)
    foreach ($p in @(Get-Prop $Snapshot 'SecurityCenter')) {
        if ($null -eq $p -or "$($p.DisplayName)" -match 'Defender') { continue }
        $state = [int]$p.ProductState
        [pscustomobject]@{
            DisplayName = "$($p.DisplayName)"
            Enabled     = ($state -band 0x1000) -ne 0
            UpToDate    = ($state -band 0x10) -eq 0
        }
    }
}

#endregion

#region Evaluation

function Invoke-Check {
    # Runs one check against a snapshot. Never throws: a missing section becomes
    # Skipped or Error, and a Test that throws becomes Error.
    param([string]$Name, $Definition, $Snapshot, $Thresholds)
    $collection = Get-Prop $Snapshot 'Collection'
    $needs = @()
    if ($Definition.Contains('Needs')) { $needs = @($Definition.Needs) }
    $needsAny = @()
    if ($Definition.Contains('NeedsAny')) { $needsAny = @($Definition.NeedsAny) }

    $blocked = $null
    foreach ($n in $needs) {
        $c = Get-Prop $collection $n
        if ($null -eq $c) { $blocked = New-CheckResult Error "Snapshot has no collection record for $n."; break }
        if ("$($c.Status)" -ne 'Ok') { $blocked = New-CheckResult $c.Status "$n not collected: $($c.Reason)"; break }
    }
    if (-not $blocked -and $needsAny.Count -gt 0) {
        $okAny = @($needsAny | Where-Object { "$((Get-Prop (Get-Prop $collection $_) 'Status'))" -eq 'Ok' })
        if ($okAny.Count -eq 0) {
            $reasons = @($needsAny | ForEach-Object {
                $c = Get-Prop $collection $_
                if ($null -eq $c) { "$($_): no collection record" } else { "$($_): $($c.Reason)" }
            })
            $states = @($needsAny | ForEach-Object { "$((Get-Prop (Get-Prop $collection $_) 'Status'))" })
            $state = if ($states -contains 'Error' -or $states -contains '') { 'Error' } else { 'Skipped' }
            $blocked = New-CheckResult $state ('None collected. ' + ($reasons -join '; '))
        }
    }

    $result = $blocked
    if (-not $result) {
        try {
            $result = & $Definition.Test $Snapshot $Thresholds
            if ($null -eq $result) { $result = New-CheckResult Error 'Check returned no result.' }
        } catch {
            $result = New-CheckResult Error "Check failed: $($_.Exception.Message)"
        }
    }
    [pscustomobject]@{
        Check    = $Name
        Title    = $Definition.Title
        State    = $result.State
        Evidence = $result.Evidence
        Note     = $result.Note
    }
}

function Invoke-CmmcEvaluation {
    # Judges a snapshot. Returns the check results and one result per requirement
    # at or under -Level.
    param($Snapshot, $Thresholds, $Catalog, [int]$Level = 2)
    $table = Get-CheckTable
    $checkResults = [ordered]@{}
    foreach ($name in $table.Keys) {
        $checkResults[$name] = Invoke-Check -Name $name -Definition $table[$name] -Snapshot $Snapshot -Thresholds $Thresholds
    }

    $requirements = foreach ($r in @($Catalog.Requirements | Where-Object { $_.Level -le $Level })) {
        $names = @($r.Checks)
        $notes = @()
        if ($r.Contains('Note') -and $r.Note) { $notes += $r.Note }
        if ($names.Count -eq 0) {
            $state = 'Manual'
            $checks = ''
            $evidence = ''
        } else {
            $results = @(foreach ($n in $names) {
                if (-not $checkResults.Contains($n)) { throw "Catalog entry $($r.Id) names unknown check '$n'." }
                $checkResults[$n]
            })
            $state = ($results | Sort-Object { $StateRank[$_.State] } | Select-Object -First 1).State
            $checks = ($results | ForEach-Object { "$($_.Check)=$($_.State)" }) -join '; '
            $evidence = ($results | ForEach-Object { "$($_.Check): $($_.Evidence)" }) -join ' | '
            $notes += @($results | Where-Object { $_.Note } | ForEach-Object { $_.Note })
        }
        [pscustomobject]@{
            Requirement = $r.Id
            Practice    = "$($r.Family).L$($r.Level)-$($r.Id)"
            Level       = $r.Level
            Family      = $r.Family
            Title       = $r.Title
            State       = $state
            Checks      = $checks
            Evidence    = $evidence
            Note        = (@($notes | Select-Object -Unique) -join ' ')
        }
    }

    [pscustomobject]@{
        Checks       = @($checkResults.Values)
        Requirements = @($requirements)
    }
}

function Get-ScanExitCode {
    param([object[]]$Requirements)
    $states = @($Requirements | ForEach-Object { $_.State })
    if ($states -contains 'Error') { return 2 }
    if ($states -contains 'Fail') { return 1 }
    return 0
}

function Get-ScanThreshold {
    # The example thresholds, with -ProfilePath (or CmmcScan.local.psd1) on top.
    [CmdletBinding()]
    param([string]$ExamplePath, [string]$OverridePath)
    $t = Import-PowerShellDataFile -LiteralPath $ExamplePath
    if ($OverridePath) {
        $o = Import-PowerShellDataFile -LiteralPath $OverridePath
        foreach ($k in @($o.Keys)) {
            if (-not $t.ContainsKey($k)) { Write-Warning "Unknown threshold '$k' in $OverridePath is ignored." ; continue }
            $t[$k] = $o[$k]
        }
    }
    return $t
}

function Read-Snapshot {
    param([string]$Path)
    $s = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $v = Get-Prop $s 'SchemaVersion'
    if ($v -ne $SnapshotSchemaVersion) { throw "Snapshot $Path has schema version '$v'; this script reads version $SnapshotSchemaVersion." }
    return $s
}

#endregion

#region Collection (Windows only)

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Collector {
    # Fills one snapshot section. A collector throws NotSupportedException when
    # its source doesn't exist on this machine (Skipped); anything else is Error.
    param($Snapshot, [string]$Name, [bool]$Elevated, [switch]$RequiresAdmin, [scriptblock]$Script)
    if ($RequiresAdmin -and -not $Elevated) {
        $Snapshot.Collection[$Name] = [ordered]@{ Status = 'Skipped'; Reason = 'Needs an elevated session.' }
        $Snapshot[$Name] = $null
        return
    }
    try {
        $Snapshot[$Name] = & $Script
        $Snapshot.Collection[$Name] = [ordered]@{ Status = 'Ok'; Reason = '' }
    } catch [System.NotSupportedException] {
        Write-Verbose "Collector $Name skipped: $($_.Exception.Message)"
        $Snapshot[$Name] = $null
        $Snapshot.Collection[$Name] = [ordered]@{ Status = 'Skipped'; Reason = $_.Exception.Message }
    } catch {
        Write-Verbose "Collector $Name failed: $($_.Exception.Message)"
        $Snapshot[$Name] = $null
        $Snapshot.Collection[$Name] = [ordered]@{ Status = 'Error'; Reason = $_.Exception.Message }
    }
}

function Read-RegistryValue {
    # One value straight from the registry API, so a missing key, a missing value
    # and an access-denied key are told apart.
    param([string]$Key)
    $hiveName, $rest = $Key -split ':\\', 2
    $sub = Split-Path $rest -Parent
    $name = Split-Path $rest -Leaf
    $hive = if ($hiveName -eq 'HKCU') { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
    try {
        $k = $hive.OpenSubKey($sub)
    } catch [System.Security.SecurityException] {
        Write-Verbose "Registry key $sub not readable: $($_.Exception.Message)"
        return [ordered]@{ Present = $false; Value = $null; Denied = $true }
    }
    if ($null -eq $k) { return [ordered]@{ Present = $false; Value = $null; Denied = $false } }
    try {
        $v = $k.GetValue($name)
    } finally { $k.Close() }
    if ($null -eq $v) { return [ordered]@{ Present = $false; Value = $null; Denied = $false } }
    if ($v -is [string[]]) { $v = $v -join "`n" }
    if ($v -is [byte[]]) { $v = [BitConverter]::ToString($v) }
    return [ordered]@{ Present = $true; Value = $v; Denied = $false }
}

function Get-EndpointSnapshot {
    # Collects every fact the checks read. Read-only.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Thresholds',
        Justification = 'Used inside the Services collector script block, which the rule does not follow.')]
    param($Thresholds)
    $elevated = Test-Elevated
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $snap = [ordered]@{
        SchemaVersion = $SnapshotSchemaVersion
        Meta          = [ordered]@{
            Tool         = 'cmmc-endpoint-scan'
            Version      = $CmmcScanVersion
            ComputerName = $env:COMPUTERNAME
            CollectedUtc = ConvertTo-IsoDate (Get-Date)
            IsElevated   = $elevated
            PSVersion    = "$($PSVersionTable.PSVersion)"
            OSCaption    = "$($os.Caption)"
            OSVersion    = "$($os.Version)"
            ProductType  = [int]$os.ProductType
        }
        Collection    = [ordered]@{}
    }
    $tmpDir = [IO.Path]::GetTempPath()

    Invoke-Collector $snap 'SecurityPolicy' $elevated -RequiresAdmin {
        $tmp = Join-Path $tmpDir ("cmmc-secpol-{0}.inf" -f [guid]::NewGuid())
        try {
            $null = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY /quiet
            if ($LASTEXITCODE -ne 0) { throw "secedit /export exited with $LASTEXITCODE." }
            $section = ''
            $out = [ordered]@{}
            foreach ($line in Get-Content -LiteralPath $tmp -Encoding Unicode) {
                if ($line -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
                if ($section -ne 'System Access' -or $line -notmatch '^\s*(\w+)\s*=\s*(.*?)\s*$') { continue }
                $key = $Matches[1]
                $raw = $Matches[2].Trim('"')
                $n = 0
                if ([int]::TryParse($raw, [ref]$n)) { $out[$key] = $n } else { $out[$key] = $raw }
            }
            $out
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    Invoke-Collector $snap 'AuditPolicy' $elevated -RequiresAdmin {
        $tmp = Join-Path $tmpDir ("cmmc-audit-{0}.csv" -f [guid]::NewGuid())
        try {
            $null = & auditpol.exe /backup "/file:$tmp"
            if ($LASTEXITCODE -ne 0) { throw "auditpol /backup exited with $LASTEXITCODE." }
            $out = [ordered]@{}
            foreach ($row in Import-Csv -LiteralPath $tmp) {
                $guid = "$($row.'Subcategory GUID')".Trim()
                if ($guid -eq '') { continue }
                $val = 0
                $null = [int]::TryParse("$($row.'Setting Value')", [ref]$val)
                $out[$guid.ToUpperInvariant()] = $val
            }
            if ($out.Count -eq 0) { throw 'auditpol returned no subcategories.' }
            $out
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    Invoke-Collector $snap 'Registry' $elevated {
        $out = [ordered]@{}
        foreach ($key in Get-RegistryTarget) { $out[$key] = Read-RegistryValue $key }
        $out
    }

    Invoke-Collector $snap 'Services' $elevated {
        $out = [ordered]@{}
        foreach ($n in @(@($Thresholds.NonessentialServices) + 'W32Time' | Select-Object -Unique)) {
            $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($svc) {
                $out[$n] = [ordered]@{ Present = $true; StartType = "$($svc.StartType)"; Status = "$($svc.Status)" }
            } else {
                $out[$n] = [ordered]@{ Present = $false; StartType = ''; Status = '' }
            }
        }
        $out
    }

    Invoke-Collector $snap 'Smb' $elevated {
        $server = $null
        $source = 'unavailable'
        if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
            try {
                $server = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
                $source = 'Get-SmbServerConfiguration'
            } catch {
                Write-Verbose "Get-SmbServerConfiguration failed, falling back to the registry: $($_.Exception.Message)"
            }
        }
        [ordered]@{ ServerEnabled = $server; Source = $source }
    }

    Invoke-Collector $snap 'Firewall' $elevated {
        if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
            throw [System.NotSupportedException]::new('Get-NetFirewallProfile is not available.')
        }
        @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
            [ordered]@{ Name = "$($_.Name)"; Enabled = "$($_.Enabled)"; DefaultInboundAction = "$($_.DefaultInboundAction)" }
        })
    }

    Invoke-Collector $snap 'Defender' $elevated {
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
            throw [System.NotSupportedException]::new('Microsoft Defender cmdlets are not available.')
        }
        $m = Get-MpComputerStatus
        [ordered]@{
            AMServiceEnabled              = [bool]$m.AMServiceEnabled
            AntivirusEnabled              = [bool]$m.AntivirusEnabled
            RealTimeProtectionEnabled     = [bool]$m.RealTimeProtectionEnabled
            AMRunningMode                 = "$(Get-Prop $m 'AMRunningMode')"
            AntivirusSignatureLastUpdated = ConvertTo-IsoDate $m.AntivirusSignatureLastUpdated
            QuickScanEndTime              = ConvertTo-IsoDate $m.QuickScanEndTime
            FullScanEndTime               = ConvertTo-IsoDate $m.FullScanEndTime
        }
    }

    Invoke-Collector $snap 'SecurityCenter' $elevated {
        if ($snap.Meta.ProductType -ne 1) {
            throw [System.NotSupportedException]::new('Security Center exists only on client Windows.')
        }
        @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object {
            [ordered]@{ DisplayName = "$($_.displayName)"; ProductState = [int]$_.productState }
        })
    }

    Invoke-Collector $snap 'BitLocker' $elevated -RequiresAdmin {
        $drive = $env:SystemDrive
        $v = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$drive'"
        if ($null -eq $v) { throw [System.NotSupportedException]::new("No BitLocker information for $drive.") }
        $status = switch ([int]$v.ProtectionStatus) { 0 { 'Off' } 1 { 'On' } default { 'Unknown' } }
        [ordered]@{ MountPoint = $drive; ProtectionStatus = $status }
    }

    Invoke-Collector $snap 'LocalAccounts' $elevated {
        $users = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
            [ordered]@{ Name = "$($_.Name)"; Sid = "$($_.SID)"; Enabled = -not $_.Disabled; PasswordRequired = [bool]$_.PasswordRequired }
        })
        $group = Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
        $admins = @(Get-CimAssociatedInstance -InputObject $group -Association Win32_GroupUser | ForEach-Object { "$($_.Domain)\$($_.Name)" })
        [ordered]@{ Users = $users; Administrators = $admins }
    }

    Invoke-Collector $snap 'Hotfix' $elevated {
        $all = @(Get-HotFix | Where-Object { $_.InstalledOn })
        $latest = $all | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($latest) {
            [ordered]@{ Count = $all.Count; LatestKb = "$($latest.HotFixID)"; LatestInstalledOn = ConvertTo-IsoDate $latest.InstalledOn }
        } else {
            [ordered]@{ Count = 0; LatestKb = ''; LatestInstalledOn = $null }
        }
    }

    # Round-trip through JSON so a live snapshot has exactly the shape of a saved one.
    return ($snap | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
}

#endregion

#region Report

function Write-ScanSummary {
    param($Evaluation, $Snapshot, [int]$Level)
    $reqs = @($Evaluation.Requirements)
    $meta = Get-Prop $Snapshot 'Meta'
    Write-Host ''
    $when = (ConvertTo-DateValue $meta.CollectedUtc).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
    Write-Host "CMMC endpoint scan $CmmcScanVersion, Level $Level, $($meta.ComputerName), collected $when UTC"
    if (-not $meta.IsElevated) { Write-Host 'Not elevated: checks that need elevation are Skipped.' -ForegroundColor Yellow }
    $order = 'Fail', 'Error', 'Skipped', 'Manual', 'Pass', 'NotApplicable'
    $counts = foreach ($s in $order) { '{0} {1}' -f @($reqs | Where-Object { $_.State -eq $s }).Count, $s }
    Write-Host ("$($reqs.Count) requirements: " + ($counts -join ', '))
    # Fixed-width rows rather than Format-Table, which renders nothing when the
    # host has no console width (a scheduled task, a CI log).
    $cols = 'Pass', 'Fail', 'Error', 'Skipped', 'Manual', 'NotApplicable'
    Write-Host ('{0,-7}{1,6}{2,6}{3,7}{4,9}{5,8}{6,5}' -f 'Family', 'Pass', 'Fail', 'Error', 'Skipped', 'Manual', 'N/A')
    foreach ($grp in @($reqs | Group-Object Family | Sort-Object Name)) {
        $n = foreach ($c in $cols) { @($grp.Group | Where-Object { $_.State -eq $c }).Count }
        Write-Host ('{0,-7}{1,6}{2,6}{3,7}{4,9}{5,8}{6,5}' -f (@($grp.Name) + $n))
    }
    # Then each requirement that needs attention, with only the checks that didn't pass.
    $byCheck = @{}
    foreach ($c in @($Evaluation.Checks)) { $byCheck[$c.Check] = $c }
    foreach ($state in 'Fail', 'Error', 'Skipped') {
        $colour = switch ($state) { 'Fail' { 'Red' } 'Error' { 'Magenta' } default { 'Yellow' } }
        foreach ($r in @($reqs | Where-Object { $_.State -eq $state })) {
            $why = foreach ($pair in ($r.Checks -split '; ')) {
                $name, $st = $pair -split '=', 2
                if ($st -notin 'Pass', 'NotApplicable') { "$($name): $($byCheck[$name].Evidence)" }
            }
            Write-Host ('{0,-8} {1,-14} {2}' -f $state, $r.Practice, (@($why) -join ' | ')) -ForegroundColor $colour
        }
    }
}

function Export-ScanReport {
    param($Evaluation, $Snapshot, $Thresholds, [int]$Level, [string]$Folder, [switch]$IncludeSnapshot)
    if (-not (Test-Path -LiteralPath $Folder)) { $null = New-Item -ItemType Directory -Path $Folder }
    $meta = Get-Prop $Snapshot 'Meta'
    $computer = "$($meta.ComputerName)" -replace '[^A-Za-z0-9-]', '_'
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $base = Join-Path $Folder "cmmc-scan-$computer-$stamp"

    $Evaluation.Requirements | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8

    $report = [ordered]@{
        Tool         = 'cmmc-endpoint-scan'
        Version      = $CmmcScanVersion
        Level        = $Level
        ComputerName = $meta.ComputerName
        CollectedUtc = $meta.CollectedUtc
        IsElevated   = $meta.IsElevated
        Summary      = [ordered]@{}
        Requirements = $Evaluation.Requirements
        Checks       = $Evaluation.Checks
        Thresholds   = $Thresholds
    }
    foreach ($s in 'Fail', 'Error', 'Skipped', 'Manual', 'Pass', 'NotApplicable') {
        $report.Summary[$s] = @($Evaluation.Requirements | Where-Object { $_.State -eq $s }).Count
    }
    if ($IncludeSnapshot) { $report.Snapshot = $Snapshot }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$base.json" -Encoding UTF8
    return @("$base.csv", "$base.json")
}

#endregion

# Dot-sourced (as the tests do): define the functions above and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $root = $PSScriptRoot
    $catalog = Import-PowerShellDataFile -LiteralPath (Join-Path $root 'CmmcControls.psd1')

    $override = $ProfilePath
    if (-not $override) {
        $local = Join-Path $root 'CmmcScan.local.psd1'
        if (Test-Path -LiteralPath $local) { $override = $local }
    }
    $thresholds = Get-ScanThreshold -ExamplePath (Join-Path $root 'CmmcScan.example.psd1') -OverridePath $override
    if ($override) { Write-Verbose "Thresholds: example with $override on top." }

    if ($FromSnapshot) {
        $snapshot = Read-Snapshot $FromSnapshot
    } else {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
            throw 'A live scan needs Windows. Use -FromSnapshot to evaluate a saved snapshot elsewhere.'
        }
        $snapshot = Get-EndpointSnapshot -Thresholds $thresholds
    }
    if ($SnapshotPath) {
        $snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SnapshotPath -Encoding UTF8
    }

    $evaluation = Invoke-CmmcEvaluation -Snapshot $snapshot -Thresholds $thresholds -Catalog $catalog -Level $Level

    $folder = $OutputPath
    if (-not $folder) { $folder = Join-Path $root 'Reports' }
    $files = Export-ScanReport -Evaluation $evaluation -Snapshot $snapshot -Thresholds $thresholds -Level $Level -Folder $folder -IncludeSnapshot:$IncludeSnapshot

    Write-ScanSummary -Evaluation $evaluation -Snapshot $snapshot -Level $Level
    Write-Host ("Reports: " + ($files -join ', '))
    if ($PassThru) { $evaluation.Requirements }
    $code = Get-ScanExitCode $evaluation.Requirements
} catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    $code = 2
}
exit $code
