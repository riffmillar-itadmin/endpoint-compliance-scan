<#
.SYNOPSIS
    Scans the local Windows endpoint for evidence against one compliance framework,
    chosen at run time: CMMC, NIST SP 800-171 Rev 3, NIST SP 800-53 Rev 5, the DISA
    STIGs for Windows 11 and Windows Server 2019, 2022 and 2025, CIS Controls v8.1,
    NIST CSF 2.0, PCI DSS 4.0.1 or HIPAA.

.DESCRIPTION
    Read-only. The scan changes no setting, writes nothing to the registry and makes
    no network call. Its only side effects are temporary files (the secedit and
    auditpol exports), deleted as soon as they are read, and the report files.

    It works in two stages so that every pass/fail rule can be tested anywhere:
        1. Collect: gather raw facts about the machine into a snapshot.
        2. Evaluate: judge the snapshot against one framework's requirements.
    One snapshot holds the facts for every framework, so a saved snapshot can be
    evaluated against any of them later with -FromSnapshot.

    Each framework is a catalog in the frameworks folder (frameworks/README.md
    describes the format). A requirement gets its evidence from named checks in
    this script, from setting expectations in the catalog (a registry value, a
    security policy value, an audit subcategory, a user right, a service or a
    Windows feature), or from both. Its result is the worst of those results:
        Fail           evidence collected and it misses the threshold
        Error          a collector or check threw; the message is in the report
        Skipped        the check applies but could not run (usually: not elevated)
        Manual         the endpoint cannot show this; the note says what can
        Pass           evidence collected and it meets the threshold
        NotApplicable  the thing checked is absent (for example, RDP is off, or
                       local accounts on a domain controller)
    Nothing passes by default. A fact missing from the snapshot is an Error, never
    a Pass.

    A STIG catalog names the Windows edition and build it was written for. Run on
    any other, the scan warns, and the report carries the warning.

    This is evidence for an assessment, not a verdict. Most requirements in most
    frameworks are procedural or need evidence from outside the endpoint, so the
    report never states that a machine is compliant and never computes a score.
    Catalogs for copyrighted standards (CIS, PCI DSS) and the HIPAA catalog hold
    only the requirements an endpoint can show evidence for; the report says so.

    Writes two files per run into -OutputPath:
        compliance-scan-<framework>-<computer>-<timestamp>.csv   one row per requirement
        compliance-scan-<framework>-<computer>-<timestamp>.json  requirements, checks and thresholds

    Exit codes: 0 no Fail and no Error; 1 at least one Fail; 2 at least one Error,
    or the scan could not start. Error wins over Fail because a run with errors
    can't be relied on either way.

.PARAMETER Framework
    The framework to evaluate, by its Id or its catalog file name, for example
    CMMC, NIST-800-53r5 or disa-stig-ws2022-ms. Required; run without it to list them.

.PARAMETER Level
    The framework level to assess, such as L1 (CMMC), Low (NIST SP 800-53), CAT I
    (STIG) or IG1 (CIS). A level includes the levels before it. Defaults to the
    framework's highest level. For CMMC, 1 and 2 also work.

.PARAMETER OutputPath
    Folder for the report files. Defaults to a Reports folder beside this script.

.PARAMETER ProfilePath
    Thresholds file to use on top of ComplianceScan.example.psd1 and the
    framework's own thresholds. Without it, a ComplianceScan.local.psd1 beside the
    script is used if present.

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
    .\Invoke-EndpointComplianceScan.ps1 -Framework CMMC
    Full CMMC Level 2 scan. Run elevated, or the checks that need elevation are Skipped.

.EXAMPLE
    .\Invoke-EndpointComplianceScan.ps1 -Framework DISA-STIG-Win11 -Level 'CAT I' -SnapshotPath .\pc01.snapshot.json
    STIG CAT I rules only, and keep the raw snapshot.

.EXAMPLE
    pwsh -File ./Invoke-EndpointComplianceScan.ps1 -Framework NIST-800-53r5 -Level Low -FromSnapshot ./pc01.snapshot.json
    Evaluate a saved snapshot against another framework.

.NOTES
    Version notes
    0.1.0  2026-10-23  First draft: catalog of all 110 requirements, 30 endpoint
                       checks, CSV and JSON reports.
    0.2.0  2026-10-23  Multiple frameworks, chosen with -Framework: CMMC, NIST SP
                       800-171 Rev 3, NIST SP 800-53 Rev 5, DISA Windows 11 STIG,
                       CIS Controls v8.1, NIST CSF 2.0, PCI DSS 4.0.1, HIPAA.
                       Setting expectations in catalogs, an optional features
                       collector, three new checks. Renamed from
                       Invoke-CmmcEndpointScan.ps1.
    0.3.0  2026-10-23  Windows Server: DISA STIGs for Server 2019, 2022 and 2025,
                       member server and domain controller. User rights
                       expectations and collector, Kerberos policy, Server
                       features, platform warning when a catalog is for another
                       Windows, local accounts NotApplicable on a domain
                       controller. Snapshot schema 3.
#>

[CmdletBinding()]
param(
    [string]$Framework,
    [string]$Level,
    [string]$OutputPath,
    [string]$ProfilePath,
    [string]$SnapshotPath,
    [string]$FromSnapshot,
    [switch]$IncludeSnapshot,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ComplianceScanVersion = '0.3.0'
$SnapshotSchemaVersion = 3

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
$RegExplorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$RegExplorerPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
# Device setup class GUID for removable disks
$RemovableDiskClass = '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'

function Get-RegistryTarget {
    # Every registry value a named check reads. Keys in the snapshot are "<path>\<name>".
    @(
        "$RegSystem\EnableLUA"
        "$RegSystem\PromptOnSecureDesktop"
        "$RegSystem\ConsentPromptBehaviorAdmin"
        "$RegSystem\ConsentPromptBehaviorUser"
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
        "$RegLsa\LimitBlankPasswordUse"
        "$RegLsa\FipsAlgorithmPolicy\Enabled"
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        "$RegSchannel\TLS 1.0\Server\Enabled"
        "$RegSchannel\TLS 1.0\Client\Enabled"
        "$RegSchannel\TLS 1.1\Server\Enabled"
        "$RegSchannel\TLS 1.1\Client\Enabled"
        "$RegRemovable\Deny_All"
        "$RegRemovable\$RemovableDiskClass\Deny_Write"
        "$RegExplorer\NoDriveTypeAutoRun"
        "$RegExplorer\NoAutorun"
        "$RegExplorerPolicy\NoAutoplayfornonVolume"
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize'
        'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type'
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start'
    )
}

function Get-CollectionTarget {
    # What the collectors read: the named checks' registry values plus every
    # registry value, service and optional feature any catalog expects, so one
    # snapshot serves every framework. Registry targets keep path and value name
    # apart, because a value name can hold a backslash (\\*\NETLOGON).
    param([object[]]$Catalogs, $Thresholds)
    $registry = [ordered]@{}
    foreach ($k in Get-RegistryTarget) {
        $i = $k.LastIndexOf('\')
        $registry[$k] = [pscustomobject]@{ Path = $k.Substring(0, $i); Name = $k.Substring($i + 1) }
    }
    $services = [Collections.Generic.List[string]]::new()
    foreach ($n in @(@($Thresholds.NonessentialServices) + 'W32Time')) { if (-not $services.Contains($n)) { $services.Add($n) } }
    $features = [Collections.Generic.List[string]]::new()
    foreach ($c in $Catalogs) {
        foreach ($r in @($c.Requirements)) {
            if (-not $r.Contains('Expect')) { continue }
            foreach ($e in @($r.Expect)) {
                switch ("$($e.Source)") {
                    'Registry' { $registry["$($e.Path)\$($e.Name)"] = [pscustomobject]@{ Path = $e.Path; Name = $e.Name } }
                    'Service' { if (-not $services.Contains($e.Name)) { $services.Add($e.Name) } }
                    'Feature' { if (-not $features.Contains($e.Name)) { $features.Add($e.Name) } }
                }
            }
        }
    }
    [pscustomobject]@{ Registry = $registry; Services = @($services); Features = @($features) }
}

$AuditBits = @{ Success = 1; Failure = 2; SuccessAndFailure = 3 }
$AuditNames = @{ 0 = 'No Auditing'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }

# Advanced audit subcategories by English name. auditpol records them by GUID,
# so matching on the GUID works on any Windows display language.
$AuditGuidSuffix = '-69AE-11D9-BED3-505054503030}'
$AuditSubcategoryGuid = @{}
foreach ($pair in @(
        @('Security State Change', '10'), @('Security System Extension', '11'), @('System Integrity', '12'),
        @('IPsec Driver', '13'), @('Other System Events', '14'), @('Logon', '15'), @('Logoff', '16'),
        @('Account Lockout', '17'), @('Special Logon', '1B'), @('Other Logon/Logoff Events', '1C'),
        @('File System', '1D'), @('Registry', '1E'), @('File Share', '24'), @('Other Object Access Events', '27'),
        @('Sensitive Privilege Use', '28'), @('Process Creation', '2B'), @('Audit Policy Change', '2F'),
        @('Authentication Policy Change', '30'), @('Authorization Policy Change', '31'),
        @('MPSSVC Rule-Level Policy Change', '32'), @('Other Policy Change Events', '34'),
        @('User Account Management', '35'), @('Computer Account Management', '36'),
        @('Security Group Management', '37'), @('Credential Validation', '3F'), @('Detailed File Share', '44'),
        @('Removable Storage', '45'), @('Plug and Play Events', '48'), @('Group Membership', '49'),
        @('Other Account Management Events', '3A'), @('Directory Service Access', '3B'),
        @('Directory Service Changes', '3C'))) {
    $AuditSubcategoryGuid[$pair[0]] = "{0CCE92$($pair[1])$AuditGuidSuffix"
}

function Test-AuditSubcategory {
    # Each required subcategory (Name, Setting) must include the required bits.
    # Returns a result.
    param($Snapshot, [object[]]$Required)
    $ap = Get-Prop $Snapshot 'AuditPolicy'
    $short = @()
    $ok = @()
    foreach ($r in $Required) {
        $guid = $AuditSubcategoryGuid["$($r.Name)"]
        if ($null -eq $guid) { throw "Unknown audit subcategory '$($r.Name)'." }
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

        'AC-UacPromptBehavior' = @{
            Title = 'Elevation prompts are never skipped'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                # Admin: 0 elevates without asking. User: 0 denies, 1 and 3 ask for credentials.
                $admin = Get-RegSetting $S @("$RegSystem\ConsentPromptBehaviorAdmin") -Default 5
                $user = Get-RegSetting $S @("$RegSystem\ConsentPromptBehaviorUser") -Default 3
                $ev = (Format-Setting $admin 'ConsentPromptBehaviorAdmin') + '; ' + (Format-Setting $user 'ConsentPromptBehaviorUser')
                $bad = @()
                if ("$($admin.Value)" -notin @($T.UacAdminPromptValues | ForEach-Object { "$_" })) {
                    $bad += 'admin prompt allowed: ' + (@($T.UacAdminPromptValues) -join ', ')
                }
                if ("$($user.Value)" -notin @($T.UacUserPromptValues | ForEach-Object { "$_" })) {
                    $bad += 'user prompt allowed: ' + (@($T.UacUserPromptValues) -join ', ')
                }
                if ($bad.Count -gt 0) { return New-CheckResult Fail "$ev; $($bad -join '; ')." }
                New-CheckResult Pass $ev
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
                $req = @($T.AuditSubcategories | Where-Object { $_.Name -eq 'Sensitive Privilege Use' })
                if ($req.Count -eq 0) { $req = @(@{ Name = 'Sensitive Privilege Use'; Setting = 'SuccessAndFailure' }) }
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

        'CM-AutoplayDisabled' = @{
            Title = 'Autorun and AutoPlay are off for every drive type'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $types = Get-RegSetting $S @("$RegExplorer\NoDriveTypeAutoRun") -Default 145
                $autorun = Get-RegSetting $S @("$RegExplorer\NoAutorun")
                $nonVolume = Get-RegSetting $S @("$RegExplorerPolicy\NoAutoplayfornonVolume")
                $ev = @((Format-Setting $types 'NoDriveTypeAutoRun'), (Format-Setting $autorun 'NoAutorun'),
                    (Format-Setting $nonVolume 'NoAutoplayfornonVolume')) -join '; '
                if ("$($types.Value)" -eq '255' -and "$($autorun.Value)" -eq '1' -and "$($nonVolume.Value)" -eq '1') {
                    return New-CheckResult Pass $ev
                }
                New-CheckResult Fail "$ev; needs 255, 1 and 1."
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

        'IA-BlankPasswordConsoleOnly' = @{
            Title = 'Accounts with blank passwords can log on only at the console'
            Needs = @('Registry')
            Test  = {
                param($S, $T)
                $v = Get-RegSetting $S @("$RegLsa\LimitBlankPasswordUse") -Default 1
                $ev = Format-Setting $v 'LimitBlankPasswordUse'
                if ("$($v.Value)" -eq '1') { return New-CheckResult Pass $ev }
                New-CheckResult Fail $ev
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
                $third = @(Get-ThirdPartyAvProduct $S | Where-Object { $_.Enabled })
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
                $third = @(Get-ThirdPartyAvProduct $S | Where-Object { $_.Enabled })
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
                $third = @(Get-ThirdPartyAvProduct $S | Where-Object { $_.Enabled })
                if ($third.Count -gt 0) {
                    return New-CheckResult Manual ('Third-party antivirus: ' + (($third | ForEach-Object { $_.DisplayName }) -join ', ')) 'Scan history is in that product''s console.'
                }
                New-CheckResult Fail 'No active antivirus to report scans.'
            }
        }
    }
}

function Get-ThirdPartyAvProduct {
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
    # Skipped or Error, and a Test that throws becomes Error. The Test gets the
    # definition too, which is how an expectation reaches its Test.
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
            $result = & $Definition.Test $Snapshot $Thresholds $Definition
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

#region Expectations

# The snapshot section each expectation source reads.
$ExpectSection = @{
    Registry = 'Registry'; SecPol = 'SecurityPolicy'; Audit = 'AuditPolicy'; UserRight = 'UserRights'
    Service = 'Services'; Feature = 'Features'
}

# Feature states that leave the feature in place, now or until a restart.
$FeatureOnStates = @('Enabled', 'EnablePending', 'DisablePending', 'Installed', 'InstallPending', 'UninstallPending')

# Well-known SIDs for the identities UserRight expectations name, so matching
# works in any display language. '*' is the domain part of a domain-relative
# SID. An identity not listed is matched by account name.
$IdentitySid = @{
    'Administrators'                                   = 'S-1-5-32-544'
    'Users'                                            = 'S-1-5-32-545'
    'Guests'                                           = 'S-1-5-32-546'
    'Remote Desktop Users'                             = 'S-1-5-32-555'
    'Service'                                          = 'S-1-5-6'
    'Enterprise Domain Controllers'                    = 'S-1-5-9'
    'Authenticated Users'                              = 'S-1-5-11'
    'Local Service'                                    = 'S-1-5-19'
    'Network Service'                                  = 'S-1-5-20'
    'Local account'                                    = 'S-1-5-113'
    'Local account and member of Administrators group' = 'S-1-5-114'
    'NT Virtual Machine\Virtual Machines'              = 'S-1-5-83-0'
    'Domain Admins'                                    = 'S-1-5-21-*-512'
    'Enterprise Admins'                                = 'S-1-5-21-*-519'
}

function Get-ExpectLabel {
    # Short name for an expectation in the Checks column. Never holds '=' or ';'.
    param($Expect)
    switch ("$($Expect.Source)") {
        'Audit' { return "Audit:$($Expect.Subcategory)/$($Expect.Setting)" }
        default { return "$($Expect.Source):$($Expect.Name)" }
    }
}

function ConvertTo-Comparable {
    # Values compare as text, case and spacing ignored. A DWORD the registry API
    # returned as a negative Int32 compares as the unsigned value Windows shows.
    param($Value)
    if ($Value -is [int] -and $Value -lt 0) { $Value = [int64]$Value + 4294967296 }
    return ("$Value" -replace '\s', '').ToLowerInvariant()
}

function ConvertTo-Number {
    param($Value)
    if ($Value -is [int] -and $Value -lt 0) { return [double]([int64]$Value + 4294967296) }
    $n = 0.0
    if ([double]::TryParse("$Value", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return $n }
    return $null
}

function Format-Expectation {
    param($Expect)
    $text = switch ("$($Expect.Op)") {
        'eq' { "$($Expect.Value)" }
        'ne' { "anything but '$($Expect.Value)'" }
        'ge' { "$($Expect.Value) or more" }
        'between' { "$($Expect.Min) to $($Expect.Max)" }
        'in' { 'one of ' + (@($Expect.Values) -join ', ') }
        'notempty' { 'a value' }
        default { throw "Unknown Op '$($Expect.Op)'; use eq, ne, ge, between, in or notempty." }
    }
    if ($Expect.Contains('Also')) { $text += ' (or ' + (@($Expect.Also) -join ', ') + ')' }
    return $text
}

function Test-ExpectValue {
    # True when $Actual meets the expectation's Op.
    param($Actual, $Expect)
    if ($Expect.Contains('Also')) {
        foreach ($a in @($Expect.Also)) { if ((ConvertTo-Comparable $Actual) -eq (ConvertTo-Comparable $a)) { return $true } }
    }
    switch ("$($Expect.Op)") {
        'eq' { return (ConvertTo-Comparable $Actual) -eq (ConvertTo-Comparable $Expect.Value) }
        'ne' { return (ConvertTo-Comparable $Actual) -ne (ConvertTo-Comparable $Expect.Value) }
        'ge' {
            $n = ConvertTo-Number $Actual
            return $null -ne $n -and $n -ge [double]$Expect.Value
        }
        'between' {
            $n = ConvertTo-Number $Actual
            return $null -ne $n -and $n -ge [double]$Expect.Min -and $n -le [double]$Expect.Max
        }
        'in' {
            foreach ($v in @($Expect.Values)) { if ((ConvertTo-Comparable $Actual) -eq (ConvertTo-Comparable $v)) { return $true } }
            return $false
        }
        'notempty' { return "$Actual".Trim() -ne '' }
        default { throw "Unknown Op '$($Expect.Op)'; use eq, ne, ge, between, in or notempty." }
    }
}

function Format-Identity {
    # An assigned identity as the evidence shows it: its name, or its SID when
    # the name didn't resolve.
    param($Entry)
    if ("$($Entry.Name)") { return "$($Entry.Name)" }
    return "$($Entry.Sid)"
}

function Test-IdentityMatch {
    # True when an assigned entry (Sid, Name) is one of the catalog identities.
    param($Entry, [string[]]$Identity)
    foreach ($i in $Identity) {
        $sid = $IdentitySid[$i]
        if ($sid -and "$($Entry.Sid)") {
            if ("$($Entry.Sid)" -like $sid) { return $true }
            continue
        }
        $name = "$($Entry.Name)"
        if ($name -eq $i -or $name.EndsWith("\$i", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-UserRight {
    # Op 'only': everyone holding the right is in Identities (empty: no one may).
    # Op 'includes': each of Identities holds it. 'A|B' in Identities means
    # either. Domain groups aren't required of a machine outside a domain.
    param($Snapshot, $Expect)
    $rights = Get-Prop $Snapshot 'UserRights'
    $assigned = @()
    if (Test-Prop $rights $Expect.Name) { $assigned = @(@(Get-Prop $rights $Expect.Name) | Where-Object { $null -ne $_ }) }
    $held = @($assigned | ForEach-Object { Format-Identity $_ })
    $ev = "$($Expect.Name) is assigned to " + $(if ($held.Count -gt 0) { $held -join ', ' } else { 'no one' })
    $wanted = @($Expect.Identities | Where-Object { "$_" -ne '' })
    switch ("$($Expect.Op)") {
        'only' {
            $allowed = @($wanted | ForEach-Object { "$_" -split '\|' })
            $extra = @($assigned | Where-Object { -not (Test-IdentityMatch $_ $allowed) } | ForEach-Object { Format-Identity $_ })
            if ($extra.Count -eq 0) { return New-CheckResult Pass "$ev." }
            $limit = if ($allowed.Count -gt 0) { 'only ' + ($allowed -join ', ') } else { 'no one' }
            return New-CheckResult Fail "$ev; allowed: $limit."
        }
        'includes' {
            $inDomain = Get-Prop (Get-Prop $Snapshot 'Meta') 'PartOfDomain'
            if ($null -eq $inDomain) { throw 'Snapshot has no Meta.PartOfDomain.' }
            $missing = @()
            $waived = @()
            foreach ($w in $wanted) {
                $alts = @("$w" -split '\|')
                if (-not $inDomain) {
                    $local = @($alts | Where-Object { -not "$($IdentitySid[$_])".Contains('*') })
                    if ($local.Count -eq 0) { $waived += $w; continue }
                    $alts = $local
                }
                if (@($assigned | Where-Object { Test-IdentityMatch $_ $alts }).Count -eq 0) { $missing += ($alts -join ' or ') }
            }
            if ($missing.Count -gt 0) { return New-CheckResult Fail "$ev; missing: $($missing -join ', ')." }
            if ($waived.Count -gt 0) { return New-CheckResult Pass "$ev; $($waived -join ' and ') not required outside a domain." }
            return New-CheckResult Pass "$ev."
        }
        default { throw "Unknown UserRight Op '$($Expect.Op)'; use only or includes." }
    }
}

function Test-Expectation {
    # Judges one catalog expectation against the snapshot. Returns a result.
    param($Snapshot, $Expect)
    switch ("$($Expect.Source)") {
        'Registry' {
            $f = Get-RegFact $Snapshot "$($Expect.Path)\$($Expect.Name)"
            if (Get-Prop $f 'Denied') { return New-CheckResult Skipped "$($Expect.Name) is not readable without elevation." }
            if (-not (Get-Prop $f 'Present')) {
                if ($Expect.Contains('AbsentOk') -and $Expect.AbsentOk) { return New-CheckResult Pass "$($Expect.Name) not set, which is allowed." }
                return New-CheckResult Fail "$($Expect.Name) not set; needs $(Format-Expectation $Expect)."
            }
            $actual = Get-Prop $f 'Value'
            $label = $Expect.Name
        }
        'SecPol' {
            $actual = Get-SecPolValue $Snapshot $Expect.Name
            if ($null -eq $actual) { return New-CheckResult Fail "$($Expect.Name) is not defined in the security policy; needs $(Format-Expectation $Expect)." }
            $label = $Expect.Name
        }
        'Audit' {
            return Test-AuditSubcategory $Snapshot @(@{ Name = $Expect.Subcategory; Setting = $Expect.Setting })
        }
        'UserRight' {
            return Test-UserRight $Snapshot $Expect
        }
        'Service' {
            $svc = Get-Prop (Get-Prop $Snapshot 'Services') $Expect.Name
            if ($null -eq $svc) { throw "Service '$($Expect.Name)' was not collected." }
            if (-not $svc.Present) { return New-CheckResult Pass "Service $($Expect.Name) is not installed." }
            $ev = "Service $($Expect.Name) is $($svc.StartType)"
            if ("$($svc.StartType)" -eq "$($Expect.StartType)") { return New-CheckResult Pass "$ev." }
            return New-CheckResult Fail "$ev; needs $($Expect.StartType)."
        }
        'Feature' {
            if ("$($Expect.State)" -ne 'Disabled') { throw "Feature expectations take State = 'Disabled', not '$($Expect.State)'." }
            $feat = Get-Prop (Get-Prop $Snapshot 'Features') $Expect.Name
            if ($null -eq $feat) { throw "Feature '$($Expect.Name)' was not collected." }
            if (-not $feat.Present) { return New-CheckResult Pass "Feature $($Expect.Name) is not offered on this Windows build." }
            # Disabled, DisabledWithPayloadRemoved, Available and Removed all pass.
            if ("$($feat.State)" -in $FeatureOnStates) {
                return New-CheckResult Fail "Feature $($Expect.Name) is $($feat.State); needs it disabled or removed."
            }
            return New-CheckResult Pass "Feature $($Expect.Name) is $($feat.State)."
        }
        default { throw "Unknown expectation source '$($Expect.Source)'." }
    }
    $ev = "$label = $actual"
    if (Test-ExpectValue $actual $Expect) { return New-CheckResult Pass $ev }
    return New-CheckResult Fail "$ev; needs $(Format-Expectation $Expect)."
}

function Invoke-Expectation {
    # Runs one expectation through Invoke-Check, so a section that wasn't
    # collected is Skipped or Error exactly as it is for a named check.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'The Test takes the same (snapshot, thresholds, definition) arguments as every check; expectations have no threshold.')]
    param($Expect, $Snapshot)
    $label = Get-ExpectLabel $Expect
    $section = $ExpectSection["$($Expect.Source)"]
    $definition = @{
        Title  = $label
        Expect = $Expect
        Test   = { param($S, $T, $D) Test-Expectation $S $D.Expect }
    }
    if ($section) { $definition.Needs = @($section) }
    Invoke-Check -Name $label -Definition $definition -Snapshot $Snapshot -Thresholds $null
}

#endregion

#region Frameworks

function Import-CatalogFile {
    # Reads a catalog as data. Import-PowerShellDataFile stops at a node limit the
    # STIG catalog exceeds, and Windows PowerShell 5.1 has no -SkipLimitCheck, so
    # the file is checked against the restricted language (literals, arrays and
    # hashtables; no commands, no variables but $true, $false and $null) and only
    # then run.
    param([string]$Path)
    $block = [scriptblock]::Create([IO.File]::ReadAllText($Path))
    $block.CheckRestrictedLanguage([string[]]@(), [string[]]@(), $false)
    $data = & $block
    if ($data -isnot [hashtable]) { throw "$Path does not hold a single hashtable." }
    return $data
}

function Get-FrameworkCatalog {
    # Every catalog in the frameworks folder, sorted by Id.
    param([string]$Folder)
    $files = @(Get-ChildItem -LiteralPath $Folder -Filter '*.psd1' -File | Sort-Object Name)
    if ($files.Count -eq 0) { throw "No framework catalogs in $Folder." }
    @(foreach ($f in $files) {
        $c = Import-CatalogFile $f.FullName
        $c.File = $f.BaseName
        $c
    }) | Sort-Object { $_.Id }
}

function Format-FrameworkList {
    param([object[]]$Catalogs)
    (@($Catalogs | ForEach-Object {
        '  {0,-20} {1} (levels: {2})' -f $_.Id, $_.Name, (@($_.Levels) -join ', ')
    }) -join [Environment]::NewLine)
}

function Resolve-Framework {
    # A catalog by Id or file name, ignoring case.
    param([object[]]$Catalogs, [string]$Name)
    if (-not $Name) {
        throw ("Choose a framework with -Framework. Available:" + [Environment]::NewLine + (Format-FrameworkList $Catalogs))
    }
    $hit = @($Catalogs | Where-Object { $_.Id -eq $Name -or $_.File -eq $Name })
    if ($hit.Count -eq 0) {
        throw ("Unknown framework '$Name'. Available:" + [Environment]::NewLine + (Format-FrameworkList $Catalogs))
    }
    return $hit[0]
}

function Resolve-FrameworkLevel {
    # The framework's spelling of -Level; the highest level when none is given.
    # A bare number n also matches level Ln, so CMMC takes -Level 2.
    param($Catalog, [string]$Level)
    $levels = @($Catalog.Levels)
    if (-not $Level) { return $levels[-1] }
    foreach ($l in $levels) {
        if ($l -eq $Level -or ($Level -match '^\d+$' -and $l -eq "L$Level")) { return $l }
    }
    throw "Level '$Level' is not one of $($Catalog.Id)'s levels: $($levels -join ', ')."
}

function Format-RequirementReference {
    # The ID a report shows, from the catalog's PracticeFormat, such as
    # '{Family}.{Level}-{Id}' for CMMC (AC.L2-3.1.8). Default: the Id.
    param($Catalog, $Requirement)
    $format = '{Id}'
    if ($Catalog.Contains('PracticeFormat') -and $Catalog.PracticeFormat) { $format = $Catalog.PracticeFormat }
    return $format.Replace('{Family}', "$($Requirement.Family)").Replace('{Level}', "$($Requirement.Level)").Replace('{Id}', "$($Requirement.Id)")
}

$ProductTypeName = @{ 1 = 'client Windows'; 2 = 'a domain controller'; 3 = 'Windows Server (not a domain controller)' }

function Get-PlatformMismatch {
    # Why the snapshot's Windows isn't the one the catalog's AppliesTo names, or
    # $null when it is. A catalog without AppliesTo applies to any Windows.
    param($Catalog, $Snapshot)
    if (-not $Catalog.Contains('AppliesTo')) { return $null }
    $a = $Catalog.AppliesTo
    $meta = Get-Prop $Snapshot 'Meta'
    $type = Get-Prop $meta 'ProductType'
    $version = $null
    if (-not [version]::TryParse("$(Get-Prop $meta 'OSVersion')", [ref]$version) -or $null -eq $type) {
        return "$($Catalog.Id) is written for one Windows edition and build, and the snapshot doesn't say which Windows it came from."
    }
    $build = $version.Build
    $want = @()
    $off = $false
    if ($a.Contains('ProductTypes')) {
        $want += (@($a.ProductTypes) | ForEach-Object { $ProductTypeName[[int]$_] }) -join ' or '
        if ([int]$type -notin @($a.ProductTypes)) { $off = $true }
    }
    if ($a.Contains('Builds')) {
        $want += 'build ' + (@($a.Builds) -join ' or ')
        if ($build -notin @($a.Builds)) { $off = $true }
    }
    if ($a.Contains('MinBuild')) {
        $want += "build $($a.MinBuild) or later"
        if ($build -lt [int]$a.MinBuild) { $off = $true }
    }
    if (-not $off) { return $null }
    $have = $ProductTypeName[[int]$type]
    if (-not $have) { $have = "product type $type" }
    return "$($Catalog.Id) is written for $($want -join ', '); $($meta.ComputerName) is $have, build $build. Rules may not fit this Windows; choose the framework written for it."
}

#endregion

function Invoke-ComplianceEvaluation {
    # Judges a snapshot against one framework. Returns the check results and one
    # result per requirement at or under -Level (a level includes the ones
    # listed before it in the catalog).
    param($Snapshot, $Thresholds, $Catalog, [string]$Level)
    $Level = Resolve-FrameworkLevel $Catalog $Level
    $levels = @($Catalog.Levels)
    $cut = [array]::IndexOf($levels, $Level)

    $table = Get-CheckTable
    $checkResults = [ordered]@{}
    foreach ($name in $table.Keys) {
        $checkResults[$name] = Invoke-Check -Name $name -Definition $table[$name] -Snapshot $Snapshot -Thresholds $Thresholds
    }

    $requirements = foreach ($r in @($Catalog.Requirements)) {
        $rank = [array]::IndexOf($levels, "$($r.Level)")
        if ($rank -lt 0) { throw "Catalog entry $($r.Id) has level '$($r.Level)', which is not in Levels." }
        if ($rank -gt $cut) { continue }
        $notes = @()
        if ($r.Contains('Note') -and $r.Note) { $notes += $r.Note }
        $results = @(foreach ($n in @($r.Checks)) {
            if (-not $checkResults.Contains($n)) { throw "Catalog entry $($r.Id) names unknown check '$n'." }
            $checkResults[$n]
        })
        if ($r.Contains('Expect')) {
            $results += @(foreach ($e in @($r.Expect)) { Invoke-Expectation -Expect $e -Snapshot $Snapshot })
        }
        if ($results.Count -eq 0) {
            $state = 'Manual'
            $checks = ''
            $evidence = ''
            $findings = ''
        } else {
            $state = ($results | Sort-Object { $StateRank[$_.State] } | Select-Object -First 1).State
            $checks = ($results | ForEach-Object { "$($_.Check)=$($_.State)" }) -join '; '
            $evidence = ($results | ForEach-Object { "$($_.Check): $($_.Evidence)" }) -join ' | '
            $findings = (@($results | Where-Object { $_.State -notin 'Pass', 'NotApplicable' } |
                ForEach-Object { "$($_.Check): $($_.Evidence)" }) -join ' | ')
            $notes += @($results | Where-Object { $_.Note } | ForEach-Object { $_.Note })
        }
        [pscustomobject]@{
            Requirement = $r.Id
            Reference   = Format-RequirementReference $Catalog $r
            Level       = $r.Level
            Family      = $r.Family
            Title       = $r.Title
            State       = $state
            Checks      = $checks
            Evidence    = $evidence
            Findings    = $findings
            Note        = (@($notes | Select-Object -Unique) -join ' ')
        }
    }

    [pscustomobject]@{
        Framework       = $Catalog.Id
        Level           = $Level
        PlatformWarning = Get-PlatformMismatch $Catalog $Snapshot
        Checks          = @($checkResults.Values)
        Requirements    = @($requirements)
    }
}

function Get-ScanExitCode {
    param([object[]]$Requirements)
    $states = @($Requirements | ForEach-Object { $_.State })
    if ($states -contains 'Error') { return 2 }
    if ($states -contains 'Fail') { return 1 }
    return 0
}

# Which way is stricter, for the warning when a local profile loosens a value a
# framework sets. Keys not listed warn on any change.
$ThresholdDirection = @{
    MaxLocalAdmins = 'Max'; LockoutThresholdMax = 'Max'; InactivityLockMaxSeconds = 'Max'; RdpIdleMaxMinutes = 'Max'
    MaxDaysSinceUpdate = 'Max'; MaxSignatureAgeDays = 'Max'; MaxDaysSinceScan = 'Max'
    LockoutDurationMinMinutes = 'Min'; MinPasswordLength = 'Min'; MinPasswordHistory = 'Min'; MinSecurityLogMB = 'Min'
}

function Get-ScanThreshold {
    # The example thresholds, then the framework's, then -ProfilePath (or
    # ComplianceScan.local.psd1). Warns when the profile loosens a framework value.
    [CmdletBinding()]
    param([string]$ExamplePath, $Catalog, [string]$OverridePath)
    $t = Import-PowerShellDataFile -LiteralPath $ExamplePath
    $fromFramework = @{}
    if ($Catalog -and $Catalog.Contains('Thresholds')) { $fromFramework = $Catalog.Thresholds }
    foreach ($k in @($fromFramework.Keys)) {
        if (-not $t.ContainsKey($k)) { throw "Framework $($Catalog.Id) sets unknown threshold '$k'." }
        $t[$k] = $fromFramework[$k]
    }
    if ($OverridePath) {
        $o = Import-PowerShellDataFile -LiteralPath $OverridePath
        foreach ($k in @($o.Keys)) {
            if (-not $t.ContainsKey($k)) { Write-Warning "Unknown threshold '$k' in $OverridePath is ignored." ; continue }
            if ($fromFramework.ContainsKey($k)) {
                $fw = $fromFramework[$k]
                $mine = $o[$k]
                $looser = switch ($ThresholdDirection[$k]) {
                    'Max' { [double]$mine -gt [double]$fw }
                    'Min' { [double]$mine -lt [double]$fw }
                    default { (@($mine) -join ',') -ne (@($fw) -join ',') }
                }
                if ($looser) {
                    Write-Warning "$OverridePath sets $k = $(@($mine) -join ', '), looser than or different from $($Catalog.Id)'s $(@($fw) -join ', '). The report uses your value."
                }
            }
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
    # Fills one snapshot section. A collector throws PlatformNotSupportedException
    # when the section has no meaning on this kind of Windows (NotApplicable),
    # NotSupportedException when its source doesn't exist on this machine
    # (Skipped); anything else is Error.
    param($Snapshot, [string]$Name, [bool]$Elevated, [switch]$RequiresAdmin, [scriptblock]$Script)
    if ($RequiresAdmin -and -not $Elevated) {
        $Snapshot.Collection[$Name] = [ordered]@{ Status = 'Skipped'; Reason = 'Needs an elevated session.' }
        $Snapshot[$Name] = $null
        return
    }
    try {
        $Snapshot[$Name] = & $Script
        $Snapshot.Collection[$Name] = [ordered]@{ Status = 'Ok'; Reason = '' }
    } catch [System.PlatformNotSupportedException] {
        Write-Verbose "Collector $Name not applicable: $($_.Exception.Message)"
        $Snapshot[$Name] = $null
        $Snapshot.Collection[$Name] = [ordered]@{ Status = 'NotApplicable'; Reason = $_.Exception.Message }
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
    param([string]$Path, [string]$Name)
    $hiveName, $sub = $Path -split ':\\', 2
    $hive = if ($hiveName -eq 'HKCU') { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
    try {
        $k = $hive.OpenSubKey($sub)
    } catch [System.Security.SecurityException] {
        Write-Verbose "Registry key $sub not readable: $($_.Exception.Message)"
        return [ordered]@{ Present = $false; Value = $null; Denied = $true }
    }
    if ($null -eq $k) { return [ordered]@{ Present = $false; Value = $null; Denied = $false } }
    try {
        $v = $k.GetValue($Name)
    } finally { $k.Close() }
    if ($null -eq $v) { return [ordered]@{ Present = $false; Value = $null; Denied = $false } }
    if ($v -is [string[]]) { $v = $v -join "`n" }
    if ($v -is [byte[]]) { $v = [BitConverter]::ToString($v) }
    return [ordered]@{ Present = $true; Value = $v; Denied = $false }
}

function Read-SecurityTemplate {
    # Exports the given secedit areas and returns each [section] as an ordered
    # dictionary of name = raw value.
    param([string[]]$Area, [string]$TempFolder)
    $tmp = Join-Path $TempFolder ("compliance-secedit-{0}.inf" -f [guid]::NewGuid())
    try {
        $null = & secedit.exe /export /cfg $tmp /areas @Area /quiet
        if ($LASTEXITCODE -ne 0) { throw "secedit /export /areas $($Area -join ' ') exited with $LASTEXITCODE." }
        $sections = [ordered]@{}
        $current = $null
        foreach ($line in Get-Content -LiteralPath $tmp -Encoding Unicode) {
            if ($line -match '^\[(.+)\]$') {
                $current = [ordered]@{}
                $sections[$Matches[1]] = $current
                continue
            }
            if ($null -ne $current -and $line -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') { $current[$Matches[1]] = $Matches[2] }
        }
        return $sections
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function ConvertTo-IdentityEntry {
    # One [Privilege Rights] entry: '*S-1-5-32-544' for an account secedit
    # resolved to a SID, or a bare name it couldn't. Both become Sid and Name; an
    # account that no longer resolves keeps an empty Sid or Name.
    param([string]$Item)
    $sid = ''
    $name = ''
    if ($Item.StartsWith('*')) {
        $sid = $Item.Substring(1)
        try {
            $name = ([Security.Principal.SecurityIdentifier]::new($sid)).Translate([Security.Principal.NTAccount]).Value
        } catch {
            Write-Verbose "SID $sid does not resolve to a name: $($_.Exception.Message)"
        }
    } else {
        $name = $Item
        try {
            $sid = ([Security.Principal.NTAccount]::new($Item)).Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            Write-Verbose "Account '$Item' does not resolve to a SID: $($_.Exception.Message)"
        }
    }
    [ordered]@{ Sid = $sid; Name = $name }
}

function Get-EndpointSnapshot {
    # Collects every fact the checks and catalogs read (see Get-CollectionTarget). Read-only.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Targets',
        Justification = 'Used inside the collector script blocks, which the rule does not follow.')]
    param($Targets)
    $elevated = Test-Elevated
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $snap = [ordered]@{
        SchemaVersion = $SnapshotSchemaVersion
        Meta          = [ordered]@{
            Tool         = 'endpoint-compliance-scan'
            Version      = $ComplianceScanVersion
            ComputerName = $env:COMPUTERNAME
            CollectedUtc = ConvertTo-IsoDate (Get-Date)
            IsElevated   = $elevated
            PSVersion    = "$($PSVersionTable.PSVersion)"
            OSCaption    = "$($os.Caption)"
            OSVersion    = "$($os.Version)"
            ProductType  = [int]$os.ProductType
            PartOfDomain = [bool]$cs.PartOfDomain
        }
        Collection    = [ordered]@{}
    }
    $tmpDir = [IO.Path]::GetTempPath()

    Invoke-Collector $snap 'SecurityPolicy' $elevated -RequiresAdmin {
        # Kerberos Policy is exported only on a domain controller.
        $template = Read-SecurityTemplate -Area SECURITYPOLICY -TempFolder $tmpDir
        $out = [ordered]@{}
        foreach ($section in 'System Access', 'Kerberos Policy') {
            if (-not $template.Contains($section)) { continue }
            foreach ($key in @($template[$section].Keys)) {
                $raw = "$($template[$section][$key])".Trim('"')
                $n = 0
                if ([int]::TryParse($raw, [ref]$n)) { $out[$key] = $n } else { $out[$key] = $raw }
            }
        }
        $out
    }

    Invoke-Collector $snap 'UserRights' $elevated -RequiresAdmin {
        # A right nobody holds is left out of the export, and so out of the snapshot.
        $template = Read-SecurityTemplate -Area USER_RIGHTS -TempFolder $tmpDir
        $out = [ordered]@{}
        if ($template.Contains('Privilege Rights')) {
            $rights = $template['Privilege Rights']
            foreach ($right in @($rights.Keys)) {
                $out[$right] = @(foreach ($item in ("$($rights[$right])" -split ',')) {
                    if ($item.Trim() -ne '') { ConvertTo-IdentityEntry $item.Trim() }
                })
            }
        }
        $out
    }

    Invoke-Collector $snap 'AuditPolicy' $elevated -RequiresAdmin {
        $tmp = Join-Path $tmpDir ("compliance-audit-{0}.csv" -f [guid]::NewGuid())
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
        foreach ($key in @($Targets.Registry.Keys)) {
            $t = $Targets.Registry[$key]
            $out[$key] = Read-RegistryValue -Path $t.Path -Name $t.Name
        }
        $out
    }

    Invoke-Collector $snap 'Services' $elevated {
        $out = [ordered]@{}
        foreach ($n in @($Targets.Services)) {
            $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($svc) {
                $out[$n] = [ordered]@{ Present = $true; StartType = "$($svc.StartType)"; Status = "$($svc.Status)" }
            } else {
                $out[$n] = [ordered]@{ Present = $false; StartType = ''; Status = '' }
            }
        }
        $out
    }

    Invoke-Collector $snap 'Features' $elevated -RequiresAdmin {
        # Optional features (DISM) on every Windows, plus roles and features
        # (ServerManager) on Windows Server, where the Server STIGs name them.
        $all = @{}
        $hasOptional = [bool](Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)
        if (-not $hasOptional -and $snap.Meta.ProductType -eq 1) {
            throw [System.NotSupportedException]::new('Get-WindowsOptionalFeature is not available.')
        }
        if ($hasOptional) {
            foreach ($f in @(Get-WindowsOptionalFeature -Online)) { $all["$($f.FeatureName)"] = "$($f.State)" }
        }
        if ($snap.Meta.ProductType -ne 1) {
            # PowerShell 7 loads ServerManager through its Windows PowerShell
            # compatibility session and warns that it does; the warning is expected.
            Import-Module ServerManager -ErrorAction Stop -WarningAction SilentlyContinue -Verbose:$false
            foreach ($f in @(Get-WindowsFeature)) { $all["$($f.Name)"] = "$($f.InstallState)" }
        }
        $out = [ordered]@{}
        foreach ($n in @($Targets.Features)) {
            if ($all.ContainsKey($n)) {
                $out[$n] = [ordered]@{ Present = $true; State = $all[$n] }
            } else {
                $out[$n] = [ordered]@{ Present = $false; State = '' }
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
        if ($snap.Meta.ProductType -eq 2) {
            throw [System.PlatformNotSupportedException]::new('A domain controller has no local accounts; review domain accounts in Active Directory.')
        }
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
    param($Evaluation, $Snapshot, $Catalog)
    $reqs = @($Evaluation.Requirements)
    $meta = Get-Prop $Snapshot 'Meta'
    Write-Host ''
    $when = (ConvertTo-DateValue $meta.CollectedUtc).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
    Write-Host "Endpoint compliance scan ${ComplianceScanVersion}: $($Catalog.Name), level $($Evaluation.Level), $($meta.ComputerName), collected $when UTC"
    if (-not $Catalog.Complete) {
        Write-Host 'This catalog lists only the requirements an endpoint can show evidence for; the rest of the framework is assessed elsewhere.' -ForegroundColor Yellow
    }
    if ($Evaluation.PlatformWarning) { Write-Host $Evaluation.PlatformWarning -ForegroundColor Yellow }
    if (-not $meta.IsElevated) { Write-Host 'Not elevated: checks that need elevation are Skipped.' -ForegroundColor Yellow }
    $order = 'Fail', 'Error', 'Skipped', 'Manual', 'Pass', 'NotApplicable'
    $counts = foreach ($s in $order) { '{0} {1}' -f @($reqs | Where-Object { $_.State -eq $s }).Count, $s }
    Write-Host ("$($reqs.Count) requirements: " + ($counts -join ', '))
    # Fixed-width rows rather than Format-Table, which renders nothing when the
    # host has no console width (a scheduled task, a CI log).
    $cols = 'Pass', 'Fail', 'Error', 'Skipped', 'Manual', 'NotApplicable'
    $width = [math]::Max(7, (@($reqs | ForEach-Object { "$($_.Family)".Length }) + 0 | Measure-Object -Maximum).Maximum + 1)
    $row = "{0,-$width}{1,6}{2,6}{3,7}{4,9}{5,8}{6,5}"
    Write-Host ($row -f 'Family', 'Pass', 'Fail', 'Error', 'Skipped', 'Manual', 'N/A')
    foreach ($grp in @($reqs | Group-Object Family | Sort-Object Name)) {
        $n = foreach ($c in $cols) { @($grp.Group | Where-Object { $_.State -eq $c }).Count }
        Write-Host ($row -f (@($grp.Name) + $n))
    }
    # Then each requirement that needs attention, with only the evidence that didn't pass.
    $refWidth = [math]::Max(14, (@($reqs | ForEach-Object { "$($_.Reference)".Length }) + 0 | Measure-Object -Maximum).Maximum)
    foreach ($state in 'Fail', 'Error', 'Skipped') {
        $colour = switch ($state) { 'Fail' { 'Red' } 'Error' { 'Magenta' } default { 'Yellow' } }
        foreach ($r in @($reqs | Where-Object { $_.State -eq $state })) {
            Write-Host ("{0,-8} {1,-$refWidth} {2}" -f $state, $r.Reference, $r.Findings) -ForegroundColor $colour
        }
    }
}

function Export-ScanReport {
    param($Evaluation, $Snapshot, $Thresholds, $Catalog, [string]$Folder, [switch]$IncludeSnapshot)
    if (-not (Test-Path -LiteralPath $Folder)) { $null = New-Item -ItemType Directory -Path $Folder }
    $meta = Get-Prop $Snapshot 'Meta'
    $computer = "$($meta.ComputerName)" -replace '[^A-Za-z0-9-]', '_'
    $framework = "$($Catalog.Id)".ToLowerInvariant() -replace '[^a-z0-9.-]', '_'
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $base = Join-Path $Folder "compliance-scan-$framework-$computer-$stamp"

    $Evaluation.Requirements | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8

    $report = [ordered]@{
        Tool            = 'endpoint-compliance-scan'
        Version         = $ComplianceScanVersion
        Framework       = $Catalog.Id
        FrameworkName   = $Catalog.Name
        Source          = $Catalog.Source
        Complete        = [bool]$Catalog.Complete
        Level           = $Evaluation.Level
        PlatformWarning = $Evaluation.PlatformWarning
        ComputerName    = $meta.ComputerName
        CollectedUtc    = $meta.CollectedUtc
        IsElevated      = $meta.IsElevated
        Summary         = [ordered]@{}
        Requirements    = $Evaluation.Requirements
        Checks          = $Evaluation.Checks
        Thresholds      = $Thresholds
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
    $catalogs = @(Get-FrameworkCatalog (Join-Path $root 'frameworks'))
    $catalog = Resolve-Framework $catalogs $Framework
    $Level = Resolve-FrameworkLevel $catalog $Level

    $override = $ProfilePath
    if (-not $override) {
        $local = Join-Path $root 'ComplianceScan.local.psd1'
        if (Test-Path -LiteralPath $local) { $override = $local }
    }
    $thresholds = Get-ScanThreshold -ExamplePath (Join-Path $root 'ComplianceScan.example.psd1') -Catalog $catalog -OverridePath $override
    if ($override) { Write-Verbose "Thresholds: example, then $($catalog.Id), then $override." }

    if ($FromSnapshot) {
        $snapshot = Read-Snapshot $FromSnapshot
    } else {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
            throw 'A live scan needs Windows. Use -FromSnapshot to evaluate a saved snapshot elsewhere.'
        }
        $snapshot = Get-EndpointSnapshot -Targets (Get-CollectionTarget -Catalogs $catalogs -Thresholds $thresholds)
    }
    if ($SnapshotPath) {
        $snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SnapshotPath -Encoding UTF8
    }

    $evaluation = Invoke-ComplianceEvaluation -Snapshot $snapshot -Thresholds $thresholds -Catalog $catalog -Level $Level
    if ($evaluation.PlatformWarning) { Write-Warning $evaluation.PlatformWarning }

    $folder = $OutputPath
    if (-not $folder) { $folder = Join-Path $root 'Reports' }
    $files = Export-ScanReport -Evaluation $evaluation -Snapshot $snapshot -Thresholds $thresholds -Catalog $catalog -Folder $folder -IncludeSnapshot:$IncludeSnapshot

    Write-ScanSummary -Evaluation $evaluation -Snapshot $snapshot -Catalog $catalog
    Write-Host ("Reports: " + ($files -join ', '))
    if ($PassThru) { $evaluation.Requirements }
    $code = Get-ScanExitCode $evaluation.Requirements
} catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    $code = 2
}
exit $code
