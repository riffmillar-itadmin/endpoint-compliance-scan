<#
.SYNOPSIS
    Scans the local Windows endpoint for evidence against one compliance framework,
    chosen at run time: CMMC, NIST SP 800-171 Rev 3, NIST SP 800-53 Rev 5, the DISA
    STIGs for Windows 11 and Windows Server 2019, 2022 and 2025, CIS Controls v8.1,
    NIST CSF 2.0, PCI DSS 4.0.1 or HIPAA.

.DESCRIPTION
    Read-only. The scan changes no setting, writes nothing to the registry and makes
    no network call; on a domain controller it reads Active Directory from itself
    (localhost) over LDAP. Its only side effects are temporary files (the secedit
    and auditpol exports), deleted as soon as they are read, and the report files.

    It works in two stages so that every pass/fail rule can be tested anywhere:
        1. Collect: gather raw facts about the machine into a snapshot.
        2. Evaluate: judge the snapshot against one framework's requirements.
    One snapshot holds the facts for every framework, so a saved snapshot can be
    evaluated against any of them later with -FromSnapshot.

    Each framework is a catalog in the frameworks folder (frameworks/README.md
    describes the format). A requirement gets its evidence from named checks in
    this script, from setting expectations in the catalog (a registry value, a
    security policy value, an audit subcategory, a user right, a service, a
    Windows feature or a directory test), or from both. Its result is the worst of those results:
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

    Writes these files per run into -OutputPath, named by scan ID (computer and
    collection time, UTC) so a shared folder of many machines' reports sorts by
    computer, then time:
        compliance-scan-<scan id>-<framework>.csv           one row per requirement
        compliance-scan-<scan id>-<framework>.json          requirements, checks and thresholds
        compliance-scan-<scan id>-<framework>.records.json  flat records for Power BI
        compliance-scan-<scan id>-<framework>.html          a self-contained report
        compliance-scan-<scan id>-<framework>.cklb          STIG Viewer 3 checklist (STIGs, with -StigPath)
        compliance-scan-<scan id>-<framework>.ckl           STIG Viewer 2 checklist (STIGs, with -StigPath)

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

.PARAMETER StigPath
    The DISA STIG zip from cyber.mil, or the XCCDF file inside it, for the
    framework being scanned. With it, a STIG scan also writes STIG Viewer
    checklists (.cklb for STIG Viewer 3, .ckl for STIG Viewer 2) holding every
    rule's text and the scan's results.

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
    .\Invoke-EndpointComplianceScan.ps1 -Framework DISA-STIG-WS2022-MS -StigPath .\U_MS_Windows_Server_2022_STIG.zip -OutputPath \\fileserver\scans
    Server 2022 member server STIG, with a STIG Viewer checklist, into a shared folder.

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
    0.4.0  2026-10-24  Reports: a self-contained HTML report, flat JSON records
                       for Power BI, and a STIG Viewer checklist (.ckl) with
                       -StigPath. Reports are named by scan ID.
    0.4.1  2026-10-24  STIG Viewer checklist: characters XML can't hold, such as
                       NUL from a registry value, no longer stop the .ckl being
                       written. Registry strings drop trailing NULs.
    0.5.0  2026-10-24  STIG Viewer 3 checklist (.cklb) beside the .ckl, which
                       STIG Viewer 3 doesn't open.
    0.6.0  2026-10-24  Catalog generator tools/Update-FrameworkCatalog.ps1, with
                       pinned sources and failover. The Windows 11 STIG catalog
                       follows DISA's V2R11.
    0.7.0  2026-10-24  Server 2022 and 2025 STIG catalogs follow DISA's V2R11
                       and V1R4. DomainOnly expectations are NotApplicable off
                       a domain.
    0.8.0  2026-10-24  DISA Windows Defender Firewall STIG V2R2. Registry
                       expectations can fall back from the Group Policy value
                       to the local setting (FallbackPath).
    0.8.1  2026-10-25  STIG fixes from a domain controller scan: SMB1 settings
                       are NotApplicable when SMB1 is removed (NotApplicableIf),
                       StandaloneOnly expectations, and DISA's full value lists
                       for diagnostic data, Delivery Optimization and the
                       administrator UAC prompt.
    0.9.0  2026-10-25  DISA Active Directory Domain and Forest STIGs, with a
                       directory collector on domain controllers (ADSI, or the
                       ActiveDirectory module). Snapshot schema 4.
#>

[CmdletBinding()]
param(
    [string]$Framework,
    [string]$Level,
    [string]$OutputPath,
    [string]$ProfilePath,
    [string]$SnapshotPath,
    [string]$FromSnapshot,
    [string]$StigPath,
    [switch]$IncludeSnapshot,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ComplianceScanVersion = '0.9.0'
$SnapshotSchemaVersion = 4

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
            # A waiver's expectations (NotApplicableIf) are read too.
            $all = @(foreach ($e in @($r.Expect)) { $e; if ($e.Contains('NotApplicableIf')) { @($e.NotApplicableIf.Expect) } })
            foreach ($e in $all) {
                switch ("$($e.Source)") {
                    'Registry' {
                        $registry["$($e.Path)\$($e.Name)"] = [pscustomobject]@{ Path = $e.Path; Name = $e.Name }
                        if ($e.Contains('FallbackPath')) { $registry["$($e.FallbackPath)\$($e.Name)"] = [pscustomobject]@{ Path = $e.FallbackPath; Name = $e.Name } }
                    }
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
        @('Directory Service Changes', '3C'), @('Kerberos Service Ticket Operations', '40'),
        @('Kerberos Authentication Service', '42'))) {
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
    Service = 'Services'; Feature = 'Features'; Directory = 'Directory'
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

# Domain functional levels (msDS-Behavior-Version) by Windows Server release.
$DomainModeName = @{ 0 = '2000'; 1 = '2003 interim'; 2 = '2003'; 3 = '2008'; 4 = '2008 R2'; 5 = '2012'; 6 = '2012 R2'; 7 = '2016'; 10 = '2025' }

# trustedDomain attributes (MS-ADTS 6.1.6.7): direction, and the attribute bits
# the AD STIG checks read.
$TrustOutbound = 2
$TrustQuarantined = 0x4          # SID filtering on an external trust
$TrustForestTransitive = 0x8     # a forest trust
$TrustCrossOrganization = 0x10   # selective authentication
$TrustWithinForest = 0x20        # parent-child or tree-root: not a trust the STIG reviews
$TrustTreatAsExternal = 0x40     # SID history enabled on a forest trust

function Format-NameList {
    # Up to 20 names, then a count of the rest.
    param([string[]]$Names)
    $n = @($Names | Where-Object { $_ })
    if ($n.Count -le 20) { return ($n -join ', ') }
    return (($n[0..19] -join ', ') + ", and $($n.Count - 20) more")
}

function Get-DirectoryUser {
    # Enabled user accounts that are members, directly or through nesting, of any
    # of the named groups, once each.
    param($Directory, [string[]]$Group)
    $seen = @{}
    foreach ($g in $Group) {
        $entry = Get-Prop (Get-Prop $Directory 'Groups') $g
        if ($null -eq $entry) { throw "Directory snapshot has no group '$g'." }
        foreach ($u in @(Get-Prop $entry 'Users')) {
            if ($null -eq $u -or -not (Get-Prop $u 'Enabled')) { continue }
            if (-not $seen.ContainsKey("$($u.Sid)")) { $seen["$($u.Sid)"] = $u }
        }
    }
    @($seen.Values | Sort-Object Name)
}

function Get-DirectoryMember {
    # The direct members of one group.
    param($Directory, [string]$Group)
    $entry = Get-Prop (Get-Prop $Directory 'Groups') $Group
    if ($null -eq $entry) { throw "Directory snapshot has no group '$Group'." }
    @(Get-Prop $entry 'Members' | Where-Object { $null -ne $_ })
}

function Test-AdminSeparation {
    # Members of one administrator group who also belong to the others.
    param($Directory, [string]$Group, [string[]]$Others)
    $users = @(Get-DirectoryUser $Directory @($Group))
    $other = @{}
    foreach ($u in @(Get-DirectoryUser $Directory $Others)) { $other["$($u.Sid)"] = $true }
    $both = @($users | Where-Object { $other.ContainsKey("$($_.Sid)") } | ForEach-Object { $_.Name })
    if ($both.Count -gt 0) {
        return New-CheckResult Fail "$Group members also in $($Others -join ', '): $(Format-NameList $both)."
    }
    if ($users.Count -eq 0) { return New-CheckResult Pass "$Group has no enabled members." }
    New-CheckResult Manual "$Group members: $(Format-NameList @($users | ForEach-Object { $_.Name }))." 'None is in another administrator group. Confirm each is a separate account documented with the ISSO.'
}

# Directory tests, by name: each reads the Directory section (and the snapshot,
# for its date) and returns a result.
$PrivilegedGroups = @('Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators')
$DirectoryTest = [ordered]@{
    EnterpriseAdminsSeparate = {
        param($D) Test-AdminSeparation $D 'Enterprise Admins' @('Domain Admins', 'Schema Admins', 'Backup Operators', 'Server Operators')
    }
    DomainAdminsSeparate = {
        param($D) Test-AdminSeparation $D 'Domain Admins' @('Enterprise Admins', 'Backup Operators', 'Server Operators')
    }
    PrivilegedNotDelegated = {
        param($D)
        $users = @(Get-DirectoryUser $D $PrivilegedGroups)
        $bad = @($users | Where-Object { -not (Get-Prop $_ 'NotDelegated') } | ForEach-Object { $_.Name })
        if ($bad.Count -gt 0) { return New-CheckResult Fail "$($bad.Count) of $($users.Count) privileged accounts can be delegated: $(Format-NameList $bad)." }
        New-CheckResult Pass "All $($users.Count) enabled privileged accounts are marked sensitive and cannot be delegated."
    }
    LapsCoverage = {
        param($D)
        $laps = Get-Prop $D 'Laps'
        if ($null -eq $laps) { throw 'Directory snapshot has no Laps.' }
        if ("$($laps.Schema)" -eq 'None') {
            return New-CheckResult Manual 'No LAPS attributes in the schema.' 'Show how local administrator passwords are kept unique on each system.'
        }
        $missing = @(Get-Prop $laps 'Missing' | Where-Object { $_ })
        if ($missing.Count -eq 0) { return New-CheckResult Pass "All $($laps.Computers) enabled computers have a LAPS password ($($laps.Schema))." }
        New-CheckResult Manual "$($missing.Count) of $($laps.Computers) enabled computers have no LAPS password: $(Format-NameList $missing)." 'Each one listed needs another process that keeps its local administrator password unique.'
    }
    SmartCardHashRolling = {
        param($D)
        $mode = [int](Get-Prop $D 'DomainMode')
        if ($mode -lt 7) {
            return New-CheckResult Manual "Domain functional level $($DomainModeName[$mode]) is below 2016." 'Show that NT hashes of smart card accounts are rotated every 60 days.'
        }
        if (Get-Prop $D 'ExpirePasswordsOnSmartCardOnlyAccounts') { return New-CheckResult Pass 'Rolling of expiring NTLM secrets for smart card accounts is enabled.' }
        New-CheckResult Fail 'Rolling of expiring NTLM secrets for smart card accounts is not enabled (msDS-ExpirePasswordsOnSmartCardOnlyAccounts).'
    }
    ProtectedUsers = {
        param($D)
        $mode = [int](Get-Prop $D 'DomainMode')
        if ($mode -lt 6) { return New-CheckResult NotApplicable "Domain functional level $($DomainModeName[$mode]) is below 2012 R2." }
        $sid = "$(Get-Prop $D 'DomainSid')"
        $users = @(Get-DirectoryUser $D @('Enterprise Admins', 'Domain Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators') |
            Where-Object { "$($_.Sid)".StartsWith("$sid-") })
        $out = @($users | Where-Object { -not (Get-Prop $_ 'Protected') } | ForEach-Object { $_.Name })
        if ($out.Count -eq 0) { return New-CheckResult Pass "All $($users.Count) administrative accounts are in Protected Users." }
        if ($out.Count -eq 1) { return New-CheckResult Pass "Only $($out[0]) is outside Protected Users." 'The STIG allows one account outside Protected Users, for availability.' }
        New-CheckResult Fail "$($out.Count) administrative accounts are outside Protected Users: $(Format-NameList $out)." 'The STIG allows one, for availability; service accounts are also exempt.'
    }
    UnconstrainedDelegation = {
        param($D)
        $c = @(Get-Prop $D 'UnconstrainedDelegation' | Where-Object { $_ })
        if ($c.Count -gt 0) { return New-CheckResult Fail "Computers other than domain controllers trusted for unconstrained delegation: $(Format-NameList $c)." }
        New-CheckResult Pass 'No computer other than a domain controller is trusted for unconstrained delegation.'
    }
    DsrmPasswordAge = {
        param($D, $S)
        $last = ConvertTo-DateValue (Get-Prop $D 'DsrmLastSet')
        if ($null -ne $last) {
            $age = Get-SnapshotAge $S $last
            if ($age -le 365) { return New-CheckResult Pass "DSRM password last set $($last.ToString('yyyy-MM-dd')) ($age days before the scan)." }
            return New-CheckResult Fail "DSRM password last set $($last.ToString('yyyy-MM-dd')) ($age days before the scan)."
        }
        $why = if (Get-Prop $D 'DsrmLogReadable') { 'No DSRM password change (event 4794) in the Security log.' } else { 'The Security log was not readable.' }
        New-CheckResult Manual $why 'Show that the DSRM password of each domain controller is changed at least yearly.'
    }
    DomainFunctionalLevel = {
        param($D)
        $mode = [int](Get-Prop $D 'DomainMode')
        $name = if ($DomainModeName.ContainsKey($mode)) { $DomainModeName[$mode] } else { "level $mode" }
        if ($mode -ge 7) { return New-CheckResult Pass "Domain functional level is Windows Server $name." }
        New-CheckResult Fail "Domain functional level is Windows Server $name; needs 2016 or later."
    }
    TrustSidFiltering = {
        param($D)
        $trusts = @(Get-Prop $D 'Trusts' | Where-Object { $null -ne $_ -and -not ([int]$_.Attributes -band $TrustWithinForest) -and ([int]$_.Direction -band $TrustOutbound) })
        if ($trusts.Count -eq 0) { return New-CheckResult NotApplicable 'This domain trusts no other domain or forest.' }
        $bad = @(foreach ($t in $trusts) {
                $a = [int]$t.Attributes
                if ($a -band $TrustForestTransitive) { if ($a -band $TrustTreatAsExternal) { "$($t.Name) (SID history enabled)" } }
                elseif (-not ($a -band $TrustQuarantined)) { "$($t.Name) (SID filtering off)" }
            })
        if ($bad.Count -gt 0) { return New-CheckResult Fail "Trusts that accept SIDs from other domains: $($bad -join ', ')." }
        New-CheckResult Pass "SID filtering is on for every trust: $(Format-NameList @($trusts | ForEach-Object { $_.Name }))."
    }
    SelectiveAuthentication = {
        param($D)
        $forest = @(Get-Prop $D 'Trusts' | Where-Object { $null -ne $_ -and ([int]$_.Attributes -band $TrustForestTransitive) -and ([int]$_.Direction -band $TrustOutbound) })
        if ($forest.Count -eq 0) { return New-CheckResult NotApplicable 'No outgoing forest trust.' }
        $bad = @($forest | Where-Object { -not ([int]$_.Attributes -band $TrustCrossOrganization) } | ForEach-Object { $_.Name })
        if ($bad.Count -gt 0) { return New-CheckResult Fail "Outgoing forest trusts without selective authentication: $($bad -join ', ')." }
        New-CheckResult Pass "Selective authentication is on for every outgoing forest trust."
    }
    PreWindows2000Access = {
        param($D)
        $bad = @(Get-DirectoryMember $D 'Pre-Windows 2000 Compatible Access' | Where-Object { "$($_.Sid)" -in 'S-1-1-0', 'S-1-5-7' } | ForEach-Object { $_.Name })
        if ($bad.Count -gt 0) { return New-CheckResult Fail "Pre-Windows 2000 Compatible Access includes $($bad -join ' and ')." }
        New-CheckResult Pass 'Pre-Windows 2000 Compatible Access includes neither Everyone nor Anonymous Logon.'
    }
    TrustBuildersAndPolicyCreators = {
        param($D)
        $lines = @(foreach ($g in 'Incoming Forest Trust Builders', 'Group Policy Creator Owners') {
                $m = @(Get-DirectoryMember $D $g | ForEach-Object { $_.Name })
                if ($m.Count -gt 0) { "$($g): $(Format-NameList $m)" }
            })
        if ($lines.Count -eq 0) { return New-CheckResult Pass 'Incoming Forest Trust Builders and Group Policy Creator Owners have no members.' }
        New-CheckResult Manual (($lines -join '; ') + '.') 'Each member must be documented as necessary with the ISSO.'
    }
    InterSiteReplication = {
        param($D)
        $sites = [int](Get-Prop $D 'Sites')
        if ($sites -le 1) { return New-CheckResult NotApplicable 'The forest has a single site.' }
        $links = @(Get-Prop $D 'SiteLinks' | Where-Object { $null -ne $_ })
        $slow = @($links | Where-Object { [int]$_.ReplInterval -gt 1440 } | ForEach-Object { "$($_.Name) ($($_.ReplInterval) minutes)" })
        if ($slow.Count -gt 0) { return New-CheckResult Fail "Site links replicating less than daily: $($slow -join ', ')." }
        $scheduled = @($links | Where-Object { Get-Prop $_ 'HasSchedule' } | ForEach-Object { $_.Name })
        if ($scheduled.Count -gt 0) { return New-CheckResult Manual "Site links with a replication schedule: $(Format-NameList $scheduled)." 'Confirm each schedule allows replication at least daily.' }
        New-CheckResult Pass "All $($links.Count) site links replicate at least daily, with no schedule limits."
    }
    DomainControllerCount = {
        param($D)
        $n = [int](Get-Prop $D 'DomainControllers')
        if ($n -ge 2) { return New-CheckResult Pass "$n domain controllers support the domain." }
        New-CheckResult Manual "$n domain controller supports the domain." 'This is a finding unless the domain''s Availability categorization is low.'
    }
    SchemaAdminsEmpty = {
        param($D)
        if (-not (Get-Prop $D 'IsForestRoot')) { return New-CheckResult NotApplicable 'Schema Admins is reviewed in the forest root domain.' }
        $m = @(Get-DirectoryMember $D 'Schema Admins' | ForEach-Object { $_.Name })
        if ($m.Count -gt 0) { return New-CheckResult Fail "Schema Admins members: $(Format-NameList $m)." 'Members are allowed only while schema changes are being made.' }
        New-CheckResult Pass 'Schema Admins has no members.'
    }
    AnonymousForestAccess = {
        param($D)
        $h = "$(Get-Prop $D 'DsHeuristics')"
        if ($h.Length -ge 7 -and $h[6] -eq '2') { return New-CheckResult Fail "dSHeuristics is '$h': anonymous access to forest data is enabled." }
        $shown = if ($h) { "'$h'" } else { 'not set' }
        New-CheckResult Pass "dSHeuristics is $shown; anonymous access to forest data is off."
    }
    ForestRootPdcTime = {
        param($D)
        if (-not ((Get-Prop $D 'IsForestRoot') -and (Get-Prop $D 'IsPdcEmulator'))) {
            return New-CheckResult NotApplicable 'Applies to the PDC emulator of the forest root domain; this domain controller is not it.'
        }
        $t = Get-Prop $D 'TimeSource'
        $type = "$(Get-Prop $t 'Type')"
        $server = "$(Get-Prop $t 'NtpServer')"
        if ($type -ne 'NTP') { return New-CheckResult Fail "Windows Time type is '$type'; needs NTP with an external time source." }
        New-CheckResult Manual "Windows Time type is NTP, server '$server'." 'Confirm the server is an authorized external (DoD) time source.'
    }
    CertificateTemplateApproval = {
        param($D)
        $cs = Get-Prop $D 'CertificateServices'
        if (-not (Get-Prop $cs 'Present')) { return New-CheckResult NotApplicable 'No enterprise certificate authority in the forest.' }
        $always = @('1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0')
        $withSubject = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4')
        $bad = @(foreach ($t in @(Get-Prop $cs 'Templates' | Where-Object { $null -ne $_ })) {
                if (Get-Prop $t 'ManagerApproval') { continue }
                $ekus = @(Get-Prop $t 'Ekus' | Where-Object { $_ })
                if ($ekus.Count -eq 0 -or @($ekus | Where-Object { $always -contains $_ }).Count) { "$($t.Name) (smart card logon, any purpose or no EKU)" }
                elseif ((Get-Prop $t 'SuppliesSubject') -and @($ekus | Where-Object { $withSubject -contains $_ }).Count) { "$($t.Name) (client authentication, subject supplied in the request)" }
            })
        if ($bad.Count -gt 0) { return New-CheckResult Fail "Published templates that need manager approval and don't have it: $($bad -join ', ')." }
        New-CheckResult Pass "Every published template that needs manager approval has it."
    }
}

function Test-Expectation {
    # Judges one catalog expectation against the snapshot. Returns a result.
    param($Snapshot, $Expect)
    $domainOnly = $Expect.Contains('DomainOnly') -and $Expect.DomainOnly
    $standaloneOnly = $Expect.Contains('StandaloneOnly') -and $Expect.StandaloneOnly
    if ($domainOnly -or $standaloneOnly) {
        $inDomain = Get-Prop (Get-Prop $Snapshot 'Meta') 'PartOfDomain'
        if ($null -eq $inDomain) { throw 'Snapshot has no Meta.PartOfDomain.' }
        if ($domainOnly -and -not $inDomain) { return New-CheckResult NotApplicable 'Applies only to domain-joined systems; this one is not joined to a domain.' }
        if ($standaloneOnly -and $inDomain) { return New-CheckResult NotApplicable 'Applies only to systems not joined to a domain; this one is joined to a domain.' }
    }
    if ($Expect.Contains('NotApplicableIf')) {
        # The STIG waives this rule when the other rules it names are met.
        $waiver = $Expect.NotApplicableIf
        $met = @(foreach ($e in @($waiver.Expect)) { Invoke-Expectation -Expect $e -Snapshot $Snapshot })
        if ($met.Count -gt 0 -and @($met | Where-Object { $_.State -ne 'Pass' }).Count -eq 0) {
            $rules = @($waiver.Rules)
            $verb = if ($rules.Count -gt 1) { 'are' } else { 'is' }
            return New-CheckResult NotApplicable "$($rules -join ' and ') $verb met, which the STIG accepts instead."
        }
    }
    switch ("$($Expect.Source)") {
        'Registry' {
            $f = Get-RegFact $Snapshot "$($Expect.Path)\$($Expect.Name)"
            if (Get-Prop $f 'Denied') { return New-CheckResult Skipped "$($Expect.Name) is not readable without elevation." }
            $label = $Expect.Name
            $fallback = $Expect.Contains('FallbackPath')
            if ($fallback -and -not (Get-Prop $f 'Present')) {
                # No Group Policy value under Path, so the local setting applies.
                $f = Get-RegFact $Snapshot "$($Expect.FallbackPath)\$($Expect.Name)"
                if (Get-Prop $f 'Denied') { return New-CheckResult Skipped "$($Expect.Name) (local setting) is not readable without elevation." }
                $label = "$($Expect.Name) (local setting, no policy value)"
            }
            if (-not (Get-Prop $f 'Present')) {
                if ($Expect.Contains('AbsentOk') -and $Expect.AbsentOk) { return New-CheckResult Pass "$($Expect.Name) not set, which is allowed." }
                $where = if ($fallback) { ' by policy or locally' } else { '' }
                return New-CheckResult Fail "$($Expect.Name) not set$where; needs $(Format-Expectation $Expect)."
            }
            $actual = Get-Prop $f 'Value'
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
        'Directory' {
            $d = Get-Prop $Snapshot 'Directory'
            if ($null -eq $d) { throw 'Snapshot has no Directory section.' }
            if (-not $DirectoryTest.Contains("$($Expect.Name)")) { throw "Unknown directory test '$($Expect.Name)'." }
            return & $DirectoryTest["$($Expect.Name)"] $d $Snapshot
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
    if ($v -is [string[]] -or $v -is [string]) { $v = ConvertTo-RegistryText $v }
    if ($v -is [byte[]]) { $v = [BitConverter]::ToString($v) }
    return [ordered]@{ Present = $true; Value = $v; Denied = $false }
}

function ConvertTo-RegistryText {
    # A string value as text. Policy tools can leave NUL characters in a REG_SZ,
    # trailing or as separators, and NUL isn't allowed in XML reports: trailing
    # ones go, embedded ones become line breaks, as REG_MULTI_SZ entries do.
    param([string[]]$Value)
    $lines = @($Value | ForEach-Object { "$_".TrimEnd([char]0) -replace '\x00+', "`n" })
    return ($lines -join "`n")
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

function ConvertTo-SidText {
    # A SID from ADSI (bytes) or the ActiveDirectory module (SecurityIdentifier).
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [byte[]]) { return ([Security.Principal.SecurityIdentifier]::new($Value, 0)).Value }
    return "$Value"
}

function Find-DirectoryObject {
    # One LDAP search of this domain controller, as a table of attribute values
    # (always arrays) per object. ADSI first; the ActiveDirectory module's
    # Get-ADObject when ADSI fails. Both read localhost, never another server.
    param([string]$Base, [string]$Filter, [string[]]$Property, [ValidateSet('Base', 'OneLevel', 'Subtree')][string]$Scope = 'Subtree')
    try {
        $searcher = [DirectoryServices.DirectorySearcher]::new([adsi]"LDAP://localhost/$Base", $Filter, $Property, $Scope)
        $searcher.PageSize = 500
        $found = $searcher.FindAll()
        try {
            @(foreach ($r in $found) {
                    $o = @{}
                    foreach ($p in $Property) { $o[$p] = @($r.Properties[$p.ToLowerInvariant()]) }
                    $o
                })
        } finally { $found.Dispose() }
    } catch {
        Write-Verbose "ADSI search under $Base failed; trying the ActiveDirectory module: $($_.Exception.Message)"
        if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) { throw }
        $script:DirectorySource = 'ActiveDirectory module'
        @(Get-ADObject -Server localhost -SearchBase $Base -LDAPFilter $Filter -SearchScope $Scope -Properties $Property | ForEach-Object {
                $obj = $_
                $o = @{}
                foreach ($p in $Property) { $o[$p] = @(if ($null -ne $obj.$p) { $obj.$p }) }
                $o
            })
    }
}

function Get-DirectoryRoot {
    # The rootDSE naming contexts, from ADSI or the ActiveDirectory module.
    $names = 'defaultNamingContext', 'rootDomainNamingContext', 'configurationNamingContext', 'schemaNamingContext', 'dsServiceName'
    try {
        $root = [adsi]'LDAP://localhost/RootDSE'
        $out = @{}
        foreach ($n in $names) { $out[$n] = "$($root.Properties[$n].Value)" }
        if (-not $out.defaultNamingContext) { throw 'RootDSE returned no naming context.' }
        $out
    } catch {
        Write-Verbose "ADSI rootDSE failed; trying the ActiveDirectory module: $($_.Exception.Message)"
        if (-not (Get-Command Get-ADRootDSE -ErrorAction SilentlyContinue)) { throw }
        $script:DirectorySource = 'ActiveDirectory module'
        $root = Get-ADRootDSE -Server localhost
        $out = @{}
        foreach ($n in $names) { $out[$n] = "$($root.$n)" }
        $out
    }
}

function Get-DirectoryGroup {
    # One group by SID: its direct members and the users in it, nesting included.
    param([string]$Base, [string]$Sid, [string]$ProtectedDn)
    $g = @(Find-DirectoryObject $Base "(&(objectClass=group)(objectSid=$Sid))" @('distinguishedName', 'member'))
    if ($g.Count -eq 0) { return [ordered]@{ Found = $false; Members = @(); Users = @() } }
    $dn = "$($g[0].distinguishedName[0])"
    $members = @(foreach ($m in @($g[0].member)) {
            $o = @(Find-DirectoryObject "$m" '(objectClass=*)' @('sAMAccountName', 'objectSid', 'cn') 'Base')
            if ($o.Count -eq 0) { continue }
            $name = if ($o[0].sAMAccountName.Count) { "$($o[0].sAMAccountName[0])" } else { "$($o[0].cn[0])" }
            [ordered]@{ Name = $name; Sid = ConvertTo-SidText $o[0].objectSid[0] }
        })
    $chain = '1.2.840.113556.1.4.1941'
    $protectedClause = if ($ProtectedDn) { "(memberOf:$($chain):=$ProtectedDn)" } else { '' }
    $protected = @{}
    if ($ProtectedDn) {
        foreach ($u in @(Find-DirectoryObject $Base "(&(objectCategory=person)(objectClass=user)(memberOf:$($chain):=$dn)$protectedClause)" @('objectSid'))) {
            $protected[(ConvertTo-SidText $u.objectSid[0])] = $true
        }
    }
    $users = @(foreach ($u in @(Find-DirectoryObject $Base "(&(objectCategory=person)(objectClass=user)(memberOf:$($chain):=$dn))" @('sAMAccountName', 'objectSid', 'userAccountControl'))) {
            $uac = [int]$u.userAccountControl[0]
            $sid = ConvertTo-SidText $u.objectSid[0]
            [ordered]@{ Name = "$($u.sAMAccountName[0])"; Sid = $sid; Enabled = -not ($uac -band 0x2); NotDelegated = [bool]($uac -band 0x100000); Protected = $protected.ContainsKey($sid) }
        })
    [ordered]@{ Found = $true; Members = $members; Users = $users }
}

function Get-DirectorySnapshot {
    # What the AD Domain and Forest STIG checks read, from the domain controller
    # the scan runs on. Read-only LDAP searches.
    $script:DirectorySource = 'ADSI'
    $root = Get-DirectoryRoot
    $domainNc = $root.defaultNamingContext
    $forestNc = $root.rootDomainNamingContext
    $configNc = $root.configurationNamingContext
    $head = @(Find-DirectoryObject $domainNc '(objectClass=domainDNS)' @('objectSid', 'msDS-Behavior-Version', 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts', 'fSMORoleOwner') 'Base')[0]
    $domainSid = ConvertTo-SidText $head.objectSid[0]
    $forestSid = ConvertTo-SidText (@(Find-DirectoryObject $forestNc '(objectClass=domainDNS)' @('objectSid') 'Base')[0].objectSid[0])
    $partitions = @(Find-DirectoryObject "CN=Partitions,$configNc" '(objectClass=crossRefContainer)' @('msDS-Behavior-Version') 'Base')

    $protectedDn = ''
    $pu = @(Find-DirectoryObject $domainNc "(&(objectClass=group)(objectSid=$domainSid-525))" @('distinguishedName'))
    if ($pu.Count -gt 0) { $protectedDn = "$($pu[0].distinguishedName[0])" }
    $groups = [ordered]@{}
    foreach ($g in @(
            @('Domain Admins', $domainNc, "$domainSid-512"), @('Enterprise Admins', $forestNc, "$forestSid-519"),
            @('Schema Admins', $forestNc, "$forestSid-518"), @('Group Policy Creator Owners', $domainNc, "$domainSid-520"),
            @('Protected Users', $domainNc, "$domainSid-525"), @('Administrators', $domainNc, 'S-1-5-32-544'),
            @('Account Operators', $domainNc, 'S-1-5-32-548'), @('Server Operators', $domainNc, 'S-1-5-32-549'),
            @('Print Operators', $domainNc, 'S-1-5-32-550'), @('Backup Operators', $domainNc, 'S-1-5-32-551'),
            @('Pre-Windows 2000 Compatible Access', $domainNc, 'S-1-5-32-554'), @('Incoming Forest Trust Builders', $domainNc, 'S-1-5-32-557'))) {
        # Users of the forest root's groups are checked against this domain's Protected Users.
        $groups[$g[0]] = Get-DirectoryGroup $g[1] $g[2] $protectedDn
    }

    # Computers trusted for unconstrained delegation (0x80000), domain controllers (primary group 516) aside.
    $unconstrained = @(Find-DirectoryObject $domainNc '(&(objectCategory=computer)(primaryGroupID=515)(userAccountControl:1.2.840.113556.1.4.803:=524288))' @('sAMAccountName') |
        ForEach-Object { "$($_.sAMAccountName[0])".TrimEnd('$') })
    $trusts = @(Find-DirectoryObject "CN=System,$domainNc" '(objectClass=trustedDomain)' @('trustPartner', 'trustDirection', 'trustType', 'trustAttributes') 'OneLevel' | ForEach-Object {
            [ordered]@{ Name = "$($_.trustPartner[0])"; Direction = [int]$_.trustDirection[0]; Type = [int]$_.trustType[0]; Attributes = [int]$_.trustAttributes[0] }
        })
    $sites = @(Find-DirectoryObject "CN=Sites,$configNc" '(objectClass=site)' @('cn') 'OneLevel').Count
    $links = @(Find-DirectoryObject "CN=Inter-Site Transports,CN=Sites,$configNc" '(objectClass=siteLink)' @('cn', 'replInterval', 'schedule') | ForEach-Object {
            [ordered]@{ Name = "$($_.cn[0])"; ReplInterval = [int]$(if ($_.replInterval.Count) { $_.replInterval[0] } else { 180 }); HasSchedule = $_.schedule.Count -gt 0 }
        })
    $ds = @(Find-DirectoryObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNc" '(objectClass=*)' @('dSHeuristics') 'Base')
    $dcs = @(Find-DirectoryObject $domainNc '(&(objectCategory=computer)(primaryGroupID=516))' @('cn')).Count

    # LAPS: the expiry attributes are readable more widely than the passwords.
    $schemaNc = $root.schemaNamingContext
    $hasWindowsLaps = @(Find-DirectoryObject $schemaNc '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' @('cn') 'OneLevel').Count -gt 0
    $hasLegacyLaps = @(Find-DirectoryObject $schemaNc '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)' @('cn') 'OneLevel').Count -gt 0
    $lapsSchema = if ($hasWindowsLaps -and $hasLegacyLaps) { 'Windows LAPS and legacy LAPS' } elseif ($hasWindowsLaps) { 'Windows LAPS' } elseif ($hasLegacyLaps) { 'legacy LAPS' } else { 'None' }
    $lapsProps = @('sAMAccountName') + @(if ($hasWindowsLaps) { 'msLAPS-PasswordExpirationTime' }) + @(if ($hasLegacyLaps) { 'ms-Mcs-AdmPwdExpirationTime' })
    $computers = @(Find-DirectoryObject $domainNc '(&(objectCategory=computer)(primaryGroupID=515)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' $lapsProps)
    $missing = @(if ($lapsSchema -ne 'None') {
            foreach ($c in $computers) {
                $has = $false
                foreach ($p in @($lapsProps | Select-Object -Skip 1)) { if ($c[$p].Count -gt 0) { $has = $true } }
                if (-not $has) { "$($c.sAMAccountName[0])".TrimEnd('$') }
            }
        })

    # Enterprise CAs and the templates they publish.
    $pki = "CN=Public Key Services,CN=Services,$configNc"
    $cas = @(Find-DirectoryObject "CN=Enrollment Services,$pki" '(objectClass=pKIEnrollmentService)' @('certificateTemplates') 'OneLevel')
    $published = @($cas | ForEach-Object { @($_.certificateTemplates) } | ForEach-Object { "$_" } | Select-Object -Unique)
    $templates = @(if ($cas.Count -gt 0) {
            Find-DirectoryObject "CN=Certificate Templates,$pki" '(objectClass=pKICertificateTemplate)' @('cn', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'pKIExtendedKeyUsage') 'OneLevel' |
                Where-Object { $published -contains "$($_.cn[0])" } | ForEach-Object {
                    [ordered]@{
                        Name            = "$($_.cn[0])"
                        SuppliesSubject = [bool]([int]$(if ($_.'msPKI-Certificate-Name-Flag'.Count) { $_.'msPKI-Certificate-Name-Flag'[0] } else { 0 }) -band 0x1)
                        ManagerApproval = [bool]([int]$(if ($_.'msPKI-Enrollment-Flag'.Count) { $_.'msPKI-Enrollment-Flag'[0] } else { 0 }) -band 0x2)
                        Ekus            = @($_.pKIExtendedKeyUsage | ForEach-Object { "$_" })
                    }
                }
        })

    # DSRM password changes are logged as event 4794 on the domain controller.
    $dsrm = $null
    $dsrmReadable = $true
    try {
        $e = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4794 } -MaxEvents 1 -ErrorAction Stop
        if ($e) { $dsrm = ConvertTo-IsoDate $e.TimeCreated }
    } catch {
        # Get-WinEvent throws when no event matches, as well as when the log is unreadable.
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $dsrmReadable = $false }
        Write-Verbose "No DSRM password event read: $($_.Exception.Message)"
    }
    $w32 = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    [ordered]@{
        Source                                 = $script:DirectorySource
        DomainSid                              = $domainSid
        IsForestRoot                           = $domainNc -eq $forestNc
        IsPdcEmulator                          = "$($head.fSMORoleOwner[0])" -eq $root.dsServiceName
        DomainMode                             = [int]$head.'msDS-Behavior-Version'[0]
        ForestMode                             = [int]$(if ($partitions.Count) { $partitions[0].'msDS-Behavior-Version'[0] } else { 0 })
        ExpirePasswordsOnSmartCardOnlyAccounts = [bool]$(if ($head.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'.Count) { $head.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'[0] } else { $false })
        Groups                                 = $groups
        UnconstrainedDelegation                = $unconstrained
        Trusts                                 = $trusts
        Sites                                  = $sites
        SiteLinks                              = $links
        DsHeuristics                           = $(if ($ds.Count -and $ds[0].dSHeuristics.Count) { "$($ds[0].dSHeuristics[0])" } else { '' })
        DomainControllers                      = $dcs
        Laps                                   = [ordered]@{ Schema = $lapsSchema; Computers = $computers.Count; Missing = $missing }
        CertificateServices                    = [ordered]@{ Present = $cas.Count -gt 0; Templates = $templates }
        DsrmLastSet                            = $dsrm
        DsrmLogReadable                        = $dsrmReadable
        TimeSource                             = [ordered]@{ Type = "$((Read-RegistryValue $w32 'Type').Value)"; NtpServer = "$((Read-RegistryValue $w32 'NtpServer').Value)" }
    }
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

    Invoke-Collector $snap 'Directory' $elevated {
        if ($snap.Meta.ProductType -ne 2) {
            throw [System.PlatformNotSupportedException]::new('Active Directory is read on a domain controller.')
        }
        Get-DirectorySnapshot
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

function Get-ScanId {
    # Names one collection: the computer and the UTC time its snapshot was taken.
    # Every framework evaluated from the same snapshot shares it, so reports from
    # many machines in one folder join and sort on it.
    param($Snapshot)
    $meta = Get-Prop $Snapshot 'Meta'
    $computer = "$($meta.ComputerName)" -replace '[^A-Za-z0-9-]', '_'
    $collected = ConvertTo-DateValue (Get-Prop $meta 'CollectedUtc')
    if ($null -eq $collected) { throw 'Snapshot has no Meta.CollectedUtc.' }
    return '{0}-{1}' -f $computer, $collected.ToString('yyyyMMddTHHmmssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-ScanRecord {
    # One flat record per requirement, with the scan's details repeated on each,
    # for Power BI's Folder connector or any tool that wants a single table.
    param($Evaluation, $Snapshot, $Catalog)
    $meta = Get-Prop $Snapshot 'Meta'
    $scanId = Get-ScanId $Snapshot
    $collected = ConvertTo-IsoDate (ConvertTo-DateValue $meta.CollectedUtc)
    @(foreach ($r in @($Evaluation.Requirements)) {
        [ordered]@{
            ScanId           = $scanId
            ComputerName     = "$($meta.ComputerName)"
            CollectedUtc     = $collected
            OSCaption        = "$(Get-Prop $meta 'OSCaption')"
            OSVersion        = "$(Get-Prop $meta 'OSVersion')"
            ProductType      = Get-Prop $meta 'ProductType'
            PartOfDomain     = Get-Prop $meta 'PartOfDomain'
            IsElevated       = Get-Prop $meta 'IsElevated'
            ToolVersion      = $ComplianceScanVersion
            Framework        = $Catalog.Id
            FrameworkName    = $Catalog.Name
            FrameworkLevel   = $Evaluation.Level
            CatalogComplete  = [bool]$Catalog.Complete
            PlatformWarning  = "$($Evaluation.PlatformWarning)"
            Requirement      = $r.Requirement
            Reference        = $r.Reference
            RequirementLevel = $r.Level
            Family           = $r.Family
            Title            = $r.Title
            State            = $r.State
            Checks           = $r.Checks
            Findings         = $r.Findings
            Evidence         = $r.Evidence
            Note             = $r.Note
        }
    })
}

function ConvertTo-HtmlText {
    param($Value)
    return [Net.WebUtility]::HtmlEncode("$Value")
}

$HtmlStyle = @'
:root { --bg: #ffffff; --fg: #1d2330; --muted: #5b6475; --line: #d9dde5; --panel: #f4f6f9;
  --pass: #1e7b45; --fail: #b3261e; --error: #8e24aa; --skipped: #9a6700; --manual: #3d5a99; --na: #6b7280; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #14171d; --fg: #e6e9ef; --muted: #9aa3b2; --line: #2c323d; --panel: #1c2028;
    --pass: #4cc38a; --fail: #ff7b72; --error: #d2a8ff; --skipped: #e3b341; --manual: #8cb4ff; --na: #9ca3af; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px 16px 48px; background: var(--bg); color: var(--fg);
  font: 14px/1.45 "Segoe UI", system-ui, -apple-system, sans-serif; }
main { max-width: 1200px; margin: 0 auto; }
h1 { font-size: 20px; margin: 0 0 4px; }
h2 { font-size: 15px; margin: 28px 0 8px; }
.meta { color: var(--muted); margin: 0 0 12px; }
.banner { border-left: 4px solid var(--skipped); background: var(--panel); padding: 8px 12px; margin: 8px 0; }
.counts { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0; }
.count { border: 1px solid var(--line); border-radius: 6px; padding: 8px 12px; min-width: 104px; background: var(--panel); }
.count b { display: block; font-size: 20px; }
table { border-collapse: collapse; width: 100%; }
table.fam { width: auto; min-width: 50%; }
th, td { border-bottom: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
td.n { text-align: right; font-variant-numeric: tabular-nums; }
.state { font-weight: 600; white-space: nowrap; }
.Pass { color: var(--pass); } .Fail { color: var(--fail); } .Error { color: var(--error); }
.Skipped { color: var(--skipped); } .Manual { color: var(--manual); } .NotApplicable { color: var(--na); }
.filters { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin: 8px 0 12px; }
.filters label { white-space: nowrap; }
.filters input[type=search], .filters select { font: inherit; padding: 4px 6px; color: var(--fg);
  background: var(--bg); border: 1px solid var(--line); border-radius: 4px; }
details summary { cursor: pointer; }
details div { margin: 6px 0 2px; white-space: pre-wrap; word-break: break-word; color: var(--muted); }
.wrap { overflow-x: auto; }
@media print { .filters { display: none; } tr { break-inside: avoid; } body { padding: 0; } }
'@

$HtmlScript = @'
(function () {
  var rows = Array.prototype.slice.call(document.querySelectorAll('#reqs tbody tr'));
  var boxes = Array.prototype.slice.call(document.querySelectorAll('.filters input[type=checkbox]'));
  var family = document.getElementById('family');
  var text = document.getElementById('text');
  var shown = document.getElementById('shown');
  function apply() {
    var states = boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
    var q = text.value.toLowerCase();
    var n = 0;
    rows.forEach(function (r) {
      var ok = states.indexOf(r.getAttribute('data-state')) >= 0 &&
        (!family.value || r.getAttribute('data-family') === family.value) &&
        (!q || r.textContent.toLowerCase().indexOf(q) >= 0);
      r.style.display = ok ? '' : 'none';
      if (ok) { n++; }
    });
    shown.textContent = n + ' of ' + rows.length + ' shown';
  }
  boxes.forEach(function (b) { b.addEventListener('change', apply); });
  family.addEventListener('change', apply);
  text.addEventListener('input', apply);
  window.addEventListener('beforeprint', function () {
    Array.prototype.forEach.call(document.querySelectorAll('details'), function (d) { d.open = true; });
  });
  apply();
})();
'@

function ConvertTo-HtmlReport {
    # A single self-contained page: no external files or scripts, so it opens
    # offline, survives being emailed and prints to PDF from the browser.
    param($Evaluation, $Snapshot, $Catalog, [string[]]$Notice = @())
    $meta = Get-Prop $Snapshot 'Meta'
    $reqs = @($Evaluation.Requirements)
    $order = 'Fail', 'Error', 'Skipped', 'Manual', 'Pass', 'NotApplicable'
    $label = @{ Fail = 'Fail'; Error = 'Error'; Skipped = 'Skipped'; Manual = 'Manual'; Pass = 'Pass'; NotApplicable = 'Not applicable' }
    $when = (ConvertTo-DateValue $meta.CollectedUtc).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
    $sb = [Text.StringBuilder]::new()
    $title = "$($Catalog.Name) - $($meta.ComputerName)"
    $null = $sb.Append('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    $null = $sb.Append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.Append("<title>$(ConvertTo-HtmlText $title)</title><style>$HtmlStyle</style></head><body><main>")
    $null = $sb.Append("<h1>$(ConvertTo-HtmlText $Catalog.Name)</h1>")
    $null = $sb.Append("<p class=""meta"">$(ConvertTo-HtmlText $meta.ComputerName) &middot; level $(ConvertTo-HtmlText $Evaluation.Level) &middot; collected $when UTC &middot; $(ConvertTo-HtmlText (Get-Prop $meta 'OSCaption')) $(ConvertTo-HtmlText (Get-Prop $meta 'OSVersion')) &middot; endpoint-compliance-scan $ComplianceScanVersion &middot; scan $(ConvertTo-HtmlText (Get-ScanId $Snapshot))</p>")
    $banners = @()
    if ($Evaluation.PlatformWarning) { $banners += $Evaluation.PlatformWarning }
    if (-not $Catalog.Complete) { $banners += 'This catalog lists only the requirements an endpoint can show evidence for; the rest of the framework is assessed elsewhere.' }
    if (-not $meta.IsElevated) { $banners += 'Not elevated: checks that need elevation are Skipped.' }
    $banners += @($Notice | Where-Object { $_ })
    foreach ($b in $banners) { $null = $sb.Append("<p class=""banner"">$(ConvertTo-HtmlText $b)</p>") }
    $null = $sb.Append('<p class="meta">Evidence for an assessment, not a verdict: the report never states that a machine is compliant.</p>')

    $null = $sb.Append('<div class="counts">')
    foreach ($s in $order) {
        $n = @($reqs | Where-Object { $_.State -eq $s }).Count
        $null = $sb.Append("<div class=""count""><b class=""$s"">$n</b>$($label[$s])</div>")
    }
    $null = $sb.Append("<div class=""count""><b>$($reqs.Count)</b>Requirements</div></div>")

    $null = $sb.Append('<h2>By family</h2><div class="wrap"><table class="fam"><thead><tr><th>Family</th>')
    foreach ($s in $order) { $null = $sb.Append("<th class=""n"">$($label[$s])</th>") }
    $null = $sb.Append('</tr></thead><tbody>')
    $families = @($reqs | Group-Object Family | Sort-Object Name)
    foreach ($grp in $families) {
        $null = $sb.Append("<tr><td>$(ConvertTo-HtmlText $grp.Name)</td>")
        foreach ($s in $order) { $null = $sb.Append("<td class=""n"">$(@($grp.Group | Where-Object { $_.State -eq $s }).Count)</td>") }
        $null = $sb.Append('</tr>')
    }
    $null = $sb.Append('</tbody></table></div>')

    $null = $sb.Append('<h2>Requirements</h2><div class="filters">')
    foreach ($s in $order) {
        $checked = if ($s -in 'Fail', 'Error', 'Skipped') { ' checked' } else { '' }
        $null = $sb.Append("<label><input type=""checkbox"" value=""$s""$checked> $($label[$s])</label>")
    }
    $null = $sb.Append('<select id="family" aria-label="Family"><option value="">All families</option>')
    foreach ($grp in $families) { $null = $sb.Append("<option>$(ConvertTo-HtmlText $grp.Name)</option>") }
    $null = $sb.Append('</select><input id="text" type="search" placeholder="Search" aria-label="Search"><span id="shown" class="meta"></span></div>')
    $null = $sb.Append('<div class="wrap"><table id="reqs"><thead><tr><th>Reference</th><th>Level</th><th>Family</th><th>State</th><th>Requirement</th></tr></thead><tbody>')
    foreach ($r in ($reqs | Sort-Object { $StateRank[$_.State] })) {
        $null = $sb.Append("<tr data-state=""$($r.State)"" data-family=""$(ConvertTo-HtmlText $r.Family)"">")
        $null = $sb.Append("<td>$(ConvertTo-HtmlText $r.Reference)</td><td>$(ConvertTo-HtmlText $r.Level)</td><td>$(ConvertTo-HtmlText $r.Family)</td>")
        $null = $sb.Append("<td class=""state $($r.State)"">$($label[$r.State])</td><td>")
        $parts = @()
        if ($r.Findings) { $parts += "Findings: $($r.Findings)" }
        if ($r.Evidence -and $r.Evidence -ne $r.Findings) { $parts += "Evidence: $($r.Evidence)" }
        if ($r.Note) { $parts += "Note: $($r.Note)" }
        if ($parts.Count -gt 0) {
            $null = $sb.Append("<details><summary>$(ConvertTo-HtmlText $r.Title)</summary><div>$(ConvertTo-HtmlText ($parts -join "`n`n"))</div></details>")
        } else {
            $null = $sb.Append((ConvertTo-HtmlText $r.Title))
        }
        $null = $sb.Append('</td></tr>')
    }
    $null = $sb.Append("</tbody></table></div></main><script>$HtmlScript</script></body></html>")
    return $sb.ToString()
}

function Read-StigBenchmark {
    # The rules of a DISA STIG from its XCCDF file, or from the STIG zip that
    # cyber.mil publishes (the zip's xccdf.xml is read in place). Read as data:
    # no DTDs, no external entities.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "STIG file '$Path' does not exist." }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $docs = @()
    if ([IO.Path]::GetExtension($Path) -eq '.zip') {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Path).ProviderPath)
        try {
            foreach ($entry in @($zip.Entries | Where-Object { $_.Name -like '*xccdf*.xml' })) {
                $stream = $entry.Open()
                try {
                    $reader = [Xml.XmlReader]::Create($stream, $settings)
                    $doc = [Xml.XmlDocument]::new()
                    $doc.Load($reader)
                    $docs += [pscustomobject]@{ Name = $entry.FullName; Doc = $doc }
                } finally { $stream.Dispose() }
            }
        } finally { $zip.Dispose() }
        if ($docs.Count -eq 0) { throw "$Path holds no XCCDF file (*xccdf*.xml)." }
        if ($docs.Count -gt 1) { throw "$Path holds $($docs.Count) XCCDF files; extract the one for this STIG and pass it to -StigPath." }
    } else {
        $reader = [Xml.XmlReader]::Create((Resolve-Path -LiteralPath $Path).ProviderPath, $settings)
        try {
            $doc = [Xml.XmlDocument]::new()
            $doc.Load($reader)
        } finally { $reader.Dispose() }
        $docs += [pscustomobject]@{ Name = (Split-Path $Path -Leaf); Doc = $doc }
    }
    $doc = $docs[0].Doc
    $bench = $doc.DocumentElement
    if ($bench.LocalName -ne 'Benchmark') { throw "$($docs[0].Name) is not an XCCDF benchmark." }
    function Get-Child { param($Node, [string]$Name) @($Node.ChildNodes | Where-Object { $_.LocalName -eq $Name }) }
    function Get-ChildText { param($Node, [string]$Name) $c = @(Get-Child $Node $Name); if ($c.Count -gt 0) { "$($c[0].InnerText)" } else { '' } }
    $release = @(Get-Child $bench 'plain-text' | Where-Object { $_.GetAttribute('id') -eq 'release-info' })
    $rules = [Collections.Generic.List[object]]::new()
    foreach ($group in @(Get-Child $bench 'Group')) {
        foreach ($rule in @(Get-Child $group 'Rule')) {
            # The description holds escaped tags: <VulnDiscussion>...</VulnDiscussion><FalsePositives>...
            $parts = @{}
            foreach ($m in [regex]::Matches((Get-ChildText $rule 'description'), '<(\w+)>(.*?)</\1>', 'Singleline')) {
                $parts[$m.Groups[1].Value] = $m.Groups[2].Value
            }
            $check = @(Get-Child $rule 'check')
            $checkText = ''
            $checkRef = ''
            $checkHref = ''
            if ($check.Count -gt 0) {
                $checkText = Get-ChildText $check[0] 'check-content'
                $ref = @(Get-Child $check[0] 'check-content-ref')
                if ($ref.Count -gt 0) {
                    $checkRef = $ref[0].GetAttribute('name')
                    $checkHref = $ref[0].GetAttribute('href')
                }
            }
            $idents = @(Get-Child $rule 'ident')
            $reference = @(Get-Child $rule 'reference')
            $targetKey = ''
            if ($reference.Count -gt 0) { $targetKey = Get-ChildText $reference[0] 'identifier' }
            $rules.Add([pscustomobject]@{
                GroupId        = $group.GetAttribute('id')
                GroupTitle     = Get-ChildText $group 'title'
                GroupDescription = Get-ChildText $group 'description'
                RuleId         = $rule.GetAttribute('id')
                Severity       = $rule.GetAttribute('severity')
                Weight         = $rule.GetAttribute('weight')
                RuleVersion    = Get-ChildText $rule 'version'
                RuleTitle      = Get-ChildText $rule 'title'
                Discussion     = "$($parts['VulnDiscussion'])"
                FalsePositives = "$($parts['FalsePositives'])"
                FalseNegatives = "$($parts['FalseNegatives'])"
                Documentable   = "$($parts['Documentable'])"
                Mitigations    = "$($parts['Mitigations'])"
                PotentialImpact = "$($parts['PotentialImpacts'])"
                ThirdPartyTools = "$($parts['ThirdPartyTools'])"
                MitigationControl = "$($parts['MitigationControl'])"
                Responsibility = "$($parts['Responsibility'])"
                SecurityOverrideGuidance = "$($parts['SeverityOverrideGuidance'])"
                IAControls     = "$($parts['IAControls'])"
                CheckContent   = $checkText
                CheckContentRef = $checkRef
                CheckContentHref = $checkHref
                FixText        = Get-ChildText $rule 'fixtext'
                TargetKey      = $targetKey
                Cci            = @($idents | Where-Object { $_.GetAttribute('system') -like '*cci*' } | ForEach-Object { "$($_.InnerText)" })
                Legacy         = @($idents | Where-Object { $_.GetAttribute('system') -like '*legacy*' } | ForEach-Object { "$($_.InnerText)" })
            })
        }
    }
    if ($rules.Count -eq 0) { throw "$($docs[0].Name) holds no rules." }
    [pscustomobject]@{
        Id          = $bench.GetAttribute('id')
        Title       = Get-ChildText $bench 'title'
        Description = Get-ChildText $bench 'description'
        Version     = Get-ChildText $bench 'version'
        ReleaseInfo = $(if ($release.Count -gt 0) { "$($release[0].InnerText)" } else { '' })
        Notice      = $(@(Get-Child $bench 'notice') | ForEach-Object { $_.GetAttribute('id') } | Select-Object -First 1)
        FileName    = $docs[0].Name
        Rules       = @($rules)
    }
}

function Assert-StigBenchmark {
    # Refuses a STIG file that isn't the one the catalog was built from: at least
    # 80% of the catalog's Vuln IDs must be in it. The STIG IDs PowerStig uses
    # differ from DISA's, so the IDs are compared, not the benchmark names.
    param($Catalog, $Benchmark)
    if (-not $Catalog.Contains('StigId')) { throw "$($Catalog.Id) is not a STIG; -StigPath applies only to the DISA STIG frameworks." }
    $catalogVulns = @($Catalog.Requirements | ForEach-Object { "$($_.Id)" -replace '\.[a-z]$', '' } | Select-Object -Unique)
    $benchVulns = @($Benchmark.Rules | ForEach-Object { $_.GroupId })
    $shared = @($catalogVulns | Where-Object { $benchVulns -contains $_ })
    if ($shared.Count -lt [math]::Ceiling($catalogVulns.Count * 0.8)) {
        throw "$($Benchmark.FileName) shares $($shared.Count) of $($catalogVulns.Count) Vuln IDs with $($Catalog.Id); it looks like another STIG or release."
    }
}

function ConvertTo-XmlText {
    # Drops characters XML 1.0 can't hold (control characters, NUL, unpaired
    # surrogates), which XmlWriter refuses with an exception. Text from the
    # machine, such as registry evidence, can carry them.
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Text -notmatch '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]') { return $Text }
    $sb = [Text.StringBuilder]::new($Text.Length)
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ([char]::IsHighSurrogate($c) -and $i + 1 -lt $Text.Length -and [char]::IsLowSurrogate($Text[$i + 1])) {
            $null = $sb.Append($c).Append($Text[$i + 1])
            $i++
        } elseif ([Xml.XmlConvert]::IsXmlChar($c)) {
            $null = $sb.Append($c)
        }
    }
    Write-Verbose "Dropped $($Text.Length - $sb.Length) character(s) XML can't hold."
    return $sb.ToString()
}

# Result states as STIG Viewer records them.
$ChecklistStatus = @{ Pass = 'NotAFinding'; Fail = 'Open'; NotApplicable = 'Not_Applicable' }

function Get-ChecklistResult {
    # The checklist entry for each rule of the benchmark, by Vuln ID: status,
    # finding details and comments. A catalog rule split in parts (V-1.a, V-1.b)
    # takes the worst state of its parts. Rules the scan didn't evaluate stay
    # Not_Reviewed and say why.
    param($Evaluation, $Snapshot, $Catalog, $Benchmark)
    Assert-StigBenchmark $Catalog $Benchmark
    $byVuln = @{}
    foreach ($r in @($Evaluation.Requirements)) {
        $vuln = "$($r.Requirement)" -replace '\.[a-z]$', ''
        if (-not $byVuln.ContainsKey($vuln)) { $byVuln[$vuln] = [Collections.Generic.List[object]]::new() }
        $byVuln[$vuln].Add($r)
    }
    $catalogVulns = @($Catalog.Requirements | ForEach-Object { "$($_.Id)" -replace '\.[a-z]$', '' } | Select-Object -Unique)
    $benchVulns = @($Benchmark.Rules | ForEach-Object { $_.GroupId })
    $scanId = Get-ScanId $Snapshot
    $entries = @{}
    $matched = 0
    foreach ($rule in @($Benchmark.Rules)) {
        $status = 'Not_Reviewed'
        $details = ''
        if ($byVuln.ContainsKey($rule.GroupId)) {
            $matched++
            $parts = @($byVuln[$rule.GroupId])
            $state = ($parts | Sort-Object { $StateRank[$_.State] } | Select-Object -First 1).State
            if ($ChecklistStatus.ContainsKey($state)) { $status = $ChecklistStatus[$state] }
            $details = (@($parts | ForEach-Object { "$($_.Requirement) $($_.State): $($_.Evidence)".Trim() }) -join "`n")
            $notes = @($parts | Where-Object { $_.Note } | ForEach-Object { $_.Note } | Select-Object -Unique)
            $comments = "endpoint-compliance-scan $ComplianceScanVersion, $($Catalog.Id), scan ${scanId}: $state." + $(if ($notes.Count -gt 0) { ' ' + ($notes -join ' ') } else { '' })
        } elseif ($catalogVulns -contains $rule.GroupId) {
            $comments = "Not evaluated: outside level $($Evaluation.Level)."
        } else {
            $comments = "Not in the $($Catalog.Id) catalog; review it in STIG Viewer."
        }
        $entries[$rule.GroupId] = [pscustomobject]@{ Status = $status; Details = (ConvertTo-XmlText $details); Comments = (ConvertTo-XmlText $comments) }
    }
    $meta = Get-Prop $Snapshot 'Meta'
    [pscustomobject]@{
        Entries   = $entries
        Rules     = @($Benchmark.Rules).Count
        Matched   = $matched
        Unmatched = @($catalogVulns | Where-Object { $benchVulns -notcontains $_ })
        Role      = switch ([int](Get-Prop $meta 'ProductType')) { 1 { 'Workstation' } 2 { 'Domain Controller' } 3 { 'Member Server' } default { 'None' } }
        HostName  = ConvertTo-XmlText "$($meta.ComputerName)"
        Comment   = "Scan $scanId"
    }
}

function ConvertTo-StigChecklist {
    # A STIG Viewer 2 checklist (.ckl, XML) with every rule of the benchmark and
    # the scan's results. Returns the XML text and the result counts.
    param($Evaluation, $Snapshot, $Catalog, $Benchmark)
    $result = Get-ChecklistResult $Evaluation $Snapshot $Catalog $Benchmark
    $stigRef = "$($Benchmark.Title) :: Version $($Benchmark.Version), $($Benchmark.ReleaseInfo)"
    $stigUuid = [guid]::NewGuid().ToString()

    $settings = [Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.Encoding = [Text.UTF8Encoding]::new($false)
    $buffer = [IO.MemoryStream]::new()
    $w = [Xml.XmlWriter]::Create($buffer, $settings)
    $w.WriteStartDocument()
    $w.WriteComment("endpoint-compliance-scan $ComplianceScanVersion")
    $w.WriteStartElement('CHECKLIST')
    $w.WriteStartElement('ASSET')
    foreach ($pair in @(@('ROLE', $result.Role), @('ASSET_TYPE', 'Computing'), @('MARKING', 'CUI'), @('HOST_NAME', $result.HostName),
            @('HOST_IP', ''), @('HOST_MAC', ''), @('HOST_FQDN', ''), @('TARGET_COMMENT', $result.Comment), @('TECH_AREA', ''),
            @('TARGET_KEY', "$(@($Benchmark.Rules)[0].TargetKey)"), @('WEB_OR_DATABASE', 'false'), @('WEB_DB_SITE', ''), @('WEB_DB_INSTANCE', ''))) {
        $w.WriteElementString($pair[0], (ConvertTo-XmlText $pair[1]))
    }
    $w.WriteEndElement()
    $w.WriteStartElement('STIGS')
    $w.WriteStartElement('iSTIG')
    $w.WriteStartElement('STIG_INFO')
    foreach ($pair in @(@('version', $Benchmark.Version), @('classification', 'UNCLASSIFIED'), @('customname', ''), @('stigid', $Benchmark.Id),
            @('description', $Benchmark.Description), @('filename', $Benchmark.FileName), @('releaseinfo', $Benchmark.ReleaseInfo),
            @('title', $Benchmark.Title), @('uuid', $stigUuid), @('notice', "$($Benchmark.Notice)"), @('source', 'STIG.DOD.MIL'))) {
        $w.WriteStartElement('SI_DATA')
        $w.WriteElementString('SID_NAME', $pair[0])
        if ("$($pair[1])" -ne '') { $w.WriteElementString('SID_DATA', (ConvertTo-XmlText "$($pair[1])")) }
        $w.WriteEndElement()
    }
    $w.WriteEndElement()
    foreach ($rule in @($Benchmark.Rules)) {
        $w.WriteStartElement('VULN')
        $data = @(
            @('Vuln_Num', $rule.GroupId), @('Severity', $rule.Severity), @('Group_Title', $rule.GroupTitle), @('Rule_ID', $rule.RuleId),
            @('Rule_Ver', $rule.RuleVersion), @('Rule_Title', $rule.RuleTitle), @('Vuln_Discuss', $rule.Discussion), @('IA_Controls', $rule.IAControls),
            @('Check_Content', $rule.CheckContent), @('Fix_Text', $rule.FixText), @('False_Positives', $rule.FalsePositives),
            @('False_Negatives', $rule.FalseNegatives), @('Documentable', $rule.Documentable), @('Mitigations', $rule.Mitigations),
            @('Potential_Impact', $rule.PotentialImpact), @('Third_Party_Tools', $rule.ThirdPartyTools), @('Mitigation_Control', $rule.MitigationControl),
            @('Responsibility', $rule.Responsibility), @('Security_Override_Guidance', $rule.SecurityOverrideGuidance),
            @('Check_Content_Ref', $rule.CheckContentRef), @('Weight', $rule.Weight), @('Class', 'Unclass'), @('STIGRef', $stigRef),
            @('TargetKey', $rule.TargetKey), @('STIG_UUID', $stigUuid))
        $data += @($rule.Legacy | ForEach-Object { , @('LEGACY_ID', $_) })
        $data += @($rule.Cci | ForEach-Object { , @('CCI_REF', $_) })
        foreach ($pair in $data) {
            $w.WriteStartElement('STIG_DATA')
            $w.WriteElementString('VULN_ATTRIBUTE', $pair[0])
            $w.WriteElementString('ATTRIBUTE_DATA', (ConvertTo-XmlText "$($pair[1])"))
            $w.WriteEndElement()
        }
        $entry = $result.Entries[$rule.GroupId]
        $w.WriteElementString('STATUS', $entry.Status)
        $w.WriteElementString('FINDING_DETAILS', $entry.Details)
        $w.WriteElementString('COMMENTS', $entry.Comments)
        $w.WriteElementString('SEVERITY_OVERRIDE', '')
        $w.WriteElementString('SEVERITY_JUSTIFICATION', '')
        $w.WriteEndElement()
    }
    $w.WriteEndElement()
    $w.WriteEndElement()
    $w.WriteEndElement()
    $w.WriteEndDocument()
    $w.Flush()
    $w.Dispose()
    $text = [Text.Encoding]::UTF8.GetString($buffer.ToArray())
    $buffer.Dispose()
    [pscustomobject]@{
        Xml       = $text
        Rules     = $result.Rules
        Matched   = $result.Matched
        Unmatched = $result.Unmatched
    }
}

# Checklist statuses as STIG Viewer 3 writes them in a .cklb.
$ChecklistJsonStatus = @{ NotAFinding = 'not_a_finding'; Open = 'open'; Not_Applicable = 'not_applicable'; Not_Reviewed = 'not_reviewed' }

function ConvertTo-StigChecklistJson {
    # A STIG Viewer 3 checklist (.cklb, JSON) with every rule of the benchmark and
    # the scan's results, laid out as STIG Viewer 3.8 saves one. Returns the JSON
    # text and the result counts.
    param($Evaluation, $Snapshot, $Catalog, $Benchmark, [string]$Title)
    $result = Get-ChecklistResult $Evaluation $Snapshot $Catalog $Benchmark
    $stigUuid = [guid]::NewGuid().ToString()
    $targetKey = "$(@($Benchmark.Rules)[0].TargetKey)"
    $rules = foreach ($rule in @($Benchmark.Rules)) {
        $entry = $result.Entries[$rule.GroupId]
        [ordered]@{
            group_id_src               = $rule.GroupId
            group_tree                 = @([ordered]@{ id = $rule.GroupId; title = $rule.GroupTitle; description = $rule.GroupDescription })
            group_id                   = $rule.GroupId
            severity                   = $rule.Severity
            group_title                = $rule.RuleTitle
            rule_id_src                = $rule.RuleId
            rule_id                    = $rule.RuleId -replace '_rule$', ''
            rule_version               = $rule.RuleVersion
            rule_title                 = $rule.RuleTitle
            fix_text                   = $rule.FixText
            weight                     = $rule.Weight
            check_content              = $rule.CheckContent
            check_content_ref          = [ordered]@{ href = $rule.CheckContentHref; name = $rule.CheckContentRef }
            classification             = 'Unclassified'
            discussion                 = $rule.Discussion
            false_positives            = $rule.FalsePositives
            false_negatives            = $rule.FalseNegatives
            documentable               = $rule.Documentable
            security_override_guidance = $rule.SecurityOverrideGuidance
            potential_impacts          = $rule.PotentialImpact
            third_party_tools          = $rule.ThirdPartyTools
            ia_controls                = $rule.IAControls
            responsibility             = $rule.Responsibility
            mitigations                = $rule.Mitigations
            mitigation_control         = $rule.MitigationControl
            legacy_ids                 = @($rule.Legacy)
            ccis                       = @($rule.Cci)
            reference_identifier       = $rule.TargetKey
            uuid                       = [guid]::NewGuid().ToString()
            stig_uuid                  = $stigUuid
            status                     = $ChecklistJsonStatus[$entry.Status]
            overrides                  = [ordered]@{}
            comments                   = $entry.Comments
            finding_details            = $entry.Details
            srg_id                     = $rule.GroupTitle
        }
    }
    $checklist = [ordered]@{
        title       = $Title
        id          = [guid]::NewGuid().ToString()
        stigs       = @([ordered]@{
                stig_name            = $Benchmark.Title
                display_name         = $Benchmark.Title -replace '\s*Security Technical Implementation Guide$', ''
                stig_id              = $Benchmark.Id
                release_info         = $Benchmark.ReleaseInfo
                version              = $Benchmark.Version
                uuid                 = $stigUuid
                reference_identifier = $targetKey
                size                 = @($rules).Count
                rules                = @($rules)
            })
        active      = $true
        mode        = 2
        has_path    = $true
        target_data = [ordered]@{
            target_type     = 'Computing'
            host_name       = $result.HostName
            ip_address      = ''
            mac_address     = ''
            fqdn            = ''
            comments        = $result.Comment
            role            = $result.Role
            is_web_database = $false
            technology_area = ''
            web_db_site     = ''
            web_db_instance = ''
            classification  = $null
        }
    }
    [pscustomobject]@{
        Json      = ConvertTo-Json -InputObject $checklist -Depth 8 -Compress
        Rules     = $result.Rules
        Matched   = $result.Matched
        Unmatched = $result.Unmatched
    }
}

function Export-ScanReport {
    # Writes the reports, named compliance-scan-<scan id>-<framework>, so a folder
    # of many machines' reports sorts by computer, then time. Re-evaluating a
    # snapshot against the same framework replaces its reports.
    param($Evaluation, $Snapshot, $Thresholds, $Catalog, [string]$Folder, [switch]$IncludeSnapshot, $Benchmark, [string[]]$Notice = @())
    if (-not (Test-Path -LiteralPath $Folder)) { $null = New-Item -ItemType Directory -Path $Folder }
    $meta = Get-Prop $Snapshot 'Meta'
    $scanId = Get-ScanId $Snapshot
    $framework = "$($Catalog.Id)".ToLowerInvariant() -replace '[^a-z0-9.-]', '_'
    $base = Join-Path $Folder "compliance-scan-$scanId-$framework"
    $files = @()
    $utf8 = [Text.UTF8Encoding]::new($false)

    $Evaluation.Requirements | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8
    $files += "$base.csv"

    $report = [ordered]@{
        Tool            = 'endpoint-compliance-scan'
        Version         = $ComplianceScanVersion
        ScanId          = $scanId
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
    $files += "$base.json"

    # ConvertTo-Json unwraps a one-item array in 5.1, so the list goes in explicitly.
    $records = @(ConvertTo-ScanRecord $Evaluation $Snapshot $Catalog)
    [IO.File]::WriteAllText("$base.records.json", (ConvertTo-Json -InputObject $records -Depth 4), $utf8)
    $files += "$base.records.json"

    $notes = @($Notice | Where-Object { $_ })
    if ($Benchmark) {
        $cklb = ConvertTo-StigChecklistJson $Evaluation $Snapshot $Catalog $Benchmark -Title (Split-Path $base -Leaf)
        [IO.File]::WriteAllText("$base.cklb", $cklb.Json, $utf8)
        $files += "$base.cklb"
        $ckl = ConvertTo-StigChecklist $Evaluation $Snapshot $Catalog $Benchmark
        [IO.File]::WriteAllText("$base.ckl", $ckl.Xml, $utf8)
        $files += "$base.ckl"
        $notes += "STIG Viewer checklists (.cklb for STIG Viewer 3, .ckl for STIG Viewer 2): $($ckl.Matched) of $($ckl.Rules) rules from $($Benchmark.FileName) have results; the rest are Not_Reviewed."
        if ($ckl.Unmatched.Count -gt 0) {
            $notes += "$($ckl.Unmatched.Count) catalog rule(s) are not in $($Benchmark.FileName): $($ckl.Unmatched -join ', ')."
        }
    }
    [IO.File]::WriteAllText("$base.html", (ConvertTo-HtmlReport $Evaluation $Snapshot $Catalog $notes), $utf8)
    $files += "$base.html"
    return $files
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
    # Read the STIG file first, so a wrong one stops the run before the scan.
    $benchmark = $null
    $notice = @()
    if ($StigPath) {
        $benchmark = Read-StigBenchmark $StigPath
        Assert-StigBenchmark $catalog $benchmark
    } elseif ($catalog.Contains('StigId')) {
        $notice += 'No STIG Viewer checklists: pass the DISA STIG zip from cyber.mil with -StigPath to write them.'
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
    $files = Export-ScanReport -Evaluation $evaluation -Snapshot $snapshot -Thresholds $thresholds -Catalog $catalog -Folder $folder -IncludeSnapshot:$IncludeSnapshot -Benchmark $benchmark -Notice $notice

    Write-ScanSummary -Evaluation $evaluation -Snapshot $snapshot -Catalog $catalog
    foreach ($n in $notice) { Write-Host $n -ForegroundColor Yellow }
    Write-Host ("Reports: " + ($files -join ', '))
    if ($PassThru) { $evaluation.Requirements }
    $code = Get-ScanExitCode $evaluation.Requirements
} catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    $code = 2
}
exit $code
