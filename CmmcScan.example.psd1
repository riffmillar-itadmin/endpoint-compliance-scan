# Thresholds for Invoke-CmmcEndpointScan.ps1.
#
# NIST SP 800-171 leaves most of these values to the organization, so they are
# defaults, not requirements. To change one, copy this file to
# CmmcScan.local.psd1 beside the script and keep only the keys you change; the
# local file is gitignored and its keys override these. -ProfilePath points the
# scan at a different file instead.

@{
    # 3.1.5: most members allowed in the local Administrators group.
    MaxLocalAdmins              = 2

    # 3.1.8: lockout after at most this many bad attempts (0, never locking, fails).
    LockoutThresholdMax         = 10
    # 3.1.8: minutes an account stays locked. "Until an administrator unlocks" passes.
    LockoutDurationMinMinutes   = 15

    # 3.1.10: machine inactivity limit, in seconds.
    InactivityLockMaxSeconds    = 900

    # 3.1.11 and 3.13.9: Remote Desktop idle session limit, in minutes.
    RdpIdleMaxMinutes           = 15

    # 3.5.7 and 3.5.8
    MinPasswordLength           = 12
    MinPasswordHistory          = 24

    # 3.3.1: Security event log size, in MB.
    MinSecurityLogMB            = 192

    # 3.14.1: days since the newest installed Windows update.
    MaxDaysSinceUpdate          = 35
    # 3.14.4: age of antivirus signatures, in days.
    MaxSignatureAgeDays         = 7
    # 3.14.5: days since the last quick or full scan.
    MaxDaysSinceScan            = 7

    # 3.13.11: $false reports FIPS mode as Manual (when FIPS-validated modules
    # are evidenced another way) instead of failing it.
    RequireFipsMode             = $true

    # 3.8.7: $false reports removable media as Manual (when a third-party
    # device control product enforces it) instead of failing it.
    RequireRemovableMediaPolicy = $true

    # 3.4.6 and 3.4.7: services that must be absent or disabled.
    NonessentialServices        = @('RemoteRegistry', 'TlntSvr', 'SNMP', 'FTPSVC', 'simptcp')

    # 3.3.1 and 3.3.2: advanced audit subcategories and the minimum setting each
    # needs (Success, Failure or SuccessAndFailure). Matched by GUID, so the
    # check works on any Windows display language.
    AuditSubcategories          = @(
        @{ Name = 'Credential Validation';     Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Setting = 'SuccessAndFailure' }
        @{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Setting = 'Success' }
        @{ Name = 'User Account Management';   Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Setting = 'SuccessAndFailure' }
        @{ Name = 'Process Creation';          Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Setting = 'Success' }
        @{ Name = 'Account Lockout';           Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Setting = 'Failure' }
        @{ Name = 'Logon';                     Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Setting = 'SuccessAndFailure' }
        @{ Name = 'Logoff';                    Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Setting = 'Success' }
        @{ Name = 'Special Logon';             Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Setting = 'Success' }
        @{ Name = 'Audit Policy Change';       Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Setting = 'Success' }
        @{ Name = 'Sensitive Privilege Use';   Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Setting = 'SuccessAndFailure' }
    )
}
