# Thresholds for Invoke-EndpointComplianceScan.ps1.
#
# Most frameworks leave these values to the organization, so they are defaults,
# not requirements. The numbers in comments are the NIST SP 800-171 Rev 2 (CMMC)
# requirements each one serves.
#
# Thresholds are applied in this order, later winning:
#   1. this file
#   2. the chosen framework's Thresholds (for example the STIG's 14-character
#      passwords, or PCI DSS's 30-minute lockout), in frameworks/*.psd1
#   3. ComplianceScan.local.psd1 beside the script, or the file -ProfilePath names
# To change a value, copy this file to ComplianceScan.local.psd1 and keep only
# the keys you change; the local file is gitignored. If your value is looser
# than one the framework sets, the scan warns and uses yours.

@{
    # 3.1.5: most members allowed in the local Administrators group.
    MaxLocalAdmins              = 2

    # 3.1.7: allowed UAC prompt behaviours (ConsentPromptBehaviorAdmin and
    # ConsentPromptBehaviorUser). Admin 0 elevates without asking, so it is left
    # out; the user values all either ask for credentials or deny.
    UacAdminPromptValues        = @(1, 2, 3, 4, 5)
    UacUserPromptValues         = @(0, 1, 3)

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
    # needs (Success, Failure or SuccessAndFailure). Names are the English
    # subcategory names; the scan matches them by GUID, so it works on any
    # Windows display language. The names it knows are in $AuditSubcategoryGuid
    # in the script.
    AuditSubcategories          = @(
        @{ Name = 'Credential Validation';     Setting = 'SuccessAndFailure' }
        @{ Name = 'Security Group Management'; Setting = 'Success' }
        @{ Name = 'User Account Management';   Setting = 'SuccessAndFailure' }
        @{ Name = 'Process Creation';          Setting = 'Success' }
        @{ Name = 'Account Lockout';           Setting = 'Failure' }
        @{ Name = 'Logon';                     Setting = 'SuccessAndFailure' }
        @{ Name = 'Logoff';                    Setting = 'Success' }
        @{ Name = 'Special Logon';             Setting = 'Success' }
        @{ Name = 'Audit Policy Change';       Setting = 'Success' }
        @{ Name = 'Sensitive Privilege Use';   Setting = 'SuccessAndFailure' }
    )
}
