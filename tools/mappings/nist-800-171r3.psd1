# Data for tools/Update-FrameworkCatalog.ps1: NIST SP 800-171 Rev 3.
# Read as data (literals, arrays and hashtables only); key order is kept.
# Checks: the named checks that give endpoint evidence for each requirement, by
# requirement number. Requirements not listed are Manual.

@{
    Families = @{
        'Access Control' = 'AC'
        'Awareness and Training' = 'AT'
        'Audit and Accountability' = 'AU'
        'Configuration Management' = 'CM'
        'Identification and Authentication' = 'IA'
        'Incident Response' = 'IR'
        'Maintenance' = 'MA'
        'Media Protection' = 'MP'
        'Personnel Security' = 'PS'
        'Physical Protection' = 'PE'
        'Risk Assessment' = 'RA'
        'Security Assessment and Monitoring' = 'CA'
        'System and Communications Protection' = 'SC'
        'System and Information Integrity' = 'SI'
        'Planning' = 'PL'
        'System and Services Acquisition' = 'SA'
        'Supply Chain Risk Management' = 'SR'
    }
    Checks = @{
        '03.01.01' = @('AC-GuestDisabled', 'AC-NoPasswordNotRequired')
        '03.01.02' = @('AC-UacEnabled')
        '03.01.05' = @('AC-LocalAdminCount')
        '03.01.07' = @('AC-UacEnabled', 'AC-UacSecureDesktop', 'AC-UacPromptBehavior', 'AU-SensitivePrivilegeUse')
        '03.01.08' = @('AC-AccountLockout')
        '03.01.09' = @('AC-LogonBanner')
        '03.01.10' = @('AC-InactivityLock')
        '03.01.11' = @('AC-RdpIdleTimeout')
        '03.01.12' = @('AC-RdpProtected')
        '03.03.01' = @('AU-AuditPolicy', 'AU-SecurityLogSize')
        '03.03.03' = @('AU-AuditPolicy')
        '03.03.07' = @('AU-TimeSync')
        '03.04.06' = @('CM-Smb1Disabled', 'CM-NonessentialServices', 'CM-AutoplayDisabled')
        '03.05.01' = @('AC-NoPasswordNotRequired', 'IA-BlankPasswordConsoleOnly')
        '03.05.04' = @('IA-NtlmV2Only')
        '03.05.07' = @('IA-PasswordComplexity', 'IA-PasswordHistory', 'IA-StoredPasswordProtection')
        '03.08.07' = @('MP-RemovableStorage')
        '03.13.01' = @('SC-FirewallEnabled')
        '03.13.06' = @('SC-FirewallEnabled')
        '03.13.08' = @('SC-LegacyTlsDisabled', 'SC-BitLocker')
        '03.13.09' = @('AC-RdpIdleTimeout')
        '03.13.11' = @('SC-FipsMode')
        '03.14.01' = @('SI-UpdateRecency')
        '03.14.02' = @('SI-AntivirusActive', 'SI-SignatureAge', 'SI-ScanRecency')
    }
}
