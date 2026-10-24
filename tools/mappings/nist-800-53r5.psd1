# Data for tools/Update-FrameworkCatalog.ps1: NIST SP 800-53 Rev 5.
# Read as data (literals, arrays and hashtables only); key order is kept.
# Checks: the named checks for each control or enhancement, by OSCAL control ID.
# Controls not listed are Manual.

@{
    Checks = @{
        'ac-2' = @('AC-GuestDisabled', 'AC-NoPasswordNotRequired')
        'ac-3' = @('AC-UacEnabled')
        'ac-6' = @('AC-LocalAdminCount')
        'ac-6.9' = @('AU-SensitivePrivilegeUse')
        'ac-6.10' = @('AC-UacEnabled', 'AC-UacSecureDesktop', 'AC-UacPromptBehavior')
        'ac-7' = @('AC-AccountLockout')
        'ac-8' = @('AC-LogonBanner')
        'ac-11' = @('AC-InactivityLock')
        'ac-11.1' = @('AC-InactivityLock')
        'ac-12' = @('AC-RdpIdleTimeout')
        'ac-17' = @('AC-RdpProtected')
        'ac-17.2' = @('AC-RdpProtected')
        'au-2' = @('AU-AuditPolicy')
        'au-4' = @('AU-SecurityLogSize')
        'au-8' = @('AU-TimeSync')
        'au-12' = @('AU-AuditPolicy')
        'cm-7' = @('CM-Smb1Disabled', 'CM-NonessentialServices', 'CM-AutoplayDisabled')
        'cm-11' = @('CM-AlwaysInstallElevated')
        'ia-2' = @('AC-NoPasswordNotRequired', 'IA-BlankPasswordConsoleOnly')
        'ia-2.8' = @('IA-NtlmV2Only')
        'ia-5.1' = @('IA-PasswordComplexity', 'IA-PasswordHistory', 'IA-StoredPasswordProtection')
        'mp-7' = @('MP-RemovableStorage')
        'sc-7' = @('SC-FirewallEnabled')
        'sc-7.5' = @('SC-FirewallEnabled')
        'sc-8' = @('SC-LegacyTlsDisabled')
        'sc-8.1' = @('SC-LegacyTlsDisabled')
        'sc-10' = @('AC-RdpIdleTimeout')
        'sc-13' = @('SC-FipsMode')
        'sc-28' = @('SC-BitLocker')
        'sc-28.1' = @('SC-BitLocker')
        'si-2' = @('SI-UpdateRecency')
        'si-3' = @('SI-AntivirusActive', 'SI-SignatureAge', 'SI-ScanRecency')
    }
}
