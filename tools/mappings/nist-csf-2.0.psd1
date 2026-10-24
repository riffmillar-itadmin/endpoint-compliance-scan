# Data for tools/Update-FrameworkCatalog.ps1: NIST CSF 2.0.
# Read as data (literals, arrays and hashtables only); key order is kept.
# Checks: the named checks that give endpoint evidence toward each subcategory.
# Subcategories not listed are Manual.

@{
    Checks = @{
        'PR.AA-01' = @('AC-GuestDisabled', 'AC-NoPasswordNotRequired', 'IA-PasswordComplexity', 'IA-PasswordHistory', 'IA-StoredPasswordProtection')
        'PR.AA-03' = @('IA-NtlmV2Only', 'AC-AccountLockout', 'IA-BlankPasswordConsoleOnly')
        'PR.AA-05' = @('AC-LocalAdminCount', 'AC-UacEnabled', 'AC-UacPromptBehavior')
        'PR.DS-01' = @('SC-BitLocker')
        'PR.DS-02' = @('SC-LegacyTlsDisabled', 'AC-RdpProtected')
        'PR.PS-01' = @('CM-Smb1Disabled', 'CM-NonessentialServices', 'CM-AutoplayDisabled', 'AC-InactivityLock', 'AC-LogonBanner', 'MP-RemovableStorage')
        'PR.PS-02' = @('SI-UpdateRecency')
        'PR.PS-04' = @('AU-AuditPolicy', 'AU-SecurityLogSize', 'AU-TimeSync')
        'PR.PS-05' = @('CM-AlwaysInstallElevated')
        'PR.IR-01' = @('SC-FirewallEnabled')
        'DE.CM-09' = @('SI-AntivirusActive', 'SI-SignatureAge', 'SI-ScanRecency')
    }
}
