# PCI DSS v4.0.1: 22 requirements.
# This catalog lists only the requirements that a Windows endpoint can show evidence for, with
# titles written for this project; the standard itself has the authoritative text and
# the full list. Complete = $false makes every report say so.
# The standard is published by the PCI Security Standards Council, https://www.pcisecuritystandards.org.
# Field meanings are in frameworks/README.md.

@{
    Id = 'PCI-DSS-4.0.1'
    Name = 'PCI DSS v4.0.1 (endpoint requirements)'
    Source = 'https://www.pcisecuritystandards.org/document_library/'
    Levels = @('PCI')
    Complete = $false
    Thresholds = @{
        LockoutThresholdMax = 10
        LockoutDurationMinMinutes = 30
        MinPasswordLength = 12
        MinPasswordHistory = 4
        MaxDaysSinceUpdate = 30
        InactivityLockMaxSeconds = 900
        RdpIdleMaxMinutes = 15
    }
    Requirements = @(
        @{
            Id = '1.5.1'
            Family = 'R01'
            Level = 'PCI'
            Title = 'Firewall on devices that connect to both untrusted networks and the CDE'
            Checks = @('SC-FirewallEnabled')
        }
        @{
            Id = '2.2.4'
            Family = 'R02'
            Level = 'PCI'
            Title = 'Only necessary services, protocols and functions are enabled'
            Checks = @('CM-NonessentialServices', 'CM-Smb1Disabled', 'CM-AutoplayDisabled')
        }
        @{
            Id = '2.2.7'
            Family = 'R02'
            Level = 'PCI'
            Title = 'Non-console administrative access is encrypted'
            Checks = @('AC-RdpProtected', 'SC-LegacyTlsDisabled')
        }
        @{
            Id = '4.2.1'
            Family = 'R04'
            Level = 'PCI'
            Title = 'Strong cryptography protects account data in transit'
            Checks = @('SC-LegacyTlsDisabled')
            Note = 'Shows the endpoint protocol configuration; certificates and the flows that carry account data are reviewed separately.'
        }
        @{ Id = '5.2.1'; Family = 'R05'; Level = 'PCI'; Title = 'Anti-malware is deployed'; Checks = @('SI-AntivirusActive') }
        @{ Id = '5.3.1'; Family = 'R05'; Level = 'PCI'; Title = 'Anti-malware is kept current'; Checks = @('SI-SignatureAge') }
        @{
            Id = '5.3.2'
            Family = 'R05'
            Level = 'PCI'
            Title = 'Anti-malware scans periodically or analyzes continuously'
            Checks = @('SI-AntivirusActive', 'SI-ScanRecency')
        }
        @{
            Id = '6.3.3'
            Family = 'R06'
            Level = 'PCI'
            Title = 'Security patches are installed promptly'
            Checks = @('SI-UpdateRecency')
            Note = 'PCI DSS sets one month for critical patches; the threshold uses that for the newest update.'
        }
        @{ Id = '7.2.2'; Family = 'R07'; Level = 'PCI'; Title = 'Access follows job duties and least privilege'; Checks = @('AC-LocalAdminCount') }
        @{ Id = '8.2.1'; Family = 'R08'; Level = 'PCI'; Title = 'Every user has a unique ID'; Checks = @('AC-GuestDisabled') }
        @{
            Id = '8.2.8'
            Family = 'R08'
            Level = 'PCI'
            Title = 'Idle sessions over 15 minutes need re-authentication'
            Checks = @('AC-InactivityLock', 'AC-RdpIdleTimeout')
        }
        @{
            Id = '8.3.1'
            Family = 'R08'
            Level = 'PCI'
            Title = 'User access is authenticated'
            Checks = @('AC-NoPasswordNotRequired', 'IA-BlankPasswordConsoleOnly')
        }
        @{
            Id = '8.3.2'
            Family = 'R08'
            Level = 'PCI'
            Title = 'Authentication factors are unreadable in storage and transit'
            Checks = @('IA-StoredPasswordProtection', 'IA-NtlmV2Only')
        }
        @{ Id = '8.3.4'; Family = 'R08'; Level = 'PCI'; Title = 'Accounts lock after repeated failed logons'; Checks = @('AC-AccountLockout') }
        @{ Id = '8.3.6'; Family = 'R08'; Level = 'PCI'; Title = 'Passwords meet minimum length and complexity'; Checks = @('IA-PasswordComplexity') }
        @{ Id = '8.3.7'; Family = 'R08'; Level = 'PCI'; Title = 'New passwords differ from recent ones'; Checks = @('IA-PasswordHistory') }
        @{ Id = '10.2.1'; Family = 'R10'; Level = 'PCI'; Title = 'Audit logs are enabled'; Checks = @('AU-AuditPolicy') }
        @{ Id = '10.2.1.2'; Family = 'R10'; Level = 'PCI'; Title = 'Administrative actions are logged'; Checks = @('AU-SensitivePrivilegeUse') }
        @{
            Id = '10.2.1.4'
            Family = 'R10'
            Level = 'PCI'
            Title = 'Invalid logon attempts are logged'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Failure' }
                @{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Failure' }
            )
        }
        @{
            Id = '10.2.1.5'
            Family = 'R10'
            Level = 'PCI'
            Title = 'Changes to accounts and credentials are logged'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'User Account Management'; Setting = 'Success' }
            )
        }
        @{
            Id = '10.5.1'
            Family = 'R10'
            Level = 'PCI'
            Title = 'Audit log history is retained'
            Checks = @('AU-SecurityLogSize')
            Note = 'PCI DSS asks for 12 months, 3 immediately available; that is usually met by central log storage, which is reviewed separately.'
        }
        @{ Id = '10.6.1'; Family = 'R10'; Level = 'PCI'; Title = 'Clocks are synchronized'; Checks = @('AU-TimeSync') }
    )
}
