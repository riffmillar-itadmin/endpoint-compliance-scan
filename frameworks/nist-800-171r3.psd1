# NIST SP 800-171 Rev 3 (May 2024): all 97 security requirements still in force
# (withdrawn ones are left out). Generated from NIST's OSCAL catalog,
# https://github.com/usnistgov/oscal-content (nist.gov/SP800-171/rev3).
# Field meanings are in frameworks/README.md.

@{
    Id = 'NIST-800-171r3'
    Name = 'NIST SP 800-171 Rev 3'
    Source = 'https://csrc.nist.gov/pubs/sp/800/171/r3/final'
    Levels = @('Rev3')
    Complete = $true
    Thresholds = @{}
    Requirements = @(
        @{ Id = '03.01.01'; Family = 'AC'; Level = 'Rev3'; Title = 'Account Management'; Checks = @('AC-GuestDisabled', 'AC-NoPasswordNotRequired') }
        @{ Id = '03.01.02'; Family = 'AC'; Level = 'Rev3'; Title = 'Access Enforcement'; Checks = @('AC-UacEnabled') }
        @{
            Id = '03.01.03'
            Family = 'AC'
            Level = 'Rev3'
            Title = 'Information Flow Enforcement'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.01.04'
            Family = 'AC'
            Level = 'Rev3'
            Title = 'Separation of Duties'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = '03.01.05'; Family = 'AC'; Level = 'Rev3'; Title = 'Least Privilege'; Checks = @('AC-LocalAdminCount') }
        @{
            Id = '03.01.06'
            Family = 'AC'
            Level = 'Rev3'
            Title = 'Least Privilege - Privileged Accounts'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.01.07'
            Family = 'AC'
            Level = 'Rev3'
            Title = 'Least Privilege - Privileged Functions'
            Checks = @('AC-UacEnabled', 'AC-UacSecureDesktop', 'AC-UacPromptBehavior', 'AU-SensitivePrivilegeUse')
        }
        @{ Id = '03.01.08'; Family = 'AC'; Level = 'Rev3'; Title = 'Unsuccessful Logon Attempts'; Checks = @('AC-AccountLockout') }
        @{ Id = '03.01.09'; Family = 'AC'; Level = 'Rev3'; Title = 'System Use Notification'; Checks = @('AC-LogonBanner') }
        @{ Id = '03.01.10'; Family = 'AC'; Level = 'Rev3'; Title = 'Device Lock'; Checks = @('AC-InactivityLock') }
        @{ Id = '03.01.11'; Family = 'AC'; Level = 'Rev3'; Title = 'Session Termination'; Checks = @('AC-RdpIdleTimeout') }
        @{ Id = '03.01.12'; Family = 'AC'; Level = 'Rev3'; Title = 'Remote Access'; Checks = @('AC-RdpProtected') }
        @{
            Id = '03.01.16'
            Family = 'AC'
            Level = 'Rev3'
            Title = 'Wireless Access'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.01.18'
            Family = 'AC'
            Level = 'Rev3'
            Title = 'Access Control for Mobile Devices'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.01.20'
            Family = 'AC'
            Level = 'Rev3'
            Title = 'Use of External Systems'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.01.22'
            Family = 'AC'
            Level = 'Rev3'
            Title = 'Publicly Accessible Content'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.02.01'
            Family = 'AT'
            Level = 'Rev3'
            Title = 'Literacy Training and Awareness'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.02.02'
            Family = 'AT'
            Level = 'Rev3'
            Title = 'Role-Based Training'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = '03.03.01'; Family = 'AU'; Level = 'Rev3'; Title = 'Event Logging'; Checks = @('AU-AuditPolicy', 'AU-SecurityLogSize') }
        @{
            Id = '03.03.02'
            Family = 'AU'
            Level = 'Rev3'
            Title = 'Audit Record Content'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = '03.03.03'; Family = 'AU'; Level = 'Rev3'; Title = 'Audit Record Generation'; Checks = @('AU-AuditPolicy') }
        @{
            Id = '03.03.04'
            Family = 'AU'
            Level = 'Rev3'
            Title = 'Response to Audit Logging Process Failures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.03.05'
            Family = 'AU'
            Level = 'Rev3'
            Title = 'Audit Record Review, Analysis, and Reporting'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.03.06'
            Family = 'AU'
            Level = 'Rev3'
            Title = 'Audit Record Reduction and Report Generation'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = '03.03.07'; Family = 'AU'; Level = 'Rev3'; Title = 'Time Stamps'; Checks = @('AU-TimeSync') }
        @{
            Id = '03.03.08'
            Family = 'AU'
            Level = 'Rev3'
            Title = 'Protection of Audit Information'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.04.01'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'Baseline Configuration'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.04.02'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'Configuration Settings'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.04.03'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'Configuration Change Control'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.04.04'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'Impact Analyses'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.04.05'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'Access Restrictions for Change'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.04.06'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'Least Functionality'
            Checks = @('CM-Smb1Disabled', 'CM-NonessentialServices', 'CM-AutoplayDisabled')
        }
        @{
            Id = '03.04.08'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'Authorized Software - Allow by Exception'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.04.10'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'System Component Inventory'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.04.11'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'Information Location'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.04.12'
            Family = 'CM'
            Level = 'Rev3'
            Title = 'System and Component Configuration for High-Risk Areas'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.05.01'
            Family = 'IA'
            Level = 'Rev3'
            Title = 'User Identification and Authentication'
            Checks = @('AC-NoPasswordNotRequired', 'IA-BlankPasswordConsoleOnly')
        }
        @{
            Id = '03.05.02'
            Family = 'IA'
            Level = 'Rev3'
            Title = 'Device Identification and Authentication'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.05.03'
            Family = 'IA'
            Level = 'Rev3'
            Title = 'Multi-Factor Authentication'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = '03.05.04'; Family = 'IA'; Level = 'Rev3'; Title = 'Replay-Resistant Authentication'; Checks = @('IA-NtlmV2Only') }
        @{
            Id = '03.05.05'
            Family = 'IA'
            Level = 'Rev3'
            Title = 'Identifier Management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.05.07'
            Family = 'IA'
            Level = 'Rev3'
            Title = 'Password Management'
            Checks = @('IA-PasswordComplexity', 'IA-PasswordHistory', 'IA-StoredPasswordProtection')
        }
        @{
            Id = '03.05.11'
            Family = 'IA'
            Level = 'Rev3'
            Title = 'Authentication Feedback'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.05.12'
            Family = 'IA'
            Level = 'Rev3'
            Title = 'Authenticator Management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.06.01'
            Family = 'IR'
            Level = 'Rev3'
            Title = 'Incident Handling'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.06.02'
            Family = 'IR'
            Level = 'Rev3'
            Title = 'Incident Monitoring, Reporting, and Response Assistance'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.06.03'
            Family = 'IR'
            Level = 'Rev3'
            Title = 'Incident Response Testing'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.06.04'
            Family = 'IR'
            Level = 'Rev3'
            Title = 'Incident Response Training'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.06.05'
            Family = 'IR'
            Level = 'Rev3'
            Title = 'Incident Response Plan'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.07.04'
            Family = 'MA'
            Level = 'Rev3'
            Title = 'Maintenance Tools'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.07.05'
            Family = 'MA'
            Level = 'Rev3'
            Title = 'Nonlocal Maintenance'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.07.06'
            Family = 'MA'
            Level = 'Rev3'
            Title = 'Maintenance Personnel'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.08.01'
            Family = 'MP'
            Level = 'Rev3'
            Title = 'Media Storage'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.08.02'
            Family = 'MP'
            Level = 'Rev3'
            Title = 'Media Access'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.08.03'
            Family = 'MP'
            Level = 'Rev3'
            Title = 'Media Sanitization'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.08.04'
            Family = 'MP'
            Level = 'Rev3'
            Title = 'Media Marking'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.08.05'
            Family = 'MP'
            Level = 'Rev3'
            Title = 'Media Transport'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = '03.08.07'; Family = 'MP'; Level = 'Rev3'; Title = 'Media Use'; Checks = @('MP-RemovableStorage') }
        @{
            Id = '03.08.09'
            Family = 'MP'
            Level = 'Rev3'
            Title = 'System Backup - Cryptographic Protection'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.09.01'
            Family = 'PS'
            Level = 'Rev3'
            Title = 'Personnel Screening'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.09.02'
            Family = 'PS'
            Level = 'Rev3'
            Title = 'Personnel Termination and Transfer'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.10.01'
            Family = 'PE'
            Level = 'Rev3'
            Title = 'Physical Access Authorizations'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.10.02'
            Family = 'PE'
            Level = 'Rev3'
            Title = 'Monitoring Physical Access'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.10.06'
            Family = 'PE'
            Level = 'Rev3'
            Title = 'Alternate Work Site'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.10.07'
            Family = 'PE'
            Level = 'Rev3'
            Title = 'Physical Access Control'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.10.08'
            Family = 'PE'
            Level = 'Rev3'
            Title = 'Access Control for Transmission'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.11.01'
            Family = 'RA'
            Level = 'Rev3'
            Title = 'Risk Assessment'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.11.02'
            Family = 'RA'
            Level = 'Rev3'
            Title = 'Vulnerability Monitoring and Scanning'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.11.04'
            Family = 'RA'
            Level = 'Rev3'
            Title = 'Risk Response'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.12.01'
            Family = 'CA'
            Level = 'Rev3'
            Title = 'Security Assessment'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.12.02'
            Family = 'CA'
            Level = 'Rev3'
            Title = 'Plan of Action and Milestones'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.12.03'
            Family = 'CA'
            Level = 'Rev3'
            Title = 'Continuous Monitoring'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.12.05'
            Family = 'CA'
            Level = 'Rev3'
            Title = 'Information Exchange'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = '03.13.01'; Family = 'SC'; Level = 'Rev3'; Title = 'Boundary Protection'; Checks = @('SC-FirewallEnabled') }
        @{
            Id = '03.13.04'
            Family = 'SC'
            Level = 'Rev3'
            Title = 'Information in Shared System Resources'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.13.06'
            Family = 'SC'
            Level = 'Rev3'
            Title = 'Network Communications - Deny by Default - Allow by Exception'
            Checks = @('SC-FirewallEnabled')
        }
        @{
            Id = '03.13.08'
            Family = 'SC'
            Level = 'Rev3'
            Title = 'Transmission and Storage Confidentiality'
            Checks = @('SC-LegacyTlsDisabled', 'SC-BitLocker')
        }
        @{ Id = '03.13.09'; Family = 'SC'; Level = 'Rev3'; Title = 'Network Disconnect'; Checks = @('AC-RdpIdleTimeout') }
        @{
            Id = '03.13.10'
            Family = 'SC'
            Level = 'Rev3'
            Title = 'Cryptographic Key Establishment and Management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = '03.13.11'; Family = 'SC'; Level = 'Rev3'; Title = 'Cryptographic Protection'; Checks = @('SC-FipsMode') }
        @{
            Id = '03.13.12'
            Family = 'SC'
            Level = 'Rev3'
            Title = 'Collaborative Computing Devices and Applications'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.13.13'
            Family = 'SC'
            Level = 'Rev3'
            Title = 'Mobile Code'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.13.15'
            Family = 'SC'
            Level = 'Rev3'
            Title = 'Session Authenticity'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = '03.14.01'; Family = 'SI'; Level = 'Rev3'; Title = 'Flaw Remediation'; Checks = @('SI-UpdateRecency') }
        @{
            Id = '03.14.02'
            Family = 'SI'
            Level = 'Rev3'
            Title = 'Malicious Code Protection'
            Checks = @('SI-AntivirusActive', 'SI-SignatureAge', 'SI-ScanRecency')
        }
        @{
            Id = '03.14.03'
            Family = 'SI'
            Level = 'Rev3'
            Title = 'Security Alerts, Advisories, and Directives'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.14.06'
            Family = 'SI'
            Level = 'Rev3'
            Title = 'System Monitoring'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.14.08'
            Family = 'SI'
            Level = 'Rev3'
            Title = 'Information Management and Retention'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.15.01'
            Family = 'PL'
            Level = 'Rev3'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.15.02'
            Family = 'PL'
            Level = 'Rev3'
            Title = 'System Security Plan'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.15.03'
            Family = 'PL'
            Level = 'Rev3'
            Title = 'Rules of Behavior'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.16.01'
            Family = 'SA'
            Level = 'Rev3'
            Title = 'Security Engineering Principles'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.16.02'
            Family = 'SA'
            Level = 'Rev3'
            Title = 'Unsupported System Components'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.16.03'
            Family = 'SA'
            Level = 'Rev3'
            Title = 'External System Services'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.17.01'
            Family = 'SR'
            Level = 'Rev3'
            Title = 'Supply Chain Risk Management Plan'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.17.02'
            Family = 'SR'
            Level = 'Rev3'
            Title = 'Acquisition Strategies, Tools, and Methods'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '03.17.03'
            Family = 'SR'
            Level = 'Rev3'
            Title = 'Supply Chain Requirements and Processes'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
    )
}
