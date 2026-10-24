# DISA Microsoft Windows 11 STIG, Version 2 Release 7 (benchmark date 01 Apr 2026):
# all 282 rules, by Vuln ID. Rule data from the processed STIG in Microsoft's
# PowerStig project (MIT), https://github.com/microsoft/PowerStig; STIG content is
# published by DISA at https://public.cyber.mil/stigs/. Titles here are short
# summaries; STIG Viewer has the full rule text. Levels are the severity categories.
# Field meanings are in frameworks/README.md.

@{
    Id = 'DISA-STIG-Win11'
    Name = 'DISA Windows 11 STIG V2R7'
    Source = 'https://public.cyber.mil/stigs/'
    StigId = 'Microsoft_Windows_11_STIG'
    Levels = @('CAT I', 'CAT II', 'CAT III')
    Complete = $true
    AppliesTo = @{ ProductTypes = @(1); MinBuild = 22000 }
    Thresholds = @{
        LockoutThresholdMax = 3
        LockoutDurationMinMinutes = 15
        MinPasswordLength = 14
        MinPasswordHistory = 24
        InactivityLockMaxSeconds = 900
        MinSecurityLogMB = 1000
        UacAdminPromptValues = @(2)
        UacUserPromptValues = @(0)
    }
    Requirements = @(
        @{
            Id = 'V-253297'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Account lockout duration: 15 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LockoutDuration'; Op = 'ge'; Value = 15; Also = @(0, -1) }
            )
        }
        @{
            Id = 'V-253298'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Account lockout threshold: 1 to 3'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LockoutBadCount'; Op = 'between'; Min = 1; Max = 3 }
            )
        }
        @{
            Id = 'V-253299'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Reset account lockout counter after: 15 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'ResetLockoutCount'; Op = 'ge'; Value = 15 }
            )
        }
        @{
            Id = 'V-253300'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Enforce password history: 24 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'PasswordHistorySize'; Op = 'ge'; Value = 24 }
            )
        }
        @{
            Id = 'V-253301'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Maximum password age: 1 to 60'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MaximumPasswordAge'; Op = 'between'; Min = 1; Max = 60 }
            )
        }
        @{
            Id = 'V-253302'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Minimum password age: 1 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MinimumPasswordAge'; Op = 'ge'; Value = 1 }
            )
        }
        @{
            Id = 'V-253303'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Minimum password length: 14 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MinimumPasswordLength'; Op = 'ge'; Value = 14 }
            )
        }
        @{
            Id = 'V-253304'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Password must meet complexity requirements: Enabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'PasswordComplexity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253305'
            Family = 'Account'
            Level = 'CAT I'
            Title = 'Store passwords using reversible encryption: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'ClearTextPassword'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253306'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Credential Validation: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253307'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Credential Validation: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253308'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security Group Management: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security Group Management'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253309'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit User Account Management: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'User Account Management'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253310'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit User Account Management: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'User Account Management'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253311'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Plug and Play Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Plug and Play Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253312'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Process Creation: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Process Creation'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253313'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Account Lockout: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Account Lockout'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253314'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Group Membership: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Group Membership'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253315'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logoff: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logoff'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253316'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logon: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253317'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logon: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253318'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Special Logon: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Special Logon'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253319'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit File Share: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'File Share'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253320'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit File Share: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'File Share'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253321'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Object Access Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Object Access Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253322'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Object Access Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Object Access Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253323'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Removable Storage: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Removable Storage'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253324'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Removable Storage: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Removable Storage'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253325'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Audit Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Audit Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253326'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Authentication Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Authentication Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253327'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Authorization Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Authorization Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253328'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Sensitive Privilege Use: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Sensitive Privilege Use'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253329'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Sensitive Privilege Use: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Sensitive Privilege Use'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253330'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit IPsec Driver: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'IPsec Driver'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253331'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other System Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other System Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253332'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other System Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other System Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253333'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security State Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security State Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253334'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security System Extension: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security System Extension'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253335'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit System Integrity: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'System Integrity'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253336'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit System Integrity: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'System Integrity'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253344'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Policy Change Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Policy Change Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253345'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Logon/Logoff Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Logon/Logoff Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253346'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Logon/Logoff Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Logon/Logoff Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253347'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Detailed File Share: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Detailed File Share'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253348'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit MPSSVC Rule-Level Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'MPSSVC Rule-Level Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-253349'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit MPSSVC Rule-Level Policy Change: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'MPSSVC Rule-Level Policy Change'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-253263'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Windows 11 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a Service.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253265'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253268'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Outdated or unused accounts provide penetration points that may go undetected.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253271'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Allowing other operating systems to run on a secure system may allow users to circumvent security.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253275'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'IIS is not installed by default.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253280'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Use of software certificates and their accompanying installation files for end users to access resources is less secu...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253295'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, th...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253254'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Features such as Credential Guard use virtualization-based security to protect information that could be used in cred...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253255'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Credential Guard uses virtualization-based security to protect information that could be used in credential theft att...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253256'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253257'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Secure Boot is a standard that ensures systems boot only to a trusted operating system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253259'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'If data at rest is unencrypted, it is vulnerable to disclosure.'
            Checks = @('SC-BitLocker')
        }
        @{
            Id = 'V-253262'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Utilizing an allowlist provides a configuration management method for allowing the execution of only authorized softw...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253264'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Malicious software can establish a base on individual desktops and servers.'
            Checks = @('SI-AntivirusActive')
        }
        @{
            Id = 'V-253266'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Allowing other operating systems to run on a secure system may allow security to be circumvented.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253267'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Shares which provide network access, must not exist on a workstation except for system-created administrative shares,...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253269'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'An account that does not have Administrator duties must not have Administrator rights.'
            Checks = @('AC-LocalAdminCount')
            Note = 'The STIG requires that only accounts with administrator duties are members; review the listed members.'
        }
        @{
            Id = 'V-253270'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253272'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'To minimize potential points of attack, local user accounts, other than built-in accounts and local administrator acc...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253273'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Passwords that do not expire increase exposure with a greater probability of being discovered or cracked.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253276'
            Family = 'Other'
            Level = 'CAT II'
            Title = '"SNMP" is not installed by default.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253278'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The "Telnet Client" is not installed by default.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253279'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The "TFTP Client" is not installed by default.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253281'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on ...'
            Checks = @('SC-FirewallEnabled')
        }
        @{
            Id = 'V-253282'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Allowing inbound access to domain workstations from other systems may allow lateral movement across systems if creden...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253290'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Accounts or groups given rights on a system may show up as unresolved SIDs for various reasons including deletion of ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253293'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253294'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Using applications that access the internet or have potential internet sources using administrative privileges expose...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253296'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'The Windows Time Service controls time synchronization settings.'
            Checks = @('AU-TimeSync')
            Note = 'The STIG also requires the time source to be authorized (domain hierarchy or approved NTP).'
        }
        @{
            Id = 'V-253428'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure websites protected with External Certificate Authority (ECA) server certificates are properly valida...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253470'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Without the use of multifactor authentication, the ease of access to privileged and nonprivileged functions is greatl...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253476'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-256893'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Internet Explorer 11 (IE11) is not supported on Windows 11 semi-annual channel.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-257592'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Having portproxy enabled or configured in Windows 10 could allow a man-in-the-middle attack.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-257770'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'When this policy setting is enabled, the operating system generates audit events when a process fails to start and th...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-268317'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Some features may communicate with the vendor, sending system information or downloading data or components for the f...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-268318'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Without Windows 11 systems being managed, devices could be rogue and become targets of an attacker.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278926'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278927'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278928'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278929'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278930'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278931'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278932'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278933'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253274.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253274.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253274.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253340'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253341'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253342'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253431.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253431.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253431.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253260.a'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'UseAdvancedStartup (FVE) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseAdvancedStartup'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253260.b'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'UseTPMPIN (FVE) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseTPMPIN'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253261'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MinimumPIN (FVE) >= 6'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\Software\Policies\Microsoft\FVE'; Name = 'MinimumPIN'; Op = 'ge'; Value = 6 }
            )
        }
        @{
            Id = 'V-253284'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'DisableExceptionChainValidation (kernel) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
                    Name = 'DisableExceptionChainValidation'
                    Op = 'eq'
                    Value = 0
                }
            )
        }
        @{
            Id = 'V-253287'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SMB1 (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253288'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'Start (mrxsmb10) = 4'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name = 'Start'; Op = 'eq'; Value = 4 }
            )
        }
        @{
            Id = 'V-253291'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowBluetooth (Connectivity) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity'; Name = 'AllowBluetooth'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253337'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (Application) >= 32768'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name = 'MaxSize'; Op = 'ge'; Value = 32768 }
            )
        }
        @{
            Id = 'V-253338'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (Security) >= 1024000'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Op = 'ge'; Value = 1024000 }
            )
        }
        @{
            Id = 'V-253339'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (System) >= 32768'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name = 'MaxSize'; Op = 'ge'; Value = 32768 }
            )
        }
        @{
            Id = 'V-253350'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoLockScreenCamera (Personalization) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name = 'NoLockScreenCamera'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253351'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'Value (webcam) = Deny'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
                    Name = 'Value'
                    Op = 'eq'
                    Value = 'Deny'
                }
            )
        }
        @{
            Id = 'V-253352'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoLockScreenSlideshow (Personalization) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name = 'NoLockScreenSlideshow'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253353'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableIpSourceRouting (Parameters) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name = 'DisableIpSourceRouting'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-253354'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableIPSourceRouting (Parameters) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'DisableIPSourceRouting'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-253355'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'EnableICMPRedirect (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'EnableICMPRedirect'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253356'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'NoNameReleaseOnDemand (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'; Name = 'NoNameReleaseOnDemand'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253357'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LocalAccountTokenFilterPolicy (System) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'LocalAccountTokenFilterPolicy'
                    Op = 'eq'
                    Value = 0
                }
            )
        }
        @{
            Id = 'V-253358'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'UseLogonCredential (Wdigest) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'; Name = 'UseLogonCredential'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253359.a'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SuppressionPolicy (runasuser) = 4096'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Classes\batfile\shell\runasuser'; Name = 'SuppressionPolicy'; Op = 'eq'; Value = 4096 }
            )
        }
        @{
            Id = 'V-253359.b'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SuppressionPolicy (runasuser) = 4096'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser'; Name = 'SuppressionPolicy'; Op = 'eq'; Value = 4096 }
            )
        }
        @{
            Id = 'V-253359.c'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SuppressionPolicy (runasuser) = 4096'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser'; Name = 'SuppressionPolicy'; Op = 'eq'; Value = 4096 }
            )
        }
        @{
            Id = 'V-253359.d'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SuppressionPolicy (runasuser) = 4096'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser'; Name = 'SuppressionPolicy'; Op = 'eq'; Value = 4096 }
            )
        }
        @{
            Id = 'V-253360'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowInsecureGuestAuth (LanmanWorkstation) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name = 'AllowInsecureGuestAuth'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253361'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NC_ShowSharedAccessUI (Network Connections) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name = 'NC_ShowSharedAccessUI'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253362.a'
            Family = 'Config'
            Level = 'CAT II'
            Title = '\\*\NETLOGON (HardenedPaths) = RequireMutualAuthentication=1, RequireIntegrity=1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
                    Name = '\\*\NETLOGON'
                    Op = 'eq'
                    Value = 'RequireMutualAuthentication=1, RequireIntegrity=1'
                }
            )
        }
        @{
            Id = 'V-253362.b'
            Family = 'Config'
            Level = 'CAT II'
            Title = '\\*\SYSVOL (HardenedPaths) = RequireMutualAuthentication=1, RequireIntegrity=1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
                    Name = '\\*\SYSVOL'
                    Op = 'eq'
                    Value = 'RequireMutualAuthentication=1, RequireIntegrity=1'
                }
            )
        }
        @{
            Id = 'V-253363'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EccCurves (00010002)'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253364'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fMinimizeConnections (GroupPolicy) in 3'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
                    Name = 'fMinimizeConnections'
                    Op = 'in'
                    Values = @(3)
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-253365'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fBlockNonDomain (GroupPolicy) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'; Name = 'fBlockNonDomain'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253366'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AutoConnectAllowedOEM (config) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'; Name = 'AutoConnectAllowedOEM'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253367'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'ProcessCreationIncludeCmdLine_Enabled (Audit) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
                    Name = 'ProcessCreationIncludeCmdLine_Enabled'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253368'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowProtectedCreds (CredentialsDelegation) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; Name = 'AllowProtectedCreds'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253369.a'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableVirtualizationBasedSecurity (DeviceGuard) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'EnableVirtualizationBasedSecurity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253369.b'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequirePlatformSecurityFeatures (DeviceGuard) in 1/3'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
                    Name = 'RequirePlatformSecurityFeatures'
                    Op = 'in'
                    Values = @(1, 3)
                }
            )
        }
        @{
            Id = 'V-253370'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LsaCfgFlags (DeviceGuard) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'LsaCfgFlags'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253371'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'HypervisorEnforcedCodeIntegrity (DeviceGuard) in 1/2'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
                    Name = 'HypervisorEnforcedCodeIntegrity'
                    Op = 'in'
                    Values = @(1, 2)
                }
            )
        }
        @{
            Id = 'V-253372'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DriverLoadPolicy (EarlyLaunch) in 1/3/8'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'; Name = 'DriverLoadPolicy'; Op = 'in'; Values = @(1, 3, 8) }
            )
        }
        @{
            Id = 'V-253373'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoGPOListChanges ({35378EAC-683F-11D2-A89A-00C04FBBCFA2}) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
                    Name = 'NoGPOListChanges'
                    Op = 'eq'
                    Value = 0
                }
            )
        }
        @{
            Id = 'V-253374'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableWebPnPDownload (Printers) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableWebPnPDownload'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253375'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoWebServices (Explorer) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoWebServices'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253376'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableHTTPPrinting (Printers) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableHTTPPrinting'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253377'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DevicePKInitEnabled (Parameters) in 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
                    Name = 'DevicePKInitEnabled'
                    Op = 'in'
                    Values = @(1)
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-253378'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DontDisplayNetworkSelectionUI (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'DontDisplayNetworkSelectionUI'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253379'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnumerateLocalUsers (System) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnumerateLocalUsers'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253380'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DCSettingIndex (0e796bdb-100d-47d6-a2d5-f7d2daa51f51) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
                    Name = 'DCSettingIndex'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253381'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'ACSettingIndex (0e796bdb-100d-47d6-a2d5-f7d2daa51f51) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
                    Name = 'ACSettingIndex'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253382'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'fAllowToGetHelp (Terminal Services) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fAllowToGetHelp'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253383'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RestrictRemoteClients (Rpc) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; Name = 'RestrictRemoteClients'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253384'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'MSAOptional (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'MSAOptional'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253385'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableInventory (AppCompat) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; Name = 'DisableInventory'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253386'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoAutoplayfornonVolume (Explorer) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'NoAutoplayfornonVolume'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253387'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoAutorun (Explorer) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutorun'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253388'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoDriveTypeAutoRun (Explorer) = 255'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'; Name = 'NoDriveTypeAutoRun'; Op = 'eq'; Value = 255 }
            )
        }
        @{
            Id = 'V-253389'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnhancedAntiSpoofing (FacialFeatures) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'; Name = 'EnhancedAntiSpoofing'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253390'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableWindowsConsumerFeatures (CloudContent) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableWindowsConsumerFeatures'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253391'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnumerateAdministrators (CredUI) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name = 'EnumerateAdministrators'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253392'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LimitEnhancedDiagnosticDataWindowsAnalytics (DataCollection) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
                    Name = 'LimitEnhancedDiagnosticDataWindowsAnalytics'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253393'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowTelemetry (DataCollection) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253394.a'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DODownloadMode (DeliveryOptimization) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name = 'DODownloadMode'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253394.b'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DODownloadMode (Config) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'
                    Name = 'DODownloadMode'
                    Op = 'eq'
                    Value = 0
                }
            )
        }
        @{
            Id = 'V-253395.a'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'ShellSmartScreenLevel (System) = Block'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'ShellSmartScreenLevel'; Op = 'eq'; Value = 'Block' }
            )
        }
        @{
            Id = 'V-253395.b'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSmartScreen (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableSmartScreen'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253396'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoDataExecutionPrevention (Explorer) in 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                    Name = 'NoDataExecutionPrevention'
                    Op = 'in'
                    Values = @(0)
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-253397'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'NoHeapTerminationOnCorruption (Explorer) in 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                    Name = 'NoHeapTerminationOnCorruption'
                    Op = 'in'
                    Values = @(0)
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-253398'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'PreXPSP2ShellProtocolBehavior (Explorer) in 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                    Name = 'PreXPSP2ShellProtocolBehavior'
                    Op = 'in'
                    Values = @(0)
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-253399'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowGameDVR (GameDVR) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Name = 'AllowGameDVR'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253400'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireSecurityDevice (PassportForWork) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'; Name = 'RequireSecurityDevice'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253401'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MinimumPINLength (PINComplexity) >= 6'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'; Name = 'MinimumPINLength'; Op = 'ge'; Value = 6 }
            )
        }
        @{
            Id = 'V-253402'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisablePasswordSaving (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'DisablePasswordSaving'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253403'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fDisableCdm (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fDisableCdm'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253404'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fPromptForPassword (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fPromptForPassword'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253405'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fEncryptRPCTraffic (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fEncryptRPCTraffic'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253406'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MinEncryptionLevel (Terminal Services) = 3'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'MinEncryptionLevel'; Op = 'eq'; Value = 3 }
            )
        }
        @{
            Id = 'V-253407'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableEnclosureDownload (Feeds) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name = 'DisableEnclosureDownload'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253408'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowBasicAuthInClear (Feeds) in 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
                    Name = 'AllowBasicAuthInClear'
                    Op = 'in'
                    Values = @(0)
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-253409'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowIndexingEncryptedStoresOrItems (Windows Search) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
                    Name = 'AllowIndexingEncryptedStoresOrItems'
                    Op = 'eq'
                    Value = 0
                }
            )
        }
        @{
            Id = 'V-253410'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableUserControl (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'EnableUserControl'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253411'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AlwaysInstallElevated (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253412'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SafeForScripting (Installer) in 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
                    Name = 'SafeForScripting'
                    Op = 'in'
                    Values = @(0)
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-253413'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableAutomaticRestartSignOn (System) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'DisableAutomaticRestartSignOn'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253414'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableScriptBlockLogging (ScriptBlockLogging) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                    Name = 'EnableScriptBlockLogging'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253415'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableTranscripting (Transcription) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableTranscripting'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253416'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AllowBasic (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowBasic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253417'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowUnencryptedTraffic (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowUnencryptedTraffic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253418'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AllowBasic (Service) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowBasic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253419'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowUnencryptedTraffic (Service) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowUnencryptedTraffic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253420'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableRunAs (Service) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'DisableRunAs'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253421'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowDigest (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowDigest'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253422.a'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LetAppsActivateWithVoiceAboveLock (AppPrivacy) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; Name = 'LetAppsActivateWithVoiceAboveLock'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-253422.b'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LetAppsActivateWithVoice (AppPrivacy) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; Name = 'LetAppsActivateWithVoice'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-253423'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowDomainPINLogon (System) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\Software\Policies\Microsoft\Windows\System'; Name = 'AllowDomainPINLogon'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253424'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowWindowsInkWorkspace (WindowsInkWorkspace) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace'; Name = 'AllowWindowsInkWorkspace'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253425'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableThirdPartySuggestions (CloudContent) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableThirdPartySuggestions'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253426'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DeviceEnumerationPolicy (Kernel DMA Protection) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection'; Name = 'DeviceEnumerationPolicy'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253434'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LimitBlankPasswordUse (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LimitBlankPasswordUse'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253437'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SCENoApplyLegacyAuditPolicy (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253438'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireSignOrSeal (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireSignOrSeal'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253439'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SealSecureChannel (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SealSecureChannel'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253440'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SignSecureChannel (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SignSecureChannel'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253441'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisablePasswordChange (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'DisablePasswordChange'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253442'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'MaximumPasswordAge (Parameters) between 1 and 30'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
                    Name = 'MaximumPasswordAge'
                    Op = 'between'
                    Min = 1
                    Max = 30
                }
            )
        }
        @{
            Id = 'V-253443'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireStrongKey (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireStrongKey'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253444'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'InactivityTimeoutSecs (System) between 1 and 900'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'InactivityTimeoutSecs'
                    Op = 'between'
                    Min = 1
                    Max = 900
                }
            )
        }
        @{
            Id = 'V-253445'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LegalNoticeText (System) is set'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LegalNoticeText'; Op = 'notempty' }
            )
            Note = 'The STIG requires the DoD notice and consent text; this check confirms one is set.'
        }
        @{
            Id = 'V-253446'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LegalNoticeCaption (System) is set'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LegalNoticeCaption'; Op = 'notempty' }
            )
            Note = 'The STIG requires the DoD notice and consent text; this check confirms one is set.'
        }
        @{
            Id = 'V-253447'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'CachedLogonsCount (Winlogon) between 0 and 10'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                    Name = 'CachedLogonsCount'
                    Op = 'between'
                    Min = 0
                    Max = 10
                }
            )
        }
        @{
            Id = 'V-253448'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SCRemoveOption (Winlogon) in 1/2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'SCRemoveOption'; Op = 'in'; Values = @(1, 2) }
            )
        }
        @{
            Id = 'V-253449'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireSecuritySignature (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
                    Name = 'RequireSecuritySignature'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253450'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnablePlainTextPassword (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
                    Name = 'EnablePlainTextPassword'
                    Op = 'eq'
                    Value = 0
                }
            )
        }
        @{
            Id = 'V-253451'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireSecuritySignature (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
                    Name = 'RequireSecuritySignature'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253453'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictAnonymousSAM (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253454'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictAnonymous (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253455'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EveryoneIncludesAnonymous (Lsa) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253456'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictNullSessAccess (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name = 'RestrictNullSessAccess'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253457'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RestrictRemoteSAM (Lsa) = O:BAG:BAD:(A;;RC;;;BA)'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictRemoteSAM'; Op = 'eq'; Value = 'O:BAG:BAD:(A;;RC;;;BA)' }
            )
        }
        @{
            Id = 'V-253458'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'allownullsessionfallback (MSV1_0) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0'; Name = 'allownullsessionfallback'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253459'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowOnlineID (pku2u) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u'; Name = 'AllowOnlineID'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253460'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SupportedEncryptionTypes (Parameters) = 2147483640'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
                    Name = 'SupportedEncryptionTypes'
                    Op = 'eq'
                    Value = 2147483640
                }
            )
        }
        @{
            Id = 'V-253461'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoLMHash (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253462'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LmCompatibilityLevel (Lsa) = 5'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Op = 'eq'; Value = 5 }
            )
        }
        @{
            Id = 'V-253463'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LDAPClientIntegrity (LDAP) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'; Name = 'LDAPClientIntegrity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253464'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NTLMMinClientSec (MSV1_0) = 537395200'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinClientSec'; Op = 'eq'; Value = 537395200 }
            )
        }
        @{
            Id = 'V-253465'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NTLMMinServerSec (MSV1_0) = 537395200'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinServerSec'; Op = 'eq'; Value = 537395200 }
            )
        }
        @{
            Id = 'V-253466'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'Enabled (FIPSAlgorithmPolicy) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'; Name = 'Enabled'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253467'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'ProtectionMode (Session Manager) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Name = 'ProtectionMode'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253468'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'FilterAdministratorToken (System) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'FilterAdministratorToken'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253469'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'ConsentPromptBehaviorAdmin (System) = 2'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'ConsentPromptBehaviorAdmin'
                    Op = 'eq'
                    Value = 2
                }
            )
        }
        @{
            Id = 'V-253471'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'ConsentPromptBehaviorUser (System) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'ConsentPromptBehaviorUser'
                    Op = 'eq'
                    Value = 0
                }
            )
        }
        @{
            Id = 'V-253472'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableInstallerDetection (System) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'EnableInstallerDetection'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253473'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSecureUIAPaths (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableSecureUIAPaths'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253474'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableLUA (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253475'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableVirtualization (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableVirtualization'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253477'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'NoToastApplicationNotificationOnLockScreen (PushNotifications) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
                    Name = 'NoToastApplicationNotificationOnLockScreen'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-253478'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SaveZoneInformation (Attachments) in 2'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
                    Name = 'SaveZoneInformation'
                    Op = 'in'
                    Values = @(2)
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-279688'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableUserAuth (MicrosoftAccount) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount'; Name = 'DisableUserAuth'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-253427.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root Certific...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253427.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root Certific...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253427.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root Certific...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253427.d'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root Certific...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253429.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253429.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253430.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253430.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253430.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-253433'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Guest account status: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'EnableGuestAccount'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253435'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Rename administrator account: not ''Administrator'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'NewAdministratorName'; Op = 'ne'; Value = 'Administrator' }
            )
        }
        @{
            Id = 'V-253436'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Rename guest account: not ''Guest'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'NewGuestName'; Op = 'ne'; Value = 'Guest' }
            )
        }
        @{
            Id = 'V-253452'
            Family = 'SecOpt'
            Level = 'CAT I'
            Title = 'Network access: Allow anonymous SID/Name translation: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LSAAnonymousNameLookup'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-253289'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Service seclogon is Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'Service'; Name = 'seclogon'; StartType = 'Disabled' }
            )
        }
        @{
            Id = 'V-253479'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Access Credential Manager as a trusted caller: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTrustedCredManAccessPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-253480'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Access this computer from the network: Administrators, Remote Desktop Users only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeNetworkLogonRight'; Op = 'only'; Identities = @('Administrators', 'Remote Desktop Users') }
            )
        }
        @{
            Id = 'V-253481'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Act as part of the operating system: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTcbPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-253482'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Allow log on locally: Administrators, Users only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeInteractiveLogonRight'; Op = 'only'; Identities = @('Administrators', 'Users') }
            )
        }
        @{
            Id = 'V-253483'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Back up files and directories: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeBackupPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253484'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Change the system time: Administrators, LOCAL SERVICE only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeSystemtimePrivilege'; Op = 'only'; Identities = @('Administrators', 'LOCAL SERVICE') }
            )
        }
        @{
            Id = 'V-253485'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create a pagefile: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreatePagefilePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253486'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Create a token object: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateTokenPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-253487'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create global objects: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateGlobalPrivilege'; Op = 'only'; Identities = @('Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE') }
            )
        }
        @{
            Id = 'V-253488'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create permanent shared objects: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreatePermanentPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-253489'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create symbolic links: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateSymbolicLinkPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253490'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Debug Programs: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDebugPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253491'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny access to this computer from the network: includes Enterprise Admins, Domain Admins, Local account, Guests'
            Checks = @()
            Expect = @(
                @{
                    Source = 'UserRight'
                    Name = 'SeDenyNetworkLogonRight'
                    Op = 'includes'
                    Identities = @('Enterprise Admins', 'Domain Admins', 'Local account', 'Guests')
                }
            )
        }
        @{
            Id = 'V-253492'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on as a batch job: includes Enterprise Admins, Domain Admins'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyBatchLogonRight'; Op = 'includes'; Identities = @('Enterprise Admins', 'Domain Admins') }
            )
        }
        @{
            Id = 'V-253493'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on as a service: includes Enterprise Admins, Domain Admins'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyServiceLogonRight'; Op = 'includes'; Identities = @('Enterprise Admins', 'Domain Admins') }
            )
        }
        @{
            Id = 'V-253494'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on locally: includes Enterprise Admins, Domain Admins, Guests'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyInteractiveLogonRight'; Op = 'includes'; Identities = @('Enterprise Admins', 'Domain Admins', 'Guests') }
            )
        }
        @{
            Id = 'V-253495'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on through Remote Desktop Services: includes Enterprise Admins, Domain Admins, Local account, Guests'
            Checks = @()
            Expect = @(
                @{
                    Source = 'UserRight'
                    Name = 'SeDenyRemoteInteractiveLogonRight'
                    Op = 'includes'
                    Identities = @('Enterprise Admins', 'Domain Admins', 'Local account', 'Guests')
                }
            )
        }
        @{
            Id = 'V-253496'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Enable computer and user accounts to be trusted for delegation: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeEnableDelegationPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-253497'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Force shutdown from a remote system: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeRemoteShutdownPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253498'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Impersonate a client after authentication: Administrators, LOCAL SERVICE, NETWORK SERVICE, RESTRICTED SERVICES\PrintSpoolerService, SERVICE only'
            Checks = @()
            Expect = @(
                @{
                    Source = 'UserRight'
                    Name = 'SeImpersonatePrivilege'
                    Op = 'only'
                    Identities = @('Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'RESTRICTED SERVICES\PrintSpoolerService', 'SERVICE')
                }
            )
        }
        @{
            Id = 'V-253499'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Load and unload device drivers: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeLoadDriverPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253500'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Lock pages in memory: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeLockMemoryPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-253501'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Manage auditing and security log: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeSecurityPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253502'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Modify firmware environment values: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeSystemEnvironmentPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253503'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Perform volume maintenance tasks: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeManageVolumePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253504'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Profile single process: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeProfileSingleProcessPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253505'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Restore files and directories: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeRestorePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253506'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Take ownership of files or other objects: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTakeOwnershipPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-253277'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature SimpleTCP is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'SimpleTCP'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-253285.a'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature MicrosoftWindowsPowerShellV2 is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'MicrosoftWindowsPowerShellV2'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-253285.b'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature MicrosoftWindowsPowerShellV2Root is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'MicrosoftWindowsPowerShellV2Root'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-253286'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature SMB1Protocol is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'SMB1Protocol'; State = 'Disabled' }
            )
        }
    )
}
