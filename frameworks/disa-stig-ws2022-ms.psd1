# DISA Microsoft Windows Server 2022 STIG (member server), Version 2 Release 11
# (benchmark date 30 Sep 2026): all 242 rules, by Vuln ID. Rules and severities from
# DISA's STIG (U_MS_Windows_Server_2022_STIG_V2R11_Manual-xccdf.xml); automated
# checks from the processed STIG WindowsServer-2022-MS-2.8 in Microsoft's PowerStig
# project (MIT), https://github.com/microsoft/PowerStig; STIG content is published
# by DISA at https://public.cyber.mil/stigs/. Titles here are short summaries; STIG
# Viewer has the full rule text. Levels are the severity categories.
# Field meanings are in frameworks/README.md.

@{
    Id = 'DISA-STIG-WS2022-MS'
    Name = 'DISA Windows Server 2022 member server STIG V2R11'
    Source = 'https://public.cyber.mil/stigs/'
    StigId = 'MS_Windows_Server_2022_MS_STIG'
    Levels = @('CAT I', 'CAT II', 'CAT III')
    Complete = $true
    AppliesTo = @{ ProductTypes = @(3); Builds = @(20348) }
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
            Id = 'V-254285'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Account lockout duration: 15 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LockoutDuration'; Op = 'ge'; Value = 15; Also = @(0, -1) }
            )
        }
        @{
            Id = 'V-254286'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Account lockout threshold: 1 to 3'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LockoutBadCount'; Op = 'between'; Min = 1; Max = 3 }
            )
        }
        @{
            Id = 'V-254287'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Reset account lockout counter after: 15 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'ResetLockoutCount'; Op = 'ge'; Value = 15 }
            )
        }
        @{
            Id = 'V-254288'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Enforce password history: 24 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'PasswordHistorySize'; Op = 'ge'; Value = 24 }
            )
        }
        @{
            Id = 'V-254289'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Maximum password age: 1 to 180'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MaximumPasswordAge'; Op = 'between'; Min = 1; Max = 180 }
            )
        }
        @{
            Id = 'V-254290'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Minimum password age: not ''0'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MinimumPasswordAge'; Op = 'ne'; Value = '0' }
            )
        }
        @{
            Id = 'V-254291'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Minimum password length: 14 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MinimumPasswordLength'; Op = 'ge'; Value = 14 }
            )
        }
        @{
            Id = 'V-254292'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Password must meet complexity requirements: Enabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'PasswordComplexity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254293'
            Family = 'Account'
            Level = 'CAT I'
            Title = 'Store passwords using reversible encryption: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'ClearTextPassword'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254300'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Credential Validation: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254301'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Credential Validation: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254302'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Account Management Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Account Management Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254303'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security Group Management: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security Group Management'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254304'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit User Account Management: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'User Account Management'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254305'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit User Account Management: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'User Account Management'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254306'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Plug and Play Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Plug and Play Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254307'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Process Creation: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Process Creation'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254309'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Account Lockout: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Account Lockout'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254310'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Group Membership: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Group Membership'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254311'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logoff: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logoff'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254312'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logon: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254313'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logon: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254314'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Special Logon: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Special Logon'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254315'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Object Access Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Object Access Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254316'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Object Access Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Object Access Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254317'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Removable Storage: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Removable Storage'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254318'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Removable Storage: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Removable Storage'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254319'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Audit Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Audit Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254320'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Audit Policy Change: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Audit Policy Change'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254321'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Authentication Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Authentication Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254322'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Authorization Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Authorization Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254323'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Sensitive Privilege Use: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Sensitive Privilege Use'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254324'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Sensitive Privilege Use: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Sensitive Privilege Use'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254325'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit IPsec Driver: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'IPsec Driver'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254326'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit IPsec Driver: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'IPsec Driver'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254327'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other System Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other System Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254328'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other System Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other System Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254329'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security State Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security State Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254330'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security System Extension: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security System Extension'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254331'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit System Integrity: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'System Integrity'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-254332'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit System Integrity: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'System Integrity'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-254247'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Systems at unsupported servicing levels will not receive security updates for new vulnerabilities, which leave them s...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254250'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254244'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Shared accounts (accounts where two or more people log on with the same user identification) do not provide adequate ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254249'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'A properly configured Host-based Intrusion Detection System (HIDS) and Host-based Intrusion Prevention System (HIPS) ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254256'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Outdated or unused accounts provide penetration points that may go undetected.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254261'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Use of software certificates and their accompanying installation files for end users to access resources is less secu...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254264'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Unnecessary roles and features increase the attack surface of a system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254238'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadverte...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254239'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254240'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Using applications that access the internet or have potential internet sources using administrative privileges expose...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254241'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254242'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Application/service account passwords must be of sufficient length to prevent being easily cracked.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254243'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Setting application account passwords to expire may cause applications to stop functioning.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254245'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Using an allowlist provides a configuration management method to allow the execution of only authorized software.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254246'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254255'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Windows shares are a means by which files, folders, printers, and other resources can be published for network users ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254257'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor oppor...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254258'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being disc...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254259'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction o...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254260'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Shares on a system provide network access.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254262'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'This requirement addresses protection of user-generated data as well as operating system-specific configuration data.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254263'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, f...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254267'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254268'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Emergency administrator accounts are privileged accounts established in response to crisis situations where the need ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254279'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The FTP service allows remote users to access shared files and directories.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254280'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The FTP service allows remote users to access shared files and directories that could provide access to system resour...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254281'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'The Windows Time Service controls time synchronization settings.'
            Checks = @('AU-TimeSync')
            Note = 'The STIG also requires the time source to be authorized (domain hierarchy or approved NTP).'
        }
        @{
            Id = 'V-254283'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254284'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Secure Boot is a standard that ensures systems boot only to a trusted operating system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254294'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Protection of log data includes ensuring the log data is not accidentally lost or deleted.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254295'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Protection of log data includes assuring the log data is not accidentally lost or deleted.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254428'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'An account that does not have Administrator duties must not have Administrator rights.'
            Checks = @('AC-LocalAdminCount')
            Note = 'The STIG requires that only accounts with administrator duties are members; review the listed members.'
        }
        @{
            Id = 'V-254444'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278944'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278946'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278947'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278948'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278949'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254282'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Accounts or groups given rights on a system may show up as unresolved SIDs for various reasons including deletion of ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254251'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254252.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254252.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254253'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254254.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254254.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254254.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254296'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254297'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254298'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254299'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254276'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SMB1 (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
                    Name = 'SMB1'
                    Op = 'eq'
                    Value = 0
                    NotApplicableIf = @{
                        Rules = @('V-254275')
                        Expect = @(
                            @{ Source = 'Feature'; Name = 'FS-SMB1'; State = 'Disabled' }
                        )
                    }
                }
            )
        }
        @{
            Id = 'V-254277'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'Start (mrxsmb10) = 4'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
                    Name = 'Start'
                    Op = 'eq'
                    Value = 4
                    NotApplicableIf = @{
                        Rules = @('V-254275')
                        Expect = @(
                            @{ Source = 'Feature'; Name = 'FS-SMB1'; State = 'Disabled' }
                        )
                    }
                }
            )
        }
        @{
            Id = 'V-254333'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoLockScreenSlideshow (Personalization) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name = 'NoLockScreenSlideshow'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254334'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'UseLogonCredential (Wdigest) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'; Name = 'UseLogonCredential'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254335'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableIPSourceRouting (Parameters) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name = 'DisableIPSourceRouting'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-254336'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableIPSourceRouting (Parameters) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'DisableIPSourceRouting'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-254337'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'EnableICMPRedirect (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'EnableICMPRedirect'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254338'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'NoNameReleaseOnDemand (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'; Name = 'NoNameReleaseOnDemand'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254339'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowInsecureGuestAuth (LanmanWorkstation) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name = 'AllowInsecureGuestAuth'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254340.a'
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
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-254340.b'
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
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-254341'
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
            Id = 'V-254342'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowProtectedCreds (CredentialsDelegation) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; Name = 'AllowProtectedCreds'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254343.a'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableVirtualizationBasedSecurity (DeviceGuard) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
                    Name = 'EnableVirtualizationBasedSecurity'
                    Op = 'eq'
                    Value = 1
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-254343.b'
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
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-254344'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DriverLoadPolicy (EarlyLaunch) in 1/3/8'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
                    Name = 'DriverLoadPolicy'
                    Op = 'in'
                    Values = @(1, 3, 8)
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-254345'
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
            Id = 'V-254346'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableWebPnPDownload (Printers) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableWebPnPDownload'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254347'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableHTTPPrinting (Printers) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableHTTPPrinting'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254348'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DontDisplayNetworkSelectionUI (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'DontDisplayNetworkSelectionUI'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254349'
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
            Id = 'V-254350'
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
            Id = 'V-254351'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableInventory (AppCompat) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; Name = 'DisableInventory'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254352'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoAutoplayfornonVolume (Explorer) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'NoAutoplayfornonVolume'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254353'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoAutorun (Explorer) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutorun'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254354'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoDriveTypeAutoRun (Explorer) = 255'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'; Name = 'NoDriveTypeAutoRun'; Op = 'eq'; Value = 255 }
            )
        }
        @{
            Id = 'V-254355'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnumerateAdministrators (CredUI) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name = 'EnumerateAdministrators'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254356'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowTelemetry (DataCollection) in 1/3'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Op = 'in'; Values = @(1, 3) }
            )
        }
        @{
            Id = 'V-254357'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DODownloadMode (DeliveryOptimization) in 0/1/2/99/100'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
                    Name = 'DODownloadMode'
                    Op = 'in'
                    Values = @(0, 1, 2, 99, 100)
                }
            )
        }
        @{
            Id = 'V-254358'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (Application) >= 32768'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name = 'MaxSize'; Op = 'ge'; Value = 32768 }
            )
        }
        @{
            Id = 'V-254359'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (Security) >= 5120000'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Op = 'ge'; Value = 5120000 }
            )
            Note = 'DISA''s value is an example: the Security log must hold at least one week of records in your environment.'
        }
        @{
            Id = 'V-254360'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (System) >= 32768'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name = 'MaxSize'; Op = 'ge'; Value = 32768 }
            )
        }
        @{
            Id = 'V-254361'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSmartScreen (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableSmartScreen'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254362'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoDataExecutionPrevention (Explorer) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                    Name = 'NoDataExecutionPrevention'
                    Op = 'eq'
                    Value = 0
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-254363'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'NoHeapTerminationOnCorruption (Explorer) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
                    Name = 'NoHeapTerminationOnCorruption'
                    Op = 'eq'
                    Value = 0
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-254364'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'PreXPSP2ShellProtocolBehavior (Explorer) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                    Name = 'PreXPSP2ShellProtocolBehavior'
                    Op = 'eq'
                    Value = 0
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-254365'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisablePasswordSaving (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'DisablePasswordSaving'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254366'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fDisableCdm (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fDisableCdm'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254367'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fPromptForPassword (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fPromptForPassword'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254368'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fEncryptRPCTraffic (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fEncryptRPCTraffic'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254369'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MinEncryptionLevel (Terminal Services) = 3'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'MinEncryptionLevel'; Op = 'eq'; Value = 3 }
            )
        }
        @{
            Id = 'V-254370'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableEnclosureDownload (Feeds) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name = 'DisableEnclosureDownload'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254371'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowBasicAuthInClear (Feeds) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
                    Name = 'AllowBasicAuthInClear'
                    Op = 'eq'
                    Value = 0
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-254372'
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
            Id = 'V-254373'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableUserControl (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'EnableUserControl'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254374'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AlwaysInstallElevated (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254375'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SafeForScripting (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'SafeForScripting'; Op = 'eq'; Value = 0; AbsentOk = $true }
            )
        }
        @{
            Id = 'V-254376'
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
            Id = 'V-254377'
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
            Id = 'V-254378'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AllowBasic (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowBasic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254379'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowUnencryptedTraffic (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowUnencryptedTraffic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254380'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowDigest (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowDigest'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254381'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AllowBasic (Service) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowBasic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254382'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowUnencryptedTraffic (Service) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowUnencryptedTraffic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254383'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableRunAs (Service) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'DisableRunAs'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254384'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableTranscripting (Transcription) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableTranscripting'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254429'
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
            Id = 'V-254430'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnumerateLocalUsers (System) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnumerateLocalUsers'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254431'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RestrictRemoteClients (Rpc) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; Name = 'RestrictRemoteClients'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254432'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'CachedLogonsCount (Winlogon) between 0 and 4'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                    Name = 'CachedLogonsCount'
                    Op = 'between'
                    Min = 0
                    Max = 4
                }
            )
        }
        @{
            Id = 'V-254433'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RestrictRemoteSAM (Lsa) = O:BAG:BAD:(A;;RC;;;BA)'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictRemoteSAM'; Op = 'eq'; Value = 'O:BAG:BAD:(A;;RC;;;BA)' }
            )
        }
        @{
            Id = 'V-254441'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LsaCfgFlags (DeviceGuard) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'LsaCfgFlags'; Op = 'eq'; Value = 1; DomainOnly = $true }
            )
        }
        @{
            Id = 'V-254446'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LimitBlankPasswordUse (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LimitBlankPasswordUse'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254449'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SCENoApplyLegacyAuditPolicy (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254450'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireSignOrSeal (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireSignOrSeal'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254451'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SealSecureChannel (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SealSecureChannel'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254452'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SignSecureChannel (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SignSecureChannel'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254453'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisablePasswordChange (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'DisablePasswordChange'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254454'
            Family = 'Config'
            Level = 'CAT II'
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
            Id = 'V-254455'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireStrongKey (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireStrongKey'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254456'
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
            Id = 'V-254457'
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
            Id = 'V-254459'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'scremoveoption (Winlogon) in 1/2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'scremoveoption'; Op = 'in'; Values = @(1, 2) }
            )
        }
        @{
            Id = 'V-254460'
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
            Id = 'V-254461'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSecuritySignature (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
                    Name = 'EnableSecuritySignature'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-254462'
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
            Id = 'V-254463'
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
            Id = 'V-254464'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSecuritySignature (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name = 'EnableSecuritySignature'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254466'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictAnonymousSAM (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254467'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictAnonymous (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254468'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EveryoneIncludesAnonymous (Lsa) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254469'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictNullSessAccess (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name = 'RestrictNullSessAccess'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254470'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'UseMachineId (LSA) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA'; Name = 'UseMachineId'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254471'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'allownullsessionfallback (MSV1_0) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0'; Name = 'allownullsessionfallback'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254472'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowOnlineID (pku2u) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u'; Name = 'AllowOnlineID'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254473'
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
            Id = 'V-254474'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoLMHash (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254475'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LmCompatibilityLevel (Lsa) = 5'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Op = 'eq'; Value = 5 }
            )
        }
        @{
            Id = 'V-254476'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LDAPClientIntegrity (LDAP) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'; Name = 'LDAPClientIntegrity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254477'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NTLMMinClientSec (MSV1_0) = 537395200'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinClientSec'; Op = 'eq'; Value = 537395200 }
            )
        }
        @{
            Id = 'V-254478'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NTLMMinServerSec (MSV1_0) = 537395200'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinServerSec'; Op = 'eq'; Value = 537395200 }
            )
        }
        @{
            Id = 'V-254479'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'ForceKeyProtection (Cryptography) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography'; Name = 'ForceKeyProtection'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-254480'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'Enabled (FIPSAlgorithmPolicy) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'; Name = 'Enabled'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254481'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'ProtectionMode (Session Manager) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Name = 'ProtectionMode'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254482'
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
            Id = 'V-254483'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableUIADesktopToggle (System) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableUIADesktopToggle'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254484'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'ConsentPromptBehaviorAdmin (System) in 1/2'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'ConsentPromptBehaviorAdmin'
                    Op = 'in'
                    Values = @(1, 2)
                }
            )
        }
        @{
            Id = 'V-254485'
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
            Id = 'V-254486'
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
            Id = 'V-254487'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSecureUIAPaths (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableSecureUIAPaths'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254488'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableLUA (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254489'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableVirtualization (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableVirtualization'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-254490'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SaveZoneInformation (Attachments) = 2'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
                    Name = 'SaveZoneInformation'
                    Op = 'eq'
                    Value = 2
                    AbsentOk = $true
                }
            )
        }
        @{
            Id = 'V-254442.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254442.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254442.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254442.d'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254443'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254465'
            Family = 'SecOpt'
            Level = 'CAT I'
            Title = 'Network access: Allow anonymous SID/Name translation: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LSAAnonymousNameLookup'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254445'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Guest account status: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'EnableGuestAccount'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-254447'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Rename administrator account: not ''Administrator'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'NewAdministratorName'; Op = 'ne'; Value = 'Administrator' }
            )
        }
        @{
            Id = 'V-254448'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Rename guest account: not ''Guest'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'NewGuestName'; Op = 'ne'; Value = 'Guest' }
            )
        }
        @{
            Id = 'V-254248'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Malicious software can establish a base on individual desktops and servers.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254265'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-254434'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Access this computer from the network: Administrators, Authenticated Users only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeNetworkLogonRight'; Op = 'only'; Identities = @('Administrators', 'Authenticated Users') }
            )
        }
        @{
            Id = 'V-254435'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny access to this computer from the network: includes Enterprise Admins, Domain Admins, Local account and member of Administrators group or Local account, Guests'
            Checks = @()
            Expect = @(
                @{
                    Source = 'UserRight'
                    Name = 'SeDenyNetworkLogonRight'
                    Op = 'includes'
                    Identities = @('Enterprise Admins', 'Domain Admins', 'Local account and member of Administrators group|Local account', 'Guests')
                }
            )
        }
        @{
            Id = 'V-254436'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on as a batch job: includes Enterprise Admins, Domain Admins, Guests'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyBatchLogonRight'; Op = 'includes'; Identities = @('Enterprise Admins', 'Domain Admins', 'Guests') }
            )
        }
        @{
            Id = 'V-254437'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on as a service: Enterprise Admins, Domain Admins only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyServiceLogonRight'; Op = 'only'; Identities = @('Enterprise Admins', 'Domain Admins') }
            )
        }
        @{
            Id = 'V-254438'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on locally: includes Enterprise Admins, Domain Admins, Guests'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyInteractiveLogonRight'; Op = 'includes'; Identities = @('Enterprise Admins', 'Domain Admins', 'Guests') }
            )
        }
        @{
            Id = 'V-254439'
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
            Id = 'V-254440'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Enable computer and user accounts to be trusted for delegation: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeEnableDelegationPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-254491'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Access Credential Manager as a trusted caller: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTrustedCredManAccessPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-254492'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Act as part of the operating system: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTcbPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-254493'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Allow log on locally: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeInteractiveLogonRight'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254494'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Back up files and directories: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeBackupPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254495'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create a pagefile: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreatePagefilePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254496'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Create a token object: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateTokenPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-254497'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create global objects: Administrators, Service, Local Service, Network Service only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateGlobalPrivilege'; Op = 'only'; Identities = @('Administrators', 'Service', 'Local Service', 'Network Service') }
            )
        }
        @{
            Id = 'V-254498'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create permanent shared objects: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreatePermanentPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-254499'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create symbolic links: Administrators, NT Virtual Machine\Virtual Machines only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateSymbolicLinkPrivilege'; Op = 'only'; Identities = @('Administrators', 'NT Virtual Machine\Virtual Machines') }
            )
        }
        @{
            Id = 'V-254500'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Debug programs: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDebugPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254501'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Force shutdown from a remote system: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeRemoteShutdownPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254502'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Generate security audits: Local Service, Network Service only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeAuditPrivilege'; Op = 'only'; Identities = @('Local Service', 'Network Service') }
            )
        }
        @{
            Id = 'V-254503'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Impersonate a client after authentication: Administrators, Service, Local Service, Network Service only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeImpersonatePrivilege'; Op = 'only'; Identities = @('Administrators', 'Service', 'Local Service', 'Network Service') }
            )
        }
        @{
            Id = 'V-254504'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Increase scheduling priority: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeIncreaseBasePriorityPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254505'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Load and unload device drivers: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeLoadDriverPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254506'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Lock pages in memory: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeLockMemoryPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-254507'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Manage auditing and security log: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeSecurityPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254508'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Modify firmware environment values: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeSystemEnvironmentPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254509'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Perform volume maintenance tasks: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeManageVolumePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254510'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Profile single process: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeProfileSingleProcessPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254511'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Restore files and directories: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeRestorePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254512'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Take ownership of files or other objects: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTakeOwnershipPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-254269'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Fax is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Fax'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-254270'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Web-Ftp-Service is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Web-Ftp-Service'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-254271'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature PNRP is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'PNRP'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-254272'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Simple-TCPIP is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Simple-TCPIP'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-254273'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Telnet-Client is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Telnet-Client'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-254274'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature TFTP-Client is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'TFTP-Client'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-254275'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature FS-SMB1 is not installed'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Feature'
                    Name = 'FS-SMB1'
                    State = 'Disabled'
                    NotApplicableIf = @{
                        Rules = @('V-254276', 'V-254277')
                        Expect = @(
                            @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Op = 'eq'; Value = 0 }
                            @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name = 'Start'; Op = 'eq'; Value = 4 }
                        )
                    }
                }
            )
        }
        @{
            Id = 'V-254278'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature PowerShell-v2 is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'PowerShell-v2'; State = 'Disabled' }
            )
        }
    )
}
