# DISA Microsoft Windows Server 2019 STIG (member server), Version 3 Release 8
# (benchmark date 01 Apr 2026): all 247 rules, by Vuln ID. Rule data from the
# processed STIG in Microsoft's PowerStig project (MIT),
# https://github.com/microsoft/PowerStig; STIG content is published by DISA at
# https://public.cyber.mil/stigs/. Titles here are short summaries; STIG Viewer has
# the full rule text. Levels are the severity categories.
# Field meanings are in frameworks/README.md.

@{
    Id = 'DISA-STIG-WS2019-MS'
    Name = 'DISA Windows Server 2019 member server STIG V3R8'
    Source = 'https://public.cyber.mil/stigs/'
    StigId = 'Windows_Server_2019_MS_STIG'
    Levels = @('CAT I', 'CAT II', 'CAT III')
    Complete = $true
    AppliesTo = @{ ProductTypes = @(3); Builds = @(17763) }
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
            Id = 'V-205629'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Account lockout threshold: 1 to 3'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LockoutBadCount'; Op = 'between'; Min = 1; Max = 3 }
            )
        }
        @{
            Id = 'V-205630'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Reset account lockout counter after: 15 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'ResetLockoutCount'; Op = 'ge'; Value = 15 }
            )
        }
        @{
            Id = 'V-205652'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Password must meet complexity requirements: Enabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'PasswordComplexity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205653'
            Family = 'Account'
            Level = 'CAT I'
            Title = 'Store passwords using reversible encryption: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'ClearTextPassword'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205656'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Minimum password age: not ''0'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MinimumPasswordAge'; Op = 'ne'; Value = '0' }
            )
        }
        @{
            Id = 'V-205659'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Maximum password age: 1 to 60'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MaximumPasswordAge'; Op = 'between'; Min = 1; Max = 60 }
            )
        }
        @{
            Id = 'V-205660'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Enforce password history: 24 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'PasswordHistorySize'; Op = 'ge'; Value = 24 }
            )
        }
        @{
            Id = 'V-205662'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Minimum password length: 14 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MinimumPasswordLength'; Op = 'ge'; Value = 14 }
            )
        }
        @{
            Id = 'V-205795'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Account lockout duration: 15 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LockoutDuration'; Op = 'ge'; Value = 15; Also = @(0, -1) }
            )
        }
        @{
            Id = 'V-205625'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security Group Management: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security Group Management'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205626'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit User Account Management: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'User Account Management'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205627'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit User Account Management: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'User Account Management'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205634'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logon: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205635'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logon: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205730'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Account Lockout: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Account Lockout'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205769'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Account Management Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Account Management Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205770'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Process Creation: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Process Creation'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205771'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Audit Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Audit Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205772'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Audit Policy Change: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Audit Policy Change'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205773'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Authentication Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Authentication Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205774'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Authorization Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Authorization Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205775'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Sensitive Privilege Use: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Sensitive Privilege Use'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205776'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Sensitive Privilege Use: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Sensitive Privilege Use'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205777'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit IPsec Driver: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'IPsec Driver'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205778'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit IPsec Driver: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'IPsec Driver'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205779'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other System Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other System Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205780'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other System Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other System Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205781'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security State Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security State Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205782'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security System Extension: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security System Extension'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205783'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit System Integrity: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'System Integrity'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205784'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit System Integrity: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'System Integrity'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205832'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Credential Validation: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205833'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Credential Validation: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205834'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Group Membership: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Group Membership'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205835'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Special Logon: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Special Logon'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205836'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Object Access Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Object Access Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205837'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Object Access Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Object Access Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205838'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logoff: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logoff'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205839'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Plug and Play Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Plug and Play Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205840'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Removable Storage: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Removable Storage'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-205841'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Removable Storage: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Removable Storage'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-205663'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205849'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Systems at unsupported servicing levels will not receive security updates for new vulnerabilities, which leave them s...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205677'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Unnecessary roles and features increase the attack surface of a system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205699'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Shared accounts (accounts where two or more people log on with the same user identification) do not provide adequate ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205707'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Outdated or unused accounts provide penetration points that may go undetected.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205851'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'A properly configured Host-based Intrusion Detection System (HIDS) and Host-based Intrusion Prevention System (HIPS) ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205852'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Use of software certificates and their accompanying installation files for end users to access resources is less secu...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205624'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205657'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205658'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being disc...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205661'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Application/service account passwords must be of sufficient length to prevent being easily cracked.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205664'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Windows shares are a means by which files, folders, printers, and other resources can be published for network users ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205700'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor oppor...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205710'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Emergency administrator accounts are privileged accounts established in response to crisis situations where the need ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205721'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Shares on a system provide network access.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205727'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'This requirement addresses protection of user-generated data as well as operating system-specific configuration data.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205746'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'An account that does not have Administrator duties must not have Administrator rights.'
            Checks = @('AC-LocalAdminCount')
            Note = 'The STIG requires that only accounts with administrator duties are members; review the listed members.'
        }
        @{
            Id = 'V-205799'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Protection of log data includes assuring the log data is not accidentally lost or deleted.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205800'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'The Windows Time Service controls time synchronization settings.'
            Checks = @('AU-TimeSync')
            Note = 'The STIG also requires the time source to be authorized (domain hierarchy or approved NTP).'
        }
        @{
            Id = 'V-205803'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction o...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205807'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Using an allowlist provides a configuration management method to allow the execution of only authorized software.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205829'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, f...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205843'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Protection of log data includes ensuring the log data is not accidentally lost or deleted.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205844'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadverte...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205845'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Using applications that access the Internet or have potential Internet sources using administrative privileges expose...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205846'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205847'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Setting application account passwords to expire may cause applications to stop functioning.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205848'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205853'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The FTP service allows remote users to access shared files and directories.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205854'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The FTP service allows remote users to access shared files and directories that could provide access to system resour...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205856'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205857'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Secure Boot is a standard that ensures systems boot only to a trusted operating system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278934'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278935'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278936'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278937'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278938'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278939'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278940'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278941'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205855'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Accounts or groups given rights on a system may show up as unresolved SIDs for various reasons including deletion of ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205640'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205641'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205642'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205731'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205734'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205735.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205735.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205736'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205737.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205737.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205737.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205631'
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
            Id = 'V-205632'
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
            Id = 'V-205633'
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
            Id = 'V-205636'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fEncryptRPCTraffic (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fEncryptRPCTraffic'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205637'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MinEncryptionLevel (Terminal Services) = 3'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'MinEncryptionLevel'; Op = 'eq'; Value = 3 }
            )
        }
        @{
            Id = 'V-205638'
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
            Id = 'V-205639'
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
            Id = 'V-205644'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SCENoApplyLegacyAuditPolicy (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205651'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'ForceKeyProtection (Cryptography) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography'; Name = 'ForceKeyProtection'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-205654'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoLMHash (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205655'
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
            Id = 'V-205683'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SMB1 (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205684'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'Start (mrxsmb10) = 4'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name = 'Start'; Op = 'eq'; Value = 4 }
            )
        }
        @{
            Id = 'V-205686'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoLockScreenSlideshow (Personalization) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name = 'NoLockScreenSlideshow'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205687'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'UseLogonCredential (Wdigest) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'; Name = 'UseLogonCredential'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205688'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableWebPnPDownload (Printers) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableWebPnPDownload'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205689'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableHTTPPrinting (Printers) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableHTTPPrinting'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205690'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DontDisplayNetworkSelectionUI (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'DontDisplayNetworkSelectionUI'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205691'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableInventory (AppCompat) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; Name = 'DisableInventory'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205692'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSmartScreen (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableSmartScreen'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205693'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowBasicAuthInClear (Feeds) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name = 'AllowBasicAuthInClear'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205694'
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
            Id = 'V-205696'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnumerateLocalUsers (System) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnumerateLocalUsers'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205708'
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
            Id = 'V-205711'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AllowBasic (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowBasic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205712'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowDigest (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowDigest'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205713'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AllowBasic (Service) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowBasic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205714'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnumerateAdministrators (CredUI) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name = 'EnumerateAdministrators'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205715'
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
            Id = 'V-205716'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableUIADesktopToggle (System) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableUIADesktopToggle'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205717'
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
            Id = 'V-205718'
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
            Id = 'V-205719'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSecureUIAPaths (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableSecureUIAPaths'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205720'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableVirtualization (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableVirtualization'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205722'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fDisableCdm (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fDisableCdm'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205724'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictAnonymous (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205725'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictNullSessAccess (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name = 'RestrictNullSessAccess'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205747'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RestrictRemoteSAM (Lsa) = O:BAG:BAD:(A;;RC;;;BA)'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictRemoteSAM'; Op = 'eq'; Value = 'O:BAG:BAD:(A;;RC;;;BA)' }
            )
        }
        @{
            Id = 'V-205796'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (Application) >= 32768'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name = 'MaxSize'; Op = 'ge'; Value = 32768 }
            )
        }
        @{
            Id = 'V-205797'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (Security) >= 1234569216'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Op = 'ge'; Value = 1234569216 }
            )
        }
        @{
            Id = 'V-205798'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (System) >= 32768'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name = 'MaxSize'; Op = 'ge'; Value = 32768 }
            )
        }
        @{
            Id = 'V-205801'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableUserControl (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'EnableUserControl'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205802'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AlwaysInstallElevated (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205804'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoAutoplayfornonVolume (Explorer) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'NoAutoplayfornonVolume'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205805'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoAutorun (Explorer) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutorun'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205806'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoDriveTypeAutoRun (Explorer) = 255'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'; Name = 'NoDriveTypeAutoRun'; Op = 'eq'; Value = 255 }
            )
        }
        @{
            Id = 'V-205808'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisablePasswordSaving (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'DisablePasswordSaving'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205809'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fPromptForPassword (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fPromptForPassword'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205810'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableRunAs (Service) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'DisableRunAs'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205811'
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
            Id = 'V-205812'
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
            Id = 'V-205813'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableLUA (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205814'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RestrictRemoteClients (Rpc) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; Name = 'RestrictRemoteClients'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205815'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisablePasswordChange (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'DisablePasswordChange'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205816'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowUnencryptedTraffic (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowUnencryptedTraffic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205817'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowUnencryptedTraffic (Service) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowUnencryptedTraffic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205819'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'NoNameReleaseOnDemand (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'; Name = 'NoNameReleaseOnDemand'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205821'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireSignOrSeal (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireSignOrSeal'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205822'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SealSecureChannel (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SealSecureChannel'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205823'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SignSecureChannel (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SignSecureChannel'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205824'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireStrongKey (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireStrongKey'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205825'
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
            Id = 'V-205826'
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
            Id = 'V-205827'
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
            Id = 'V-205828'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSecuritySignature (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name = 'EnableSecuritySignature'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205830'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoDataExecutionPrevention (Explorer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'NoDataExecutionPrevention'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205842'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'Enabled (FIPSAlgorithmPolicy) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'; Name = 'Enabled'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205858'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableIPSourceRouting (Parameters) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name = 'DisableIPSourceRouting'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-205859'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableIPSourceRouting (Parameters) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'DisableIPSourceRouting'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-205860'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'EnableICMPRedirect (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'EnableICMPRedirect'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205861'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowInsecureGuestAuth (LanmanWorkstation) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name = 'AllowInsecureGuestAuth'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205862.a'
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
            Id = 'V-205862.b'
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
            Id = 'V-205863'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowProtectedCreds (CredentialsDelegation) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; Name = 'AllowProtectedCreds'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205864.a'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableVirtualizationBasedSecurity (DeviceGuard) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'EnableVirtualizationBasedSecurity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205864.b'
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
            Id = 'V-205865'
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
            Id = 'V-205866'
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
            Id = 'V-205867'
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
            Id = 'V-205868'
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
            Id = 'V-205869'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowTelemetry (DataCollection) in 0/1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Op = 'in'; Values = @(0, 1) }
            )
        }
        @{
            Id = 'V-205870'
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
            Id = 'V-205871'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'NoHeapTerminationOnCorruption (Explorer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'NoHeapTerminationOnCorruption'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205872'
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
                }
            )
        }
        @{
            Id = 'V-205873'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableEnclosureDownload (Feeds) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name = 'DisableEnclosureDownload'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205874'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SafeForScripting (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'SafeForScripting'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205906'
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
            Id = 'V-205907'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LsaCfgFlags (DeviceGuard) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'LsaCfgFlags'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205908'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LimitBlankPasswordUse (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LimitBlankPasswordUse'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205911'
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
            Id = 'V-205912'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'scremoveoption (Winlogon) in 1/2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'scremoveoption'; Op = 'in'; Values = @(1, 2) }
            )
        }
        @{
            Id = 'V-205914'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictAnonymousSAM (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205915'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EveryoneIncludesAnonymous (Lsa) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205916'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'UseMachineId (LSA) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA'; Name = 'UseMachineId'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205917'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'allownullsessionfallback (MSV1_0) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0'; Name = 'allownullsessionfallback'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205918'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowOnlineID (pku2u) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u'; Name = 'AllowOnlineID'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205919'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LmCompatibilityLevel (Lsa) = 5'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Op = 'eq'; Value = 5 }
            )
        }
        @{
            Id = 'V-205920'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LDAPClientIntegrity (LDAP) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'; Name = 'LDAPClientIntegrity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205921'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NTLMMinClientSec (MSV1_0) = 537395200'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinClientSec'; Op = 'eq'; Value = 537395200 }
            )
        }
        @{
            Id = 'V-205922'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NTLMMinServerSec (MSV1_0) = 537395200'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinServerSec'; Op = 'eq'; Value = 537395200 }
            )
        }
        @{
            Id = 'V-205923'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'ProtectionMode (Session Manager) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Name = 'ProtectionMode'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205924'
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
                }
            )
        }
        @{
            Id = 'V-205925'
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
            Id = 'V-257503'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableTranscripting (Transcription) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableTranscripting'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-205648.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205648.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205648.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205648.d'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205649'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205650.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205650.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205913'
            Family = 'SecOpt'
            Level = 'CAT I'
            Title = 'Network access: Allow anonymous SID/Name translation: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LSAAnonymousNameLookup'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205709'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Guest account status: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'EnableGuestAccount'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-205909'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Rename administrator account: not ''Administrator'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'NewAdministratorName'; Op = 'ne'; Value = 'Administrator' }
            )
        }
        @{
            Id = 'V-205910'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Rename guest account: not ''Guest'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'NewGuestName'; Op = 'ne'; Value = 'Guest' }
            )
        }
        @{
            Id = 'V-205850'
            Family = 'Feature'
            Level = 'CAT I'
            Title = 'Malicious software can establish a base on individual desktops and servers.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-214936'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-205643'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Manage auditing and security log: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeSecurityPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205671'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Access this computer from the network: Administrators, Authenticated Users only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeNetworkLogonRight'; Op = 'only'; Identities = @('Administrators', 'Authenticated Users') }
            )
        }
        @{
            Id = 'V-205672'
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
            Id = 'V-205673'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on as a batch job: includes Enterprise Admins, Domain Admins, Guests'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyBatchLogonRight'; Op = 'includes'; Identities = @('Enterprise Admins', 'Domain Admins', 'Guests') }
            )
        }
        @{
            Id = 'V-205674'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on as a service: Enterprise Admins, Domain Admins only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyServiceLogonRight'; Op = 'only'; Identities = @('Enterprise Admins', 'Domain Admins') }
            )
        }
        @{
            Id = 'V-205675'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on locally: includes Enterprise Admins, Domain Admins, Guests'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyInteractiveLogonRight'; Op = 'includes'; Identities = @('Enterprise Admins', 'Domain Admins', 'Guests') }
            )
        }
        @{
            Id = 'V-205676'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Allow log on locally: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeInteractiveLogonRight'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205733'
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
            Id = 'V-205748'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Enable computer and user accounts to be trusted for delegation: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeEnableDelegationPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-205749'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Access Credential Manager as a trusted caller: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTrustedCredManAccessPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-205750'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Act as part of the operating system: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTcbPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-205751'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Back up files and directories: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeBackupPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205752'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create a pagefile: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreatePagefilePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205753'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Create a token object: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateTokenPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-205754'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create global objects: Administrators, Service, Local Service, Network Service only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateGlobalPrivilege'; Op = 'only'; Identities = @('Administrators', 'Service', 'Local Service', 'Network Service') }
            )
        }
        @{
            Id = 'V-205755'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create permanent shared objects: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreatePermanentPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-205756'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create symbolic links: Administrators, NT Virtual Machine\Virtual Machines only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateSymbolicLinkPrivilege'; Op = 'only'; Identities = @('Administrators', 'NT Virtual Machine\Virtual Machines') }
            )
        }
        @{
            Id = 'V-205757'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Debug programs: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDebugPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205758'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Force shutdown from a remote system: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeRemoteShutdownPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205759'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Generate security audits: Local Service, Network Service only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeAuditPrivilege'; Op = 'only'; Identities = @('Local Service', 'Network Service') }
            )
        }
        @{
            Id = 'V-205760'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Impersonate a client after authentication: Administrators, Service, Local Service, Network Service only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeImpersonatePrivilege'; Op = 'only'; Identities = @('Administrators', 'Service', 'Local Service', 'Network Service') }
            )
        }
        @{
            Id = 'V-205761'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Increase scheduling priority: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeIncreaseBasePriorityPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205762'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Load and unload device drivers: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeLoadDriverPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205763'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Lock pages in memory: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeLockMemoryPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-205764'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Modify firmware environment values: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeSystemEnvironmentPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205765'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Perform volume maintenance tasks: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeManageVolumePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205766'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Profile single process: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeProfileSingleProcessPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205767'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Restore files and directories: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeRestorePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205768'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Take ownership of files or other objects: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTakeOwnershipPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-205678'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Fax is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Fax'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-205679'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature PNRP is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'PNRP'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-205680'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Simple-TCPIP is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Simple-TCPIP'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-205681'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature TFTP-Client is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'TFTP-Client'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-205682'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature FS-SMB1 is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'FS-SMB1'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-205685'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature PowerShell-v2 is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'PowerShell-v2'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-205697'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Web-Ftp-Service is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Web-Ftp-Service'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-205698'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Telnet-Client is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Telnet-Client'; State = 'Disabled' }
            )
        }
    )
}
