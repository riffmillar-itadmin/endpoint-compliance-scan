# DISA Microsoft Windows Server 2025 STIG (domain controller), Version 1 Release 1
# (benchmark date 26 Jan 2026): all 281 rules, by Vuln ID. Rule data from the
# processed STIG in Microsoft's PowerStig project (MIT),
# https://github.com/microsoft/PowerStig; STIG content is published by DISA at
# https://public.cyber.mil/stigs/. Titles here are short summaries; STIG Viewer has
# the full rule text. Levels are the severity categories.
# Field meanings are in frameworks/README.md.

@{
    Id = 'DISA-STIG-WS2025-DC'
    Name = 'DISA Windows Server 2025 domain controller STIG V1R1'
    Source = 'https://public.cyber.mil/stigs/'
    StigId = 'MS_Windows_Server_2025_DC_STIG'
    Levels = @('CAT I', 'CAT II', 'CAT III')
    Complete = $true
    AppliesTo = @{ ProductTypes = @(2); Builds = @(26100) }
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
            Id = 'V-278134'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Maximum lifetime for service ticket: 1 to 600'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MaxServiceAge'; Op = 'between'; Min = 1; Max = 600 }
            )
        }
        @{
            Id = 'V-278135'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Maximum lifetime for user ticket: 1 to 10'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MaxTicketAge'; Op = 'between'; Min = 1; Max = 10 }
            )
        }
        @{
            Id = 'V-278136'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Maximum lifetime for user ticket renewal: 0 to 7'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MaxRenewAge'; Op = 'between'; Min = 0; Max = 7 }
            )
        }
        @{
            Id = 'V-278137'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Maximum tolerance for computer clock synchronization: 0 to 5'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MaxClockSkew'; Op = 'between'; Min = 0; Max = 5 }
            )
        }
        @{
            Id = 'V-278033'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Account lockout duration: 15 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LockoutDuration'; Op = 'ge'; Value = 15; Also = @(0, -1) }
            )
        }
        @{
            Id = 'V-278034'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Account lockout threshold: 1 to 3'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LockoutBadCount'; Op = 'between'; Min = 1; Max = 3 }
            )
        }
        @{
            Id = 'V-278035'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Reset account lockout counter after: 15 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'ResetLockoutCount'; Op = 'ge'; Value = 15 }
            )
        }
        @{
            Id = 'V-278036'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Enforce password history: 24 or more'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'PasswordHistorySize'; Op = 'ge'; Value = 24 }
            )
        }
        @{
            Id = 'V-278037'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Maximum password age: 1 to 60'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MaximumPasswordAge'; Op = 'between'; Min = 1; Max = 60 }
            )
        }
        @{
            Id = 'V-278038'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Minimum password age: not ''0'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'MinimumPasswordAge'; Op = 'ne'; Value = '0' }
            )
        }
        @{
            Id = 'V-278039'
            Family = 'Account'
            Level = 'CAT II'
            Title = 'Password must meet complexity requirements: Enabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'PasswordComplexity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278040'
            Family = 'Account'
            Level = 'CAT I'
            Title = 'Store passwords using reversible encryption: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'ClearTextPassword'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278047'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Credential Validation: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278048'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Credential Validation: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278049'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Account Management Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Account Management Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278050'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security Group Management: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security Group Management'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278051'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit User Account Management: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'User Account Management'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278052'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit User Account Management: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'User Account Management'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278053'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Plug and Play Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Plug and Play Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278054'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Process Creation: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Process Creation'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278055'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Account Lockout: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Account Lockout'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278056'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Account Lockout: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Account Lockout'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278057'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Group Membership: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Group Membership'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278058'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logoff: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logoff'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278059'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logon: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278060'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Logon: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278061'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Special Logon: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Special Logon'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278062'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Object Access Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Object Access Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278063'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other Object Access Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other Object Access Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278064'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Removable Storage: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Removable Storage'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278065'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Removable Storage: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Removable Storage'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278066'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Audit Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Audit Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278067'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Audit Policy Change: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Audit Policy Change'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278068'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Authentication Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Authentication Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278069'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Authorization Policy Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Authorization Policy Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278070'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Sensitive Privilege Use: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Sensitive Privilege Use'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278071'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Sensitive Privilege Use: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Sensitive Privilege Use'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278072'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit IPsec Driver: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'IPsec Driver'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278073'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit IPsec Driver: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'IPsec Driver'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278074'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other System Events: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other System Events'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278075'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Other System Events: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Other System Events'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278076'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security State Change: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security State Change'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278077'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Security System Extension: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Security System Extension'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278078'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit System Integrity: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'System Integrity'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278079'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit System Integrity: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'System Integrity'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278154'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Computer Account Management: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Computer Account Management'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278155'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Directory Service Access: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Directory Service Access'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278156'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Directory Service Access: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Directory Service Access'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-278157'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Directory Service Changes: Success'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Directory Service Changes'; Setting = 'Success' }
            )
        }
        @{
            Id = 'V-278158'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Audit Directory Service Changes: Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Directory Service Changes'; Setting = 'Failure' }
            )
        }
        @{
            Id = 'V-277997'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277982'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Security flaws with operating systems are discovered daily.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277983'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Hardware components provide the foundation for organizational systems and the platform for the execution of authorize...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277991'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Shared accounts (accounts where two or more people log on with the same user identification) do not provide adequate ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277996'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'A properly configured host-based intrusion detection system (HIDS) or host-based intrusion prevention system (HIPS) p...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278003'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Outdated or unused accounts provide penetration points that may go undetected.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278008'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Use of software certificates and their accompanying installation files for end users to access resources is less secu...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278011'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Unnecessary roles and features increase the attack surface of a system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278142'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'When directory service database objects do not have appropriate access control permissions, it may be possible for ma...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278145'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Directory data that is not appropriately encrypted is subject to compromise.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278161'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'A PKI implementation depends on the practices established by the Certificate Authority (CA) to ensure the implementat...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277985'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadverte...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277986'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277987'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Using applications that access the internet or have potential internet sources using administrative privileges expose...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277988'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277989'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Application/service account passwords must be of sufficient length to prevent being easily cracked.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277990'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Setting application account passwords to expire may cause applications to stop functioning.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277992'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Using an allowlist provides a configuration management method to allow the execution of only authorized software.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277993'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Credential Guard uses virtualization-based security to protect data that could be used in credential theft attacks if...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277995'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Malicious software can establish a base on individual desktops and servers.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278004'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor oppor...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278005'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being disc...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278006'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction o...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278007'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Shares on a system provide network access.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278009'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'This requirement addresses protection of user-generated data as well as operating system-specific configuration data.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278010'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, f...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278012'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on ...'
            Checks = @('SC-FirewallEnabled')
        }
        @{
            Id = 'V-278013'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278014'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Emergency administrator accounts are privileged accounts established in response to crisis situations where the need ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278017'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Unnecessary connections could increase the attack surface of a system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278018'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Unnecessary applications and/or services such as Bluetooth could allow an attacker to connect with intentions to take...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278027'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The FTP service allows remote users to access shared files and directories.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278028'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The FTP service allows remote users to access shared files and directories that could provide access to system resour...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278029'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'The Windows Time Service controls time synchronization settings.'
            Checks = @('AU-TimeSync')
            Note = 'The STIG also requires the time source to be authorized (domain hierarchy or approved NTP).'
        }
        @{
            Id = 'V-278031'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278032'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Secure Boot is a standard that ensures systems boot only to a trusted operating system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278041'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Protection of log data includes ensuring the log data is not accidentally lost or deleted.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278042'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Protection of log data includes ensuring the log data is not accidentally lost or deleted.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278085'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Configuring the system to ignore name release requests, except from WINS servers, prevents a denial-of-service (DoS) ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278101'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Allowing AutoPlay to execute may introduce malicious code to a system.'
            Checks = @('CM-AutoplayDisabled')
        }
        @{
            Id = 'V-278132'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'An account that does not have Administrator duties must not have Administrator rights.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278133'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'This policy setting determines whether the Kerberos Key Distribution Center (KDC) validates every request for a sessi...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278141'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'When Active Directory objects do not have appropriate access control permissions, it may be possible for malicious us...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278143'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'When directory service data files, especially for directories used for identification, authentication, or authorizati...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278144'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Executing application servers on the same host machine with a directory server may substantially weaken the security ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278146'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'To the extent that anonymous access to directory data (outside the root DSE) is permitted, read access control of the...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278147'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'The failure to terminate inactive network connections increases the risk of a successful attack on the directory server.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278149'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a use...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278150'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a use...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278151'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a use...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278152'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a use...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278153'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a use...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278159'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Domain controllers are part of the chain of trust for PKI authentications.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278160'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'A PKI implementation depends on the practices established by the Certificate Authority (CA) to ensure the implementat...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278162'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Smart cards such as the CAC support a two-factor authentication technique.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278173'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Weak mappings give rise to security vulnerabilities and demand hardening measures.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278176'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The krbtgt account acts as a service account for the Kerberos Key Distribution Center (KDC) service.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278212'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Some non-Microsoft SMB servers only support unencrypted (plain-text) password authentication.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-279916'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-279917'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-279918'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-279919'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-279920'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-279921'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-279922'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-279923'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278030'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Accounts or groups given rights on a system may show up as unresolved SIDs for various reasons including deletion of ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277998'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277999.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-277999.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278000'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Changing the system''s file and directory permissions allows the possibility of unauthorized and anonymous modificatio...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278001.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278001.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278001.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The registry is integral to the function, security, and stability of the Windows system.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278002'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Windows shares are a means by which files, folders, printers, and other resources can be published for network users ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278043'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278044'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278045'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disru...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278046'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278138'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Improper access permissions for directory data-related files could allow unauthorized users to read, modify, or delet...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278139'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Improper access permissions for directory data files could allow unauthorized users to read, modify, or delete direct...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278140'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'When directory service database objects do not have appropriate access control permissions, it may be possible for ma...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278148'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a use...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278024'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SMB1 (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278025'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'Start (mrxsmb10) = 4'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name = 'Start'; Op = 'eq'; Value = 4 }
            )
        }
        @{
            Id = 'V-278080'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NoLockScreenSlideshow (Personalization) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name = 'NoLockScreenSlideshow'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278082'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableIPSourceRouting (Parameters) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name = 'DisableIPSourceRouting'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-278083'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableIPSourceRouting (Parameters) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'DisableIPSourceRouting'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-278084'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'EnableICMPRedirect (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'EnableICMPRedirect'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278086'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowInsecureGuestAuth (LanmanWorkstation) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name = 'AllowInsecureGuestAuth'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278087.a'
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
            Id = 'V-278087.b'
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
            Id = 'V-278088'
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
            Id = 'V-278089'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowProtectedCreds (CredentialsDelegation) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; Name = 'AllowProtectedCreds'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278090.a'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableVirtualizationBasedSecurity (DeviceGuard) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'EnableVirtualizationBasedSecurity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278090.b'
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
            Id = 'V-278091'
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
            Id = 'V-278092'
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
            Id = 'V-278093'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableWebPnPDownload (Printers) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableWebPnPDownload'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278094'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableHTTPPrinting (Printers) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = 'DisableHTTPPrinting'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278095'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DontDisplayNetworkSelectionUI (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'DontDisplayNetworkSelectionUI'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278096'
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
            Id = 'V-278097'
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
            Id = 'V-278098'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DisableInventory (AppCompat) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; Name = 'DisableInventory'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278099'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoAutoplayfornonVolume (Explorer) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'NoAutoplayfornonVolume'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278100'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'NoAutorun (Explorer) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutorun'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278102'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnumerateAdministrators (CredUI) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name = 'EnumerateAdministrators'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278103'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowTelemetry (DataCollection) = '
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Op = 'eq'; Value = '' }
            )
        }
        @{
            Id = 'V-278104'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'DODownloadMode (DeliveryOptimization) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name = 'DODownloadMode'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278105'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (Application) >= 32768'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name = 'MaxSize'; Op = 'ge'; Value = 32768 }
            )
        }
        @{
            Id = 'V-278106'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (Security) >= 196608'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Op = 'ge'; Value = 196608 }
            )
        }
        @{
            Id = 'V-278107'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MaxSize (System) >= 32768'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name = 'MaxSize'; Op = 'ge'; Value = 32768 }
            )
        }
        @{
            Id = 'V-278108'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSmartScreen (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableSmartScreen'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278109'
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
            Id = 'V-278110'
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
            Id = 'V-278111'
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
            Id = 'V-278112'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisablePasswordSaving (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'DisablePasswordSaving'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278113'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fDisableCdm (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fDisableCdm'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278114'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fPromptForPassword (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fPromptForPassword'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278115'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'fEncryptRPCTraffic (Terminal Services) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fEncryptRPCTraffic'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278116'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'MinEncryptionLevel (Terminal Services) = 3'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'MinEncryptionLevel'; Op = 'eq'; Value = 3 }
            )
        }
        @{
            Id = 'V-278117'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableEnclosureDownload (Feeds) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name = 'DisableEnclosureDownload'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278118'
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
            Id = 'V-278119'
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
            Id = 'V-278120'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableUserControl (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'EnableUserControl'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278121'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AlwaysInstallElevated (Installer) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278122'
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
            Id = 'V-278123'
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
            Id = 'V-278124'
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
            Id = 'V-278125'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AllowBasic (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowBasic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278126'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowUnencryptedTraffic (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowUnencryptedTraffic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278127'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowDigest (Client) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = 'AllowDigest'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278128'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'AllowBasic (Service) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowBasic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278129'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowUnencryptedTraffic (Service) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'AllowUnencryptedTraffic'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278130'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisableRunAs (Service) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = 'DisableRunAs'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278131'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableTranscripting (Transcription) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableTranscripting'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278163'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LDAPServerIntegrity (Parameters) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name = 'LDAPServerIntegrity'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-278164'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RefusePasswordChange (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RefusePasswordChange'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278172'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'StrongCertificateBindingEnforcement (Kdc) in 1/2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'; Name = 'StrongCertificateBindingEnforcement'; Op = 'in'; Values = @(1, 2) }
            )
        }
        @{
            Id = 'V-278196'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LimitBlankPasswordUse (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LimitBlankPasswordUse'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278199'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SCENoApplyLegacyAuditPolicy (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278200'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireSignOrSeal (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireSignOrSeal'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278201'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SealSecureChannel (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SealSecureChannel'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278202'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'SignSecureChannel (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'SignSecureChannel'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278203'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DisablePasswordChange (Parameters) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'DisablePasswordChange'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278204'
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
            Id = 'V-278205'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'RequireStrongKey (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'RequireStrongKey'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278206'
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
            Id = 'V-278207'
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
            Id = 'V-278208'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LegalNoticeCaption (System) = See message title options below'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'LegalNoticeCaption'
                    Op = 'eq'
                    Value = 'See message title options below'
                }
            )
        }
        @{
            Id = 'V-278209'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'scremoveoption (Winlogon) in 1/2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'scremoveoption'; Op = 'in'; Values = @(1, 2) }
            )
        }
        @{
            Id = 'V-278210'
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
            Id = 'V-278211'
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
            Id = 'V-278213'
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
            Id = 'V-278214'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSecuritySignature (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name = 'EnableSecuritySignature'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278216'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictAnonymousSAM (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278217'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictAnonymous (Lsa) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278218'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EveryoneIncludesAnonymous (Lsa) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278219'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'RestrictNullSessAccess (Parameters) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name = 'RestrictNullSessAccess'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278220'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'UseMachineId (LSA) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA'; Name = 'UseMachineId'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278221'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'allownullsessionfallback (MSV1_0) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0'; Name = 'allownullsessionfallback'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278222'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowOnlineID (pku2u) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u'; Name = 'AllowOnlineID'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278223'
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
            Id = 'V-278225'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'LmCompatibilityLevel (Lsa) = 5'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Op = 'eq'; Value = 5 }
            )
        }
        @{
            Id = 'V-278226'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'LDAPClientIntegrity (LDAP) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'; Name = 'LDAPClientIntegrity'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278227'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NTLMMinClientSec (MSV1_0) = 537395200'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinClientSec'; Op = 'eq'; Value = 537395200 }
            )
        }
        @{
            Id = 'V-278228'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'NTLMMinServerSec (MSV1_0) = 537395200'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinServerSec'; Op = 'eq'; Value = 537395200 }
            )
        }
        @{
            Id = 'V-278229'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'ForceKeyProtection (Cryptography) = 2'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography'; Name = 'ForceKeyProtection'; Op = 'eq'; Value = 2 }
            )
        }
        @{
            Id = 'V-278230'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'Enabled (FIPSAlgorithmPolicy) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'; Name = 'Enabled'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278231'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'ProtectionMode (Session Manager) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Name = 'ProtectionMode'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278232'
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
            Id = 'V-278233'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableUIADesktopToggle (System) = 0'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableUIADesktopToggle'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278234'
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
            Id = 'V-278235'
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
            Id = 'V-278236'
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
            Id = 'V-278237'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableSecureUIAPaths (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableSecureUIAPaths'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278238'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableLUA (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278239'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableVirtualization (System) = 1'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableVirtualization'; Op = 'eq'; Value = 1 }
            )
        }
        @{
            Id = 'V-278240'
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
            Id = 'V-278192.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DOD websites and DOD-signed code are properly validated, the system must trust the DOD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278192.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DOD websites and DOD-signed code are properly validated, the system must trust the DOD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278192.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DOD websites and DOD-signed code are properly validated, the system must trust the DOD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278192.d'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure secure DOD websites and DOD-signed code are properly validated, the system must trust the DOD Root CAs.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278193.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278193.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278193.c'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278194.a'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278194.b'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'To ensure users do not experience denial of service when performing certificate-based authentication to DOD websites ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-278215'
            Family = 'SecOpt'
            Level = 'CAT I'
            Title = 'Network access: Allow anonymous SID/Name translation: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'LSAAnonymousNameLookup'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278195'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Guest account status: Disabled'
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'EnableGuestAccount'; Op = 'eq'; Value = 0 }
            )
        }
        @{
            Id = 'V-278197'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Rename administrator account: not ''Administrator'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'NewAdministratorName'; Op = 'ne'; Value = 'Administrator' }
            )
        }
        @{
            Id = 'V-278198'
            Family = 'SecOpt'
            Level = 'CAT II'
            Title = 'Accounts: Rename guest account: not ''Guest'''
            Checks = @()
            Expect = @(
                @{ Source = 'SecPol'; Name = 'NewGuestName'; Op = 'ne'; Value = 'Guest' }
            )
        }
        @{
            Id = 'V-278165'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Access this computer from the network: Administrators, Authenticated Users, Enterprise Domain Controllers only'
            Checks = @()
            Expect = @(
                @{
                    Source = 'UserRight'
                    Name = 'SeNetworkLogonRight'
                    Op = 'only'
                    Identities = @('Administrators', 'Authenticated Users', 'Enterprise Domain Controllers')
                }
            )
        }
        @{
            Id = 'V-278166'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Add workstations to domain: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeMachineAccountPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278167'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Allow log on through Remote Desktop Services: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeRemoteInteractiveLogonRight'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278168'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny access to this computer from the network: includes Guests'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyNetworkLogonRight'; Op = 'includes'; Identities = @('Guests') }
            )
        }
        @{
            Id = 'V-278169'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on as a batch job: includes Guests'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyBatchLogonRight'; Op = 'includes'; Identities = @('Guests') }
            )
        }
        @{
            Id = 'V-278170'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on as a service: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyServiceLogonRight'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-278171'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on locally: includes Guests'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyInteractiveLogonRight'; Op = 'includes'; Identities = @('Guests') }
            )
        }
        @{
            Id = 'V-278174'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Deny log on through Remote Desktop Services: includes Guests'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDenyRemoteInteractiveLogonRight'; Op = 'includes'; Identities = @('Guests') }
            )
        }
        @{
            Id = 'V-278175'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Enable computer and user accounts to be trusted for delegation: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeEnableDelegationPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278241'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Access Credential Manager as a trusted caller: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTrustedCredManAccessPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-278242'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Act as part of the operating system: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTcbPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-278243'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Allow log on locally: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeInteractiveLogonRight'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278244'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Back up files and directories: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeBackupPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278245'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create a pagefile: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreatePagefilePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278246'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Create a token object: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateTokenPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-278247'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create global objects: Administrators, Service, Local Service, Network Service only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateGlobalPrivilege'; Op = 'only'; Identities = @('Administrators', 'Service', 'Local Service', 'Network Service') }
            )
        }
        @{
            Id = 'V-278248'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create permanent shared objects: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreatePermanentPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-278249'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Create symbolic links: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeCreateSymbolicLinkPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278250'
            Family = 'Rights'
            Level = 'CAT I'
            Title = 'Debug programs: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeDebugPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278251'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Force shutdown from a remote system: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeRemoteShutdownPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278252'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Generate security audits: Local Service, Network Service only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeAuditPrivilege'; Op = 'only'; Identities = @('Local Service', 'Network Service') }
            )
        }
        @{
            Id = 'V-278253'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Impersonate a client after authentication: Administrators, Service, Local Service, Network Service only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeImpersonatePrivilege'; Op = 'only'; Identities = @('Administrators', 'Service', 'Local Service', 'Network Service') }
            )
        }
        @{
            Id = 'V-278254'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Increase scheduling priority: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeIncreaseBasePriorityPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278255'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Load and unload device drivers: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeLoadDriverPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278256'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Lock pages in memory: no one'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeLockMemoryPrivilege'; Op = 'only'; Identities = @() }
            )
        }
        @{
            Id = 'V-278257'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Manage auditing and security log: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeSecurityPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278258'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Modify firmware environment values: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeSystemEnvironmentPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278259'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Perform volume maintenance tasks: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeManageVolumePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278260'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Profile single process: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeProfileSingleProcessPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278261'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Restore files and directories: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeRestorePrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278262'
            Family = 'Rights'
            Level = 'CAT II'
            Title = 'Take ownership of files or other objects: Administrators only'
            Checks = @()
            Expect = @(
                @{ Source = 'UserRight'; Name = 'SeTakeOwnershipPrivilege'; Op = 'only'; Identities = @('Administrators') }
            )
        }
        @{
            Id = 'V-278015'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Fax is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Fax'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-278016'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Web-Ftp-Service is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Web-Ftp-Service'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-278019'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature PNRP is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'PNRP'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-278020'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Simple-TCPIP is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Simple-TCPIP'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-278021'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature Telnet-Client is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'Telnet-Client'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-278022'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature TFTP-Client is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'TFTP-Client'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-278023'
            Family = 'Feature'
            Level = 'CAT II'
            Title = 'Feature FS-SMB1 is not installed'
            Checks = @()
            Expect = @(
                @{ Source = 'Feature'; Name = 'FS-SMB1'; State = 'Disabled' }
            )
        }
        @{
            Id = 'V-278026'
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
