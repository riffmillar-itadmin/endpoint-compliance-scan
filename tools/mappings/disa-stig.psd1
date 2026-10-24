# Data for tools/Update-FrameworkCatalog.ps1: the DISA STIG catalogs.
# Read as data (literals, arrays and hashtables only); key order is kept.

@{
    # Security policy names in PowerStig rules, as secedit exports them.
    SecurityPolicy = @{
        'Account lockout duration' = 'LockoutDuration'
        'Account lockout threshold' = 'LockoutBadCount'
        'Reset account lockout counter after' = 'ResetLockoutCount'
        'Enforce password history' = 'PasswordHistorySize'
        'Maximum password age' = 'MaximumPasswordAge'
        'Minimum password age' = 'MinimumPasswordAge'
        'Minimum password length' = 'MinimumPasswordLength'
        'Password must meet complexity requirements' = 'PasswordComplexity'
        'Store passwords using reversible encryption' = 'ClearTextPassword'
        'Accounts: Guest account status' = 'EnableGuestAccount'
        'Accounts: Rename administrator account' = 'NewAdministratorName'
        'Accounts: Rename guest account' = 'NewGuestName'
        'Network access: Allow anonymous SID/Name translation' = 'LSAAnonymousNameLookup'
        # [Kerberos Policy], exported on domain controllers
        'Enforce user logon restrictions' = 'TicketValidateClient'
        'Maximum lifetime for service ticket' = 'MaxServiceAge'
        'Maximum lifetime for user ticket renewal' = 'MaxRenewAge'
        'Maximum lifetime for user ticket' = 'MaxTicketAge'
        'Maximum tolerance for computer clock synchronization' = 'MaxClockSkew'
    }

    # Security options secedit stores as registry values, checked as registry expectations.
    SecurityOptionRegistry = @{
        'Domain_controller_LDAP_server_signing_requirements' = @{
            Title = 'Domain controller: LDAP server signing requirements: Require signing'
            Expect = @{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name = 'LDAPServerIntegrity'; Op = 'eq'; Value = 2 }
        }
    }

    # Thresholds every STIG catalog carries, in this order.
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

    # Named checks for manual rules, matched by the start of the rule's discussion
    # (its first sentence), because Vuln IDs differ between STIGs. Used by catalogs
    # with NamedByText = $true. NotOnDomainController skips the match on a domain
    # controller, which has no local Administrators group to count.
    NamedByText = @(
        @{ Pattern = 'The Windows Time Service controls time synchronization'; Checks = @('AU-TimeSync'); Note = 'The STIG also requires the time source to be authorized (domain hierarchy or approved NTP).' }
        @{ Pattern = 'An account that does not have Administrator duties must not have Administrator rights'; Checks = @('AC-LocalAdminCount'); Note = 'The STIG requires that only accounts with administrator duties are members; review the listed members.'; NotOnDomainController = $true }
        @{ Pattern = 'A firewall provides a line of defense against attack'; Checks = @('SC-FirewallEnabled') }
        @{ Pattern = 'Allowing AutoPlay to execute may introduce malicious code'; Checks = @('CM-AutoplayDisabled') }
    )

    # The catalogs. PowerStig names the processed STIG file (without .xml) in
    # PowerStig's StigData/Processed folder. Named maps Vuln IDs to named checks for
    # manual rules.
    #
    # Overrides apply when the catalog follows a DISA release newer than PowerStig's:
    # for each rule DISA changed, the fields to replace (Title, Checks, Expect, Note),
    # or MoveTo, the Vuln ID DISA moved a split rule's part to. Reason says what
    # changed. An override for a rule the release doesn't have stops the build, so
    # each one is reviewed when the release changes. Reviewed lists automated rules
    # DISA reworded that a person has checked against that release; the build warns
    # about the rest.
    Catalogs = @(
        @{
            Id = 'DISA-STIG-Win11'
            File = 'disa-stig-win11'
            PowerStig = 'WindowsClient-11-2.7'
            Product = 'Windows 11'
            AppliesTo = @{ ProductTypes = @(1); MinBuild = 22000 }
            Named = @{
                'V-253259' = @{ Checks = @('SC-BitLocker') }
                'V-253264' = @{ Checks = @('SI-AntivirusActive') }
                'V-253281' = @{ Checks = @('SC-FirewallEnabled') }
                'V-253296' = @{ Checks = @('AU-TimeSync'); Note = 'The STIG also requires the time source to be authorized (domain hierarchy or approved NTP).' }
                'V-253269' = @{ Checks = @('AC-LocalAdminCount'); Note = 'The STIG requires that only accounts with administrator duties are members; review the listed members.' }
            }
            Overrides = @{
                'V-253301' = @{
                    Reason = 'V2R11 raised the maximum password age from 60 to 180 days.'
                    Title = 'Maximum password age: 1 to 180'
                    Expect = @(@{ Source = 'SecPol'; Name = 'MaximumPasswordAge'; Op = 'between'; Min = 1; Max = 180 })
                }
                'V-253422.a' = @{
                    Reason = 'V2R11 left V-253422 with one part, so it takes the Vuln ID.'
                    MoveTo = 'V-253422'
                }
                'V-253422.b' = @{
                    Reason = 'V2R11 moved LetAppsActivateWithVoice out of V-253422 into its own rule.'
                    MoveTo = 'V-289260'
                }
            }
            # Automated rules whose check DISA reworded since PowerStig's release, checked
            # by hand: the expected values are unchanged.
            Reviewed = @{
                Release = 'V2R11'
                Rules = @('V-253259', 'V-253260.a', 'V-253260.b', 'V-253261', 'V-253264', 'V-253291', 'V-253300', 'V-253359.a', 'V-253359.b', 'V-253359.c', 'V-253359.d', 'V-253362.a', 'V-253362.b', 'V-253369.a', 'V-253369.b', 'V-253370', 'V-253371', 'V-253389', 'V-253394.a', 'V-253394.b', 'V-253399', 'V-253401', 'V-253409', 'V-253414', 'V-253424', 'V-253445', 'V-253466')
            }
        }
        @{
            Id = 'DISA-STIG-WS2019-MS'
            File = 'disa-stig-ws2019-ms'
            PowerStig = 'WindowsServer-2019-MS-3.8'
            Product = 'Windows Server 2019 member server'
            Role = 'member server'
            AppliesTo = @{ ProductTypes = @(3); Builds = @(17763) }
            NamedByText = $true
        }
        @{
            Id = 'DISA-STIG-WS2019-DC'
            File = 'disa-stig-ws2019-dc'
            PowerStig = 'WindowsServer-2019-DC-3.8'
            Product = 'Windows Server 2019 domain controller'
            Role = 'domain controller'
            AppliesTo = @{ ProductTypes = @(2); Builds = @(17763) }
            NamedByText = $true
        }
        @{
            Id = 'DISA-STIG-WS2022-MS'
            File = 'disa-stig-ws2022-ms'
            PowerStig = 'WindowsServer-2022-MS-2.8'
            Product = 'Windows Server 2022 member server'
            Role = 'member server'
            AppliesTo = @{ ProductTypes = @(3); Builds = @(20348) }
            NamedByText = $true
        }
        @{
            Id = 'DISA-STIG-WS2022-DC'
            File = 'disa-stig-ws2022-dc'
            PowerStig = 'WindowsServer-2022-DC-2.8'
            Product = 'Windows Server 2022 domain controller'
            Role = 'domain controller'
            AppliesTo = @{ ProductTypes = @(2); Builds = @(20348) }
            NamedByText = $true
        }
        @{
            Id = 'DISA-STIG-WS2025-MS'
            File = 'disa-stig-ws2025-ms'
            PowerStig = 'WindowsServer-2025-MS-1.1'
            Product = 'Windows Server 2025 member server'
            Role = 'member server'
            AppliesTo = @{ ProductTypes = @(3); Builds = @(26100) }
            NamedByText = $true
        }
        @{
            Id = 'DISA-STIG-WS2025-DC'
            File = 'disa-stig-ws2025-dc'
            PowerStig = 'WindowsServer-2025-DC-1.1'
            Product = 'Windows Server 2025 domain controller'
            Role = 'domain controller'
            AppliesTo = @{ ProductTypes = @(2); Builds = @(26100) }
            NamedByText = $true
        }
    )
}
