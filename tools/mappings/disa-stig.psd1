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
    # DISA publishes one STIG for both server roles, which PowerStig splits in two
    # with IDs of its own. DisaBenchmark names the DISA benchmark a catalog follows
    # (default: PowerStig's ID), and NotForRole matches the STIG IDs of the rules
    # that are for the other role only.
    #
    # Overrides apply when the catalog follows a DISA release newer than PowerStig's:
    # for each rule DISA changed, the fields to replace (Title, Checks, Expect, Note),
    # DomainOnly to make its expectations NotApplicable off a domain, or MoveTo, the
    # Vuln ID DISA moved a split rule's part to. Reason says what changed. An
    # override for a rule the release doesn't have stops the build, so each one is
    # reviewed when the release changes. Reviewed lists automated rules DISA reworded
    # that a person has checked against that release; the build warns about the rest.
    #
    # Corrections fix PowerStig's automation whatever release the catalog follows,
    # with the same fields as Overrides. NotApplicableIf names the rules whose
    # being met makes a rule NotApplicable, for checks that say "if
    # WN25-00-000380 is configured, this is not applicable"; StandaloneOnly is
    # DomainOnly's opposite. The build stops on an automated rule with no expected
    # value, a check that lists several values (PowerStig keeps one), or a check
    # waived by another rule, until a correction or override sets its Expect or
    # NotApplicableIf.
    #
    # A catalog without PowerStig is built from DISA's XCCDF alone: Automated gives
    # each automated rule's Family, Title and Expect, written for this project and
    # checked against Release; every other rule is Manual.
    #
    # PolicyFallback joins each rule PowerStig splits into a Group Policy value (.a)
    # and the local setting (.b) into one requirement that reads the local setting
    # only when no policy value exists, as the Firewall STIG's checks do. A catalog
    # without AppliesTo applies to any Windows.
    Catalogs = @(
        @{
            Id = 'DISA-STIG-Win11'
            File = 'disa-stig-win11'
            PowerStig = 'WindowsClient-11-2.7'
            Product = 'Windows 11'
            AppliesTo = @{ ProductTypes = @(1); MinBuild = 22000 }
            Corrections = @{
                'V-253286' = @{
                    Reason = 'NA when V-253287 and V-253288 are met: SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-253287', 'V-253288')
                }
                'V-253287' = @{
                    Reason = 'NA when V-253286 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-253286')
                }
                'V-253288' = @{
                    Reason = 'NA when V-253286 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-253286')
                }
                'V-253392' = @{
                    Reason = 'NA when diagnostic data is Security or Basic (V-253393 met).'
                    NotApplicableIf = @('V-253393')
                }
                'V-253393' = @{
                    Reason = 'The check allows 0 (Security) or 1 (Basic); PowerStig keeps only 0.'
                    Title = 'AllowTelemetry (DataCollection) in 0/1'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Op = 'in'; Values = @(0, 1) })
                }
                'V-253394.a' = @{
                    Reason = 'Domain-joined systems: the check allows 0, 1, 2, 99 or 100; PowerStig keeps only 0. Standalone systems are checked by V-253394.b.'
                    Title = 'DODownloadMode (DeliveryOptimization) in 0/1/2/99/100'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name = 'DODownloadMode'; Op = 'in'; Values = @(0, 1, 2, 99, 100) })
                    DomainOnly = $true
                }
                'V-253394.b' = @{
                    Reason = 'Standalone systems (configured in Settings): the check allows 0 or 1; PowerStig keeps only 0.'
                    Title = 'DODownloadMode (Config) in 0/1'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'; Name = 'DODownloadMode'; Op = 'in'; Values = @(0, 1) })
                    StandaloneOnly = $true
                }
            }
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
            DisaBenchmark = 'MS_Windows_Server_2019_STIG'
            NotForRole = '^WN19-DC-'
            Product = 'Windows Server 2019 member server'
            Role = 'member server'
            AppliesTo = @{ ProductTypes = @(3); Builds = @(17763) }
            NamedByText = $true
            Corrections = @{
                'V-205682' = @{
                    Reason = 'NA when V-205683 and V-205684 are met: SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-205683', 'V-205684')
                }
                'V-205683' = @{
                    Reason = 'NA when V-205682 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-205682')
                }
                'V-205684' = @{
                    Reason = 'NA when V-205682 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-205682')
                }
            }
        }
        @{
            Id = 'DISA-STIG-WS2019-DC'
            File = 'disa-stig-ws2019-dc'
            PowerStig = 'WindowsServer-2019-DC-3.8'
            DisaBenchmark = 'MS_Windows_Server_2019_STIG'
            NotForRole = '^WN19-MS-'
            Product = 'Windows Server 2019 domain controller'
            Role = 'domain controller'
            AppliesTo = @{ ProductTypes = @(2); Builds = @(17763) }
            NamedByText = $true
            Corrections = @{
                'V-205682' = @{
                    Reason = 'NA when V-205683 and V-205684 are met: SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-205683', 'V-205684')
                }
                'V-205683' = @{
                    Reason = 'NA when V-205682 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-205682')
                }
                'V-205684' = @{
                    Reason = 'NA when V-205682 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-205682')
                }
            }
        }
        @{
            Id = 'DISA-STIG-WS2022-MS'
            File = 'disa-stig-ws2022-ms'
            PowerStig = 'WindowsServer-2022-MS-2.8'
            DisaBenchmark = 'MS_Windows_Server_2022_STIG'
            NotForRole = '^WN22-DC-'
            Product = 'Windows Server 2022 member server'
            Role = 'member server'
            AppliesTo = @{ ProductTypes = @(3); Builds = @(20348) }
            NamedByText = $true
            Corrections = @{
                'V-254275' = @{
                    Reason = 'NA when V-254276 and V-254277 are met: SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-254276', 'V-254277')
                }
                'V-254276' = @{
                    Reason = 'NA when V-254275 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-254275')
                }
                'V-254277' = @{
                    Reason = 'NA when V-254275 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-254275')
                }
                'V-254356' = @{
                    Reason = 'The check allows 1 (required diagnostic data) or 3 (optional); PowerStig keeps only 1.'
                    Title = 'AllowTelemetry (DataCollection) in 1/3'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Op = 'in'; Values = @(1, 3) })
                }
            }
            Overrides = @{
                'V-254289' = @{
                    Reason = 'V2R11 raised the maximum password age from 60 to 180 days.'
                    Title = 'Maximum password age: 1 to 180'
                    Expect = @(@{ Source = 'SecPol'; Name = 'MaximumPasswordAge'; Op = 'between'; Min = 1; Max = 180 })
                }
                'V-254340.a' = @{
                    Reason = 'V2R11: hardened UNC paths is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-254340.b' = @{
                    Reason = 'V2R11: hardened UNC paths is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-254343.a' = @{
                    Reason = 'V2R11: virtualization-based security is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-254343.b' = @{
                    Reason = 'V2R11: virtualization-based security is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-254359' = @{
                    Reason = 'V2R11 gives 0x4E2000 (5120000 KB, a week of a typical 5 GB log) as its example size; PowerStig had taken the mistyped hex 0x49960800 from the old text.'
                    Title = 'MaxSize (Security) >= 5120000'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Op = 'ge'; Value = 5120000 })
                    Note = 'DISA''s value is an example: the Security log must hold at least one week of records in your environment.'
                }
                'V-254441' = @{
                    Reason = 'V2R11: Credential Guard is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
            }
            # Automated rules whose check DISA reworded since PowerStig's release, checked
            # by hand: the expected values are unchanged.
            Reviewed = @{
                Release = 'V2R11'
                Rules = @('V-254281', 'V-254362', 'V-254363', 'V-254364', 'V-254371', 'V-254375', 'V-254490')
            }
        }
        @{
            Id = 'DISA-STIG-WS2022-DC'
            File = 'disa-stig-ws2022-dc'
            PowerStig = 'WindowsServer-2022-DC-2.8'
            DisaBenchmark = 'MS_Windows_Server_2022_STIG'
            NotForRole = '^WN22-MS-'
            Product = 'Windows Server 2022 domain controller'
            Role = 'domain controller'
            AppliesTo = @{ ProductTypes = @(2); Builds = @(20348) }
            NamedByText = $true
            Corrections = @{
                'V-254275' = @{
                    Reason = 'NA when V-254276 and V-254277 are met: SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-254276', 'V-254277')
                }
                'V-254276' = @{
                    Reason = 'NA when V-254275 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-254275')
                }
                'V-254277' = @{
                    Reason = 'NA when V-254275 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-254275')
                }
                'V-254356' = @{
                    Reason = 'The check allows 1 (required diagnostic data) or 3 (optional); PowerStig keeps only 1.'
                    Title = 'AllowTelemetry (DataCollection) in 1/3'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Op = 'in'; Values = @(1, 3) })
                }
            }
            Overrides = @{
                'V-254289' = @{
                    Reason = 'V2R11 raised the maximum password age from 60 to 180 days.'
                    Title = 'Maximum password age: 1 to 180'
                    Expect = @(@{ Source = 'SecPol'; Name = 'MaximumPasswordAge'; Op = 'between'; Min = 1; Max = 180 })
                }
                'V-254340.a' = @{
                    Reason = 'V2R11: hardened UNC paths is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-254340.b' = @{
                    Reason = 'V2R11: hardened UNC paths is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-254343.a' = @{
                    Reason = 'V2R11: virtualization-based security is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-254343.b' = @{
                    Reason = 'V2R11: virtualization-based security is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-254359' = @{
                    Reason = 'V2R11 gives 0x4E2000 (5120000 KB, a week of a typical 5 GB log) as its example size; PowerStig had taken the mistyped hex 0x49960800 from the old text.'
                    Title = 'MaxSize (Security) >= 5120000'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Op = 'ge'; Value = 5120000 })
                    Note = 'DISA''s value is an example: the Security log must hold at least one week of records in your environment.'
                }
            }
            # Automated rules whose check DISA reworded since PowerStig's release, checked
            # by hand: the expected values are unchanged.
            Reviewed = @{
                Release = 'V2R11'
                Rules = @('V-254281', 'V-254362', 'V-254363', 'V-254364', 'V-254371', 'V-254375', 'V-254490')
            }
        }
        @{
            Id = 'DISA-STIG-WS2025-MS'
            File = 'disa-stig-ws2025-ms'
            PowerStig = 'WindowsServer-2025-MS-1.1'
            DisaBenchmark = 'MS_Windows_Server_2025_STIG'
            NotForRole = '^WN25-DC-'
            Product = 'Windows Server 2025 member server'
            Role = 'member server'
            AppliesTo = @{ ProductTypes = @(3); Builds = @(26100) }
            NamedByText = $true
            Corrections = @{
                'V-278023' = @{
                    Reason = 'NA when V-278024 and V-278025 are met: SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-278024', 'V-278025')
                }
                'V-278024' = @{
                    Reason = 'NA when V-278023 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-278023')
                }
                'V-278025' = @{
                    Reason = 'NA when V-278023 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-278023')
                }
                'V-278103' = @{
                    Reason = 'The check allows 0 or 1; PowerStig has no value for this rule.'
                    Title = 'AllowTelemetry (DataCollection) in 0/1'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Op = 'in'; Values = @(0, 1) })
                }
                'V-278104' = @{
                    Reason = 'The check allows 0, 1, 2, 99 or 100 (3, Internet, is a finding); PowerStig keeps only 0.'
                    Title = 'DODownloadMode (DeliveryOptimization) in 0/1/2/99/100'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name = 'DODownloadMode'; Op = 'in'; Values = @(0, 1, 2, 99, 100) })
                }
                'V-278234' = @{
                    Reason = 'The check allows 2 (consent on the secure desktop) or 1 (credentials on the secure desktop); PowerStig keeps only 2.'
                    Title = 'ConsentPromptBehaviorAdmin (System) in 1/2'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; Op = 'in'; Values = @(1, 2) })
                }
            }
            Overrides = @{
                'V-278037' = @{
                    Reason = 'V1R4 raised the maximum password age from 60 to 180 days.'
                    Title = 'Maximum password age: 1 to 180'
                    Expect = @(@{ Source = 'SecPol'; Name = 'MaximumPasswordAge'; Op = 'between'; Min = 1; Max = 180 })
                }
                'V-278087.a' = @{
                    Reason = 'V1R4: hardened UNC paths is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-278087.b' = @{
                    Reason = 'V1R4: hardened UNC paths is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-278090.a' = @{
                    Reason = 'V1R4: virtualization-based security is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-278090.b' = @{
                    Reason = 'V1R4: virtualization-based security is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-278106' = @{
                    Reason = 'V1R4 gives 0x4E2000 (5120000 KB, a week of a typical 5 GB log) as its example size (V1R1 asked for 0x30000).'
                    Title = 'MaxSize (Security) >= 5120000'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Op = 'ge'; Value = 5120000 })
                    Note = 'DISA''s value is an example: the Security log must hold at least one week of records in your environment.'
                }
                'V-278190' = @{
                    Reason = 'V1R4: Credential Guard is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
            }
            # Automated rules whose check DISA reworded since PowerStig's release, checked
            # by hand: the expected values are unchanged.
            Reviewed = @{
                Release = 'V1R4'
                Rules = @('V-278029')
            }
        }
        @{
            Id = 'DISA-STIG-WS2025-DC'
            File = 'disa-stig-ws2025-dc'
            PowerStig = 'WindowsServer-2025-DC-1.1'
            DisaBenchmark = 'MS_Windows_Server_2025_STIG'
            NotForRole = '^WN25-MS-'
            Product = 'Windows Server 2025 domain controller'
            Role = 'domain controller'
            AppliesTo = @{ ProductTypes = @(2); Builds = @(26100) }
            NamedByText = $true
            Corrections = @{
                'V-278023' = @{
                    Reason = 'NA when V-278024 and V-278025 are met: SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-278024', 'V-278025')
                }
                'V-278024' = @{
                    Reason = 'NA when V-278023 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-278023')
                }
                'V-278025' = @{
                    Reason = 'NA when V-278023 is met (SMBv1 removed): SMBv1 can be disabled either way.'
                    NotApplicableIf = @('V-278023')
                }
                'V-278103' = @{
                    Reason = 'The check allows 0 or 1; PowerStig has no value for this rule.'
                    Title = 'AllowTelemetry (DataCollection) in 0/1'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Op = 'in'; Values = @(0, 1) })
                }
                'V-278104' = @{
                    Reason = 'The check allows 0, 1, 2, 99 or 100 (3, Internet, is a finding); PowerStig keeps only 0.'
                    Title = 'DODownloadMode (DeliveryOptimization) in 0/1/2/99/100'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name = 'DODownloadMode'; Op = 'in'; Values = @(0, 1, 2, 99, 100) })
                }
                'V-278234' = @{
                    Reason = 'The check allows 2 (consent on the secure desktop) or 1 (credentials on the secure desktop); PowerStig keeps only 2.'
                    Title = 'ConsentPromptBehaviorAdmin (System) in 1/2'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; Op = 'in'; Values = @(1, 2) })
                }
            }
            Overrides = @{
                'V-278037' = @{
                    Reason = 'V1R4 raised the maximum password age from 60 to 180 days.'
                    Title = 'Maximum password age: 1 to 180'
                    Expect = @(@{ Source = 'SecPol'; Name = 'MaximumPasswordAge'; Op = 'between'; Min = 1; Max = 180 })
                }
                'V-278087.a' = @{
                    Reason = 'V1R4: hardened UNC paths is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-278087.b' = @{
                    Reason = 'V1R4: hardened UNC paths is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-278090.a' = @{
                    Reason = 'V1R4: virtualization-based security is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-278090.b' = @{
                    Reason = 'V1R4: virtualization-based security is not applicable on standalone or nondomain-joined systems.'
                    DomainOnly = $true
                }
                'V-278106' = @{
                    Reason = 'V1R4 gives 0x4E2000 (5120000 KB, a week of a typical 5 GB log) as its example size (V1R1 asked for 0x30000).'
                    Title = 'MaxSize (Security) >= 5120000'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Op = 'ge'; Value = 5120000 })
                    Note = 'DISA''s value is an example: the Security log must hold at least one week of records in your environment.'
                }
                'V-278163' = @{
                    Reason = 'V1R4 checks LDAPServerEnforceIntegrity, which overrides the legacy LDAPServerIntegrity on Server 2025.'
                    Title = 'Domain controller: LDAP server signing enforced (LDAPServerEnforceIntegrity = 1)'
                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name = 'LDAPServerEnforceIntegrity'; Op = 'eq'; Value = 1 })
                }
            }
            # Automated rules whose check DISA reworded since PowerStig's release, checked
            # by hand: the expected values are unchanged.
            Reviewed = @{
                Release = 'V1R4'
                Rules = @('V-278029')
            }
        }
        @{
            Id = 'DISA-STIG-Firewall'
            File = 'disa-stig-firewall'
            PowerStig = 'WindowsFirewall-All-2.2'
            Product = 'Windows Defender Firewall'
            PolicyFallback = $true
            Overrides = @{
                'V-241989' = @{ Reason = 'Domain Profile: NA when the system is not a member of a domain.'; DomainOnly = $true }
                'V-241992' = @{ Reason = 'Domain Profile: NA when the system is not a member of a domain.'; DomainOnly = $true }
                'V-241993' = @{ Reason = 'Domain Profile: NA when the system is not a member of a domain.'; DomainOnly = $true }
                'V-241994' = @{ Reason = 'Domain Profile: NA when the system is not a member of a domain.'; DomainOnly = $true }
                'V-241995' = @{ Reason = 'Domain Profile: NA when the system is not a member of a domain.'; DomainOnly = $true }
                'V-241996' = @{ Reason = 'Domain Profile: NA when the system is not a member of a domain.'; DomainOnly = $true }
                'V-242004' = @{ Reason = 'NA when the system is not a member of a domain.'; DomainOnly = $true }
                'V-242005' = @{ Reason = 'NA when the system is not a member of a domain.'; DomainOnly = $true }
                'V-242009' = @{
                    Reason = 'PowerStig has no title for this manual rule beyond its discussion.'
                    Title = 'Inbound exceptions on domain workstations allow only authorized remote management hosts'
                    Note = 'Not automated by this scanner; review the inbound firewall rules. NA for servers and for workstations not joined to a domain.'
                }
            }
            # PowerStig keeps each part's text without DISA's policy-then-local wording, so
            # these read as reworded; paths, value names and values were checked against V2R2.
            Reviewed = @{
                Release = 'V2R2'
                Rules = @('V-241990', 'V-241991', 'V-241997', 'V-241998', 'V-241999', 'V-242000', 'V-242001', 'V-242002', 'V-242003', 'V-242006', 'V-242007', 'V-242008')
            }
        }
        @{
            Id = 'DISA-STIG-AD-Domain'
            File = 'disa-stig-ad-domain'
            DisaBenchmark = 'Active_Directory_Domain'
            Release = 'V3R8'
            Product = 'Active Directory Domain'
            AppliesTo = @{ ProductTypes = @(2) }
            Automated = @{
                'V-243466' = @{ Family = 'Directory'; Title = 'Enterprise Admins members are in no other administrator group'; Expect = @(@{ Source = 'Directory'; Name = 'EnterpriseAdminsSeparate' }) }
                'V-243467' = @{ Family = 'Directory'; Title = 'Domain Admins members are in no other administrator group'; Expect = @(@{ Source = 'Directory'; Name = 'DomainAdminsSeparate' }) }
                'V-243470' = @{ Family = 'Directory'; Title = 'Privileged accounts are sensitive and cannot be delegated'; Expect = @(@{ Source = 'Directory'; Name = 'PrivilegedNotDelegated' }) }
                'V-243471' = @{ Family = 'Directory'; Title = 'Local administrator passwords are unique (LAPS)'; Expect = @(@{ Source = 'Directory'; Name = 'LapsCoverage' }) }
                'V-243476' = @{ Family = 'Directory'; Title = 'NT hashes of smart card accounts are rotated'; Expect = @(@{ Source = 'Directory'; Name = 'SmartCardHashRolling' }) }
                'V-243477' = @{ Family = 'Directory'; Title = 'Administrative accounts are in Protected Users'; Expect = @(@{ Source = 'Directory'; Name = 'ProtectedUsers' }) }
                'V-243478' = @{ Family = 'Directory'; Title = 'No computer but a domain controller has unconstrained delegation'; Expect = @(@{ Source = 'Directory'; Name = 'UnconstrainedDelegation' }) }
                'V-243479' = @{ Family = 'Directory'; Title = 'DSRM password changed in the last year'; Expect = @(@{ Source = 'Directory'; Name = 'DsrmPasswordAge' }) }
                'V-243480' = @{ Family = 'Directory'; Title = 'Domain functional level is Windows Server 2016 or later'; Expect = @(@{ Source = 'Directory'; Name = 'DomainFunctionalLevel' }) }
                'V-243484' = @{ Family = 'Directory'; Title = 'Trusts filter SIDs from other domains'; Expect = @(@{ Source = 'Directory'; Name = 'TrustSidFiltering' }) }
                'V-243485' = @{ Family = 'Directory'; Title = 'Outgoing forest trusts use selective authentication'; Expect = @(@{ Source = 'Directory'; Name = 'SelectiveAuthentication' }) }
                'V-243486' = @{ Family = 'Directory'; Title = 'Pre-Windows 2000 Compatible Access excludes Everyone and Anonymous Logon'; Expect = @(@{ Source = 'Directory'; Name = 'PreWindows2000Access' }) }
                'V-243487' = @{ Family = 'Directory'; Title = 'Incoming Forest Trust Builders and Group Policy Creator Owners are limited'; Expect = @(@{ Source = 'Directory'; Name = 'TrustBuildersAndPolicyCreators' }) }
                'V-243497' = @{ Family = 'Directory'; Title = 'Inter-site replication occurs at least daily'; Expect = @(@{ Source = 'Directory'; Name = 'InterSiteReplication' }) }
                'V-243500' = @{ Family = 'Directory'; Title = 'More than one domain controller supports the domain'; Expect = @(@{ Source = 'Directory'; Name = 'DomainControllerCount' }) }
                'V-269097' = @{
                    Family = 'Audit'
                    Title = 'Kerberos Authentication Service and Kerberos Service Ticket Operations audited: Success and Failure'
                    Expect = @(
                        @{ Source = 'Audit'; Subcategory = 'Kerberos Authentication Service'; Setting = 'SuccessAndFailure' }
                        @{ Source = 'Audit'; Subcategory = 'Kerberos Service Ticket Operations'; Setting = 'SuccessAndFailure' }
                    )
                }
            }
        }
        @{
            Id = 'DISA-STIG-AD-Forest'
            File = 'disa-stig-ad-forest'
            DisaBenchmark = 'Active_Directory_Forest'
            Release = 'V3R2'
            Product = 'Active Directory Forest'
            AppliesTo = @{ ProductTypes = @(2) }
            Automated = @{
                'V-243502' = @{ Family = 'Directory'; Title = 'Schema Admins has no members outside schema changes'; Expect = @(@{ Source = 'Directory'; Name = 'SchemaAdminsEmpty' }) }
                'V-243503' = @{ Family = 'Directory'; Title = 'Anonymous access to forest data is disabled (dSHeuristics)'; Expect = @(@{ Source = 'Directory'; Name = 'AnonymousForestAccess' }) }
                'V-243504' = @{ Family = 'Directory'; Title = 'Forest root PDC emulator takes time from an external NTP source'; Expect = @(@{ Source = 'Directory'; Name = 'ForestRootPdcTime' }) }
                'V-269098' = @{ Family = 'Directory'; Title = 'Certificate templates that need manager approval require it'; Expect = @(@{ Source = 'Directory'; Name = 'CertificateTemplateApproval' }) }
            }
        }
    )
}
