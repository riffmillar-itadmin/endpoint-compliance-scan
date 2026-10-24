# DISA Microsoft Windows Defender Firewall with Advanced Security STIG, Version 2
# Release 2 (benchmark date 09 Nov 2023): all 21 rules, by Vuln ID. Rules and
# severities from DISA's STIG
# (U_MS_Windows_Defender_Firewall_STIG_V2R2_Manual-xccdf.xml); automated checks from
# the processed STIG WindowsFirewall-All-2.2 in Microsoft's PowerStig project (MIT),
# https://github.com/microsoft/PowerStig; STIG content is published by DISA at
# https://public.cyber.mil/stigs/. Titles here are short summaries; STIG Viewer has
# the full rule text. Levels are the severity categories.
# Field meanings are in frameworks/README.md.

@{
    Id = 'DISA-STIG-Firewall'
    Name = 'DISA Windows Defender Firewall STIG V2R2'
    Source = 'https://public.cyber.mil/stigs/'
    StigId = 'Windows_Firewall_with_Advanced_Security'
    Levels = @('CAT I', 'CAT II', 'CAT III')
    Complete = $true
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
            Id = 'V-242009'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Inbound exceptions on domain workstations allow only authorized remote management hosts'
            Checks = @()
            Note = 'Not automated by this scanner; review the inbound firewall rules. NA for servers and for workstations not joined to a domain.'
        }
        @{
            Id = 'V-241989'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableFirewall (DomainProfile) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'
                    Name = 'EnableFirewall'
                    Op = 'eq'
                    Value = 1
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-241990'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableFirewall (PrivateProfile) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'
                    Name = 'EnableFirewall'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-241991'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'EnableFirewall (PublicProfile) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
                    Name = 'EnableFirewall'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-241992'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'DefaultInboundAction (DomainProfile) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'
                    Name = 'DefaultInboundAction'
                    Op = 'eq'
                    Value = 1
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-241993'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DefaultOutboundAction (DomainProfile) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'
                    Name = 'DefaultOutboundAction'
                    Op = 'eq'
                    Value = 0
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-241994'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LogFileSize (Logging) >= 16384'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging'
                    Name = 'LogFileSize'
                    Op = 'ge'
                    Value = 16384
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-241995'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LogDroppedPackets (Logging) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging'
                    Name = 'LogDroppedPackets'
                    Op = 'eq'
                    Value = 1
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-241996'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LogSuccessfulConnections (Logging) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging'
                    Name = 'LogSuccessfulConnections'
                    Op = 'eq'
                    Value = 1
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-241997'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'DefaultInboundAction (PrivateProfile) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'
                    Name = 'DefaultInboundAction'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-241998'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DefaultOutboundAction (PrivateProfile) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'
                    Name = 'DefaultOutboundAction'
                    Op = 'eq'
                    Value = 0
                }
            )
        }
        @{
            Id = 'V-241999'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LogFileSize (Logging) >= 16384'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging'
                    Name = 'LogFileSize'
                    Op = 'ge'
                    Value = 16384
                }
            )
        }
        @{
            Id = 'V-242000'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LogDroppedPackets (Logging) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging'
                    Name = 'LogDroppedPackets'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-242001'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LogSuccessfulConnections (Logging) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging'
                    Name = 'LogSuccessfulConnections'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-242002'
            Family = 'Config'
            Level = 'CAT I'
            Title = 'DefaultInboundAction (PublicProfile) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
                    Name = 'DefaultInboundAction'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-242003'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'DefaultOutboundAction (PublicProfile) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
                    Name = 'DefaultOutboundAction'
                    Op = 'eq'
                    Value = 0
                }
            )
        }
        @{
            Id = 'V-242004'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowLocalPolicyMerge (PublicProfile) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
                    Name = 'AllowLocalPolicyMerge'
                    Op = 'eq'
                    Value = 0
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-242005'
            Family = 'Config'
            Level = 'CAT II'
            Title = 'AllowLocalIPsecPolicyMerge (PublicProfile) = 0'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
                    Name = 'AllowLocalIPsecPolicyMerge'
                    Op = 'eq'
                    Value = 0
                    DomainOnly = $true
                }
            )
        }
        @{
            Id = 'V-242006'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LogFileSize (Logging) >= 16384'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging'
                    Name = 'LogFileSize'
                    Op = 'ge'
                    Value = 16384
                }
            )
        }
        @{
            Id = 'V-242007'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LogDroppedPackets (Logging) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging'
                    Name = 'LogDroppedPackets'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
        @{
            Id = 'V-242008'
            Family = 'Config'
            Level = 'CAT III'
            Title = 'LogSuccessfulConnections (Logging) = 1'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
                    FallbackPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging'
                    Name = 'LogSuccessfulConnections'
                    Op = 'eq'
                    Value = 1
                }
            )
        }
    )
}
