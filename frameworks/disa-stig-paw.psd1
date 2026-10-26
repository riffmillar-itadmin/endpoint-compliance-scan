# DISA Microsoft Windows PAW STIG, Version 3 Release 3 (benchmark date 01 Apr 2026):
# all 24 rules, by Vuln ID. Rules and severities from DISA's STIG
# (U_MS_Windows_PAW_STIG_V3R3_Manual-xccdf.xml); automated checks written for this
# project. STIG content is published by DISA at https://public.cyber.mil/stigs/.
# Titles here are short summaries; STIG Viewer has the full rule text. Levels are
# the severity categories.
# Field meanings are in frameworks/README.md.

@{
    Id = 'DISA-STIG-PAW'
    Name = 'DISA Windows PAW STIG V3R3'
    Source = 'https://public.cyber.mil/stigs/'
    StigId = 'Windows_PAW_STIG'
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
            Id = 'V-243442'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Administrators of high-value IT resources must complete required training.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243443'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Site IT resources designated as high value by the Authorizing Official (AO) must be remotely managed only via a Windo...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243444'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Administrative accounts of all high-value IT resources must be assigned to a specific administrative tier in Active D...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243445'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'A Windows PAW must only be used to manage high-value IT resources assigned to the same tier.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243446'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'All high-value IT resources must be assigned to a specific administrative tier to separate highly sensitive resources...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243447'
            Family = 'PAW'
            Level = 'CAT II'
            Title = 'Windows 11 version is one the AO approved'
            Checks = @()
            Expect = @(
                @{ Source = 'Local'; Name = 'WindowsVersion' }
            )
        }
        @{
            Id = 'V-243448'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'A Windows update service must be available to provide software updates for the PAW platform.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243449'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The Windows PAW must be configured so that all non-administrative-related applications and functions are blocked or r...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243450'
            Family = 'PAW'
            Level = 'CAT II'
            Title = 'Device Guard enforces a kernel-mode code integrity policy'
            Checks = @()
            Expect = @(
                @{ Source = 'Local'; Name = 'CodeIntegrityEnforced' }
            )
        }
        @{
            Id = 'V-243451'
            Family = 'PAW'
            Level = 'CAT II'
            Title = 'Device Guard enforces a user-mode code integrity policy'
            Checks = @()
            Expect = @(
                @{ Source = 'Local'; Name = 'UserModeCodeIntegrityEnforced' }
            )
        }
        @{
            Id = 'V-243452'
            Family = 'PAW'
            Level = 'CAT II'
            Title = 'Allow log on locally: Administrators and groups managing high-value IT resources only'
            Checks = @()
            Expect = @(
                @{ Source = 'Local'; Name = 'LocalLogonHolders' }
            )
        }
        @{
            Id = 'V-243453'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The domain must be configured to restrict privileged administrator accounts from logging on to lower-tier hosts.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243454'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'A Windows PAW used to manage domain controllers and directory services must not be used to manage any other type of h...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243455'
            Family = 'PAW'
            Level = 'CAT II'
            Title = 'Allow log on locally on an AD PAW: Administrators and AD management groups only'
            Checks = @()
            Expect = @(
                @{ Source = 'Local'; Name = 'LocalLogonHolders' }
            )
        }
        @{
            Id = 'V-243456'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'In a Windows PAW, administrator accounts used for maintaining the PAW must be separate from administrative accounts u...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243457'
            Family = 'PAW'
            Level = 'CAT II'
            Title = 'Interactive logon requires Windows Hello for Business or a smart card'
            Checks = @()
            Expect = @(
                @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'scforceoption'; Op = 'eq'; Value = 1 }
            )
            Note = 'Another DoD-approved two-factor method also meets the rule; record it if this setting is off for that reason.'
        }
        @{
            Id = 'V-243458'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'The Windows PAW must use a trusted channel for all connections between a PAW and IT resources managed from the PAW.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243459'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'If several Windows PAWs are set up in virtual machines (VMs) on a host server, the host server must only contain PAW ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243460'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The Windows PAW must be configured so that all inbound ports and services to a PAW are blocked except as needed for m...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243461'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'The Windows PAW must be configured so that all outbound connections to the Internet from a PAW are blocked.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243462'
            Family = 'PAW'
            Level = 'CAT II'
            Title = 'Local Administrators holds only the PAW management group and local administrators'
            Checks = @()
            Expect = @(
                @{ Source = 'Local'; Name = 'LocalAdministrators' }
            )
        }
        @{
            Id = 'V-243463'
            Family = 'PAW'
            Level = 'CAT II'
            Title = 'Local privileged groups other than Administrators are empty'
            Checks = @()
            Expect = @(
                @{ Source = 'Local'; Name = 'PrivilegedGroupsEmpty' }
            )
        }
        @{
            Id = 'V-243464'
            Family = 'PAW'
            Level = 'CAT II'
            Title = 'Restricted remote administration is enforced on the PAW'
            Checks = @()
            Expect = @(
                @{
                    Source = 'Registry'
                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
                    Name = 'RestrictedRemoteAdministration'
                    Op = 'eq'
                    Value = 1
                }
            )
            Note = 'Covers the PAW side only. Check DisableRestrictedAdmin = 0 under HKLM\System\CurrentControlSet\Control\Lsa on each high-value system it manages.'
        }
        @{
            Id = 'V-243465'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'If several PAWs are set up in virtual machines (VMs) on a host server, domain administrative accounts used to manage ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
    )
}
