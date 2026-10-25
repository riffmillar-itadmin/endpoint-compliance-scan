# DISA Active Directory Domain STIG, Version 3 Release 8 (benchmark date 30 Sep
# 2026): all 36 rules, by Vuln ID. Rules and severities from DISA's STIG
# (U_Active_Directory_Domain_STIG_V3R8_Manual-xccdf.xml); automated checks written
# for this project. STIG content is published by DISA at
# https://public.cyber.mil/stigs/. Titles here are short summaries; STIG Viewer has
# the full rule text. Levels are the severity categories.
# Field meanings are in frameworks/README.md.

@{
    Id = 'DISA-STIG-AD-Domain'
    Name = 'DISA Active Directory Domain STIG V3R8'
    Source = 'https://public.cyber.mil/stigs/'
    StigId = 'Active_Directory_Domain'
    Levels = @('CAT I', 'CAT II', 'CAT III')
    Complete = $true
    AppliesTo = @{ ProductTypes = @(2) }
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
            Id = 'V-243466'
            Family = 'Directory'
            Level = 'CAT I'
            Title = 'Enterprise Admins members are in no other administrator group'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'EnterpriseAdminsSeparate' }
            )
        }
        @{
            Id = 'V-243467'
            Family = 'Directory'
            Level = 'CAT I'
            Title = 'Domain Admins members are in no other administrator group'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'DomainAdminsSeparate' }
            )
        }
        @{
            Id = 'V-243468'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Administrators must have separate accounts specifically for managing domain member servers.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243469'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Administrators must have separate accounts specifically for managing domain workstations.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243470'
            Family = 'Directory'
            Level = 'CAT I'
            Title = 'Privileged accounts are sensitive and cannot be delegated'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'PrivilegedNotDelegated' }
            )
        }
        @{
            Id = 'V-243471'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Local administrator passwords are unique (LAPS)'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'LapsCoverage' }
            )
        }
        @{
            Id = 'V-243472'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Separate smart cards must be used for Enterprise Admin (EA) and Domain Admin (DA) accounts from smart cards used for ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243473'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Separate domain accounts must be used to manage public facing servers from any domain accounts used to manage interna...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243475'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Domain controllers must be blocked from Internet access.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243476'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'NT hashes of smart card accounts are rotated'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'SmartCardHashRolling' }
            )
        }
        @{
            Id = 'V-243477'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Administrative accounts are in Protected Users'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'ProtectedUsers' }
            )
        }
        @{
            Id = 'V-243478'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'No computer but a domain controller has unconstrained delegation'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'UnconstrainedDelegation' }
            )
        }
        @{
            Id = 'V-243479'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'DSRM password changed in the last year'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'DsrmPasswordAge' }
            )
        }
        @{
            Id = 'V-243480'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Domain functional level is Windows Server 2016 or later'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'DomainFunctionalLevel' }
            )
        }
        @{
            Id = 'V-243481'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Access to need-to-know information must be restricted to an authorized community of interest.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243482'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Interconnections between DoW directory services of different classification levels must use a cross-domain solution t...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243483'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'A controlled interface must have interconnections among DoW information systems operating between DoW and non-DoW sys...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243484'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Trusts filter SIDs from other domains'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'TrustSidFiltering' }
            )
        }
        @{
            Id = 'V-243485'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Outgoing forest trusts use selective authentication'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'SelectiveAuthentication' }
            )
        }
        @{
            Id = 'V-243486'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Pre-Windows 2000 Compatible Access excludes Everyone and Anonymous Logon'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'PreWindows2000Access' }
            )
        }
        @{
            Id = 'V-243487'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Incoming Forest Trust Builders and Group Policy Creator Owners are limited'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'TrustBuildersAndPolicyCreators' }
            )
        }
        @{
            Id = 'V-243488'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'User accounts with delegated authority must be removed from Windows built-in administrative groups or remove the dele...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243489'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Read-only Domain Controller (RODC) architecture and configuration must comply with directory services requirements.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243490'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Usage of administrative accounts must be monitored for suspicious and anomalous activity.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243491'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Systems must be monitored for attempts to use local accounts to log on remotely from other systems.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243492'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Systems must be monitored for remote desktop logons.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243493'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Active Directory data must be backed up daily for systems with a Risk Management Framework categorization for Availab...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243494'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Each cross-directory authentication configuration must be documented.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243495'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'A VPN must be used to protect directory network traffic for directory service implementation spanning enclave boundar...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243496'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'Accounts from outside directories that are not part of the same organization or are not subject to the same security ...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243497'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Inter-site replication occurs at least daily'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'InterSiteReplication' }
            )
        }
        @{
            Id = 'V-243498'
            Family = 'Other'
            Level = 'CAT II'
            Title = 'If a VPN is used in the AD implementation, the traffic must be inspected by the network Intrusion detection system (I...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243499'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Active Directory implementation information must be added to the organization contingency plan where the Risk Managem...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243500'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'More than one domain controller supports the domain'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'DomainControllerCount' }
            )
        }
        @{
            Id = 'V-243501'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'The impact of CPCON changes on the cross-directory authentication configuration must be considered and procedures doc...'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-269097'
            Family = 'Audit'
            Level = 'CAT II'
            Title = 'Kerberos Authentication Service and Kerberos Service Ticket Operations audited: Success and Failure'
            Checks = @()
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Kerberos Authentication Service'; Setting = 'SuccessAndFailure' }
                @{ Source = 'Audit'; Subcategory = 'Kerberos Service Ticket Operations'; Setting = 'SuccessAndFailure' }
            )
        }
    )
}
