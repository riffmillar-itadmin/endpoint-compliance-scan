# DISA Active Directory Forest STIG, Version 3 Release 2 (benchmark date 02 Jul
# 2025): all 7 rules, by Vuln ID. Rules and severities from DISA's STIG
# (U_Active_Directory_Forest_STIG_V3R2_Manual-xccdf.xml); automated checks written
# for this project. STIG content is published by DISA at
# https://public.cyber.mil/stigs/. Titles here are short summaries; STIG Viewer has
# the full rule text. Levels are the severity categories.
# Field meanings are in frameworks/README.md.

@{
    Id = 'DISA-STIG-AD-Forest'
    Name = 'DISA Active Directory Forest STIG V3R2'
    Source = 'https://public.cyber.mil/stigs/'
    StigId = 'Active_Directory_Forest'
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
            Id = 'V-243502'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Schema Admins has no members outside schema changes'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'SchemaAdminsEmpty' }
            )
        }
        @{
            Id = 'V-243503'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Anonymous access to forest data is disabled (dSHeuristics)'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'AnonymousForestAccess' }
            )
        }
        @{
            Id = 'V-243504'
            Family = 'Directory'
            Level = 'CAT II'
            Title = 'Forest root PDC emulator takes time from an external NTP source'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'ForestRootPdcTime' }
            )
        }
        @{
            Id = 'V-243505'
            Family = 'Other'
            Level = 'CAT III'
            Title = 'Changes to the AD schema must be subject to a documented configuration management process.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-243506'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Update access to the directory schema must be restricted to appropriate accounts.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
        @{
            Id = 'V-269098'
            Family = 'Directory'
            Level = 'CAT I'
            Title = 'Certificate templates that need manager approval require it'
            Checks = @()
            Expect = @(
                @{ Source = 'Directory'; Name = 'CertificateTemplateApproval' }
            )
        }
        @{
            Id = 'V-269099'
            Family = 'Other'
            Level = 'CAT I'
            Title = 'Windows Server running Active Directory Certificate Services (AD CS) must be managed by a PAW tier 0.'
            Checks = @()
            Note = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'
        }
    )
}
