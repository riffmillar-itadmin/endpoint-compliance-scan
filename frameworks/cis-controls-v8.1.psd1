# CIS Critical Security Controls v8.1, Implementation Groups 1 and 2: 18 safeguards.
# This catalog lists only the safeguards that a Windows endpoint can show evidence for, with
# titles written for this project; the standard itself has the authoritative text and
# the full list. Complete = $false makes every report say so.
# The Controls are published by the Center for Internet Security, https://www.cisecurity.org/controls.
# Field meanings are in frameworks/README.md.

@{
    Id = 'CIS-v8.1'
    Name = 'CIS Controls v8.1 (endpoint safeguards)'
    Source = 'https://www.cisecurity.org/controls/v8-1'
    Levels = @('IG1', 'IG2')
    Complete = $false
    Thresholds = @{ InactivityLockMaxSeconds = 900; LockoutThresholdMax = 20; MinPasswordLength = 14; MaxDaysSinceUpdate = 30 }
    Requirements = @(
        @{ Id = '3.10'; Family = 'Data'; Level = 'IG2'; Title = 'Encrypt sensitive data in transit'; Checks = @('SC-LegacyTlsDisabled', 'AC-RdpProtected') }
        @{
            Id = '3.11'
            Family = 'Data'
            Level = 'IG2'
            Title = 'Encrypt sensitive data at rest'
            Checks = @('SC-BitLocker')
            Note = 'Covers the operating system volume; other data stores are reviewed separately.'
        }
        @{ Id = '4.3'; Family = 'Config'; Level = 'IG1'; Title = 'Lock sessions automatically after inactivity'; Checks = @('AC-InactivityLock') }
        @{ Id = '4.4'; Family = 'Config'; Level = 'IG1'; Title = 'Run a firewall on servers'; Checks = @('SC-FirewallEnabled') }
        @{ Id = '4.5'; Family = 'Config'; Level = 'IG1'; Title = 'Run a firewall on end-user devices'; Checks = @('SC-FirewallEnabled') }
        @{
            Id = '4.7'
            Family = 'Config'
            Level = 'IG1'
            Title = 'Manage default accounts'
            Checks = @('AC-GuestDisabled')
            Expect = @(
                @{ Source = 'SecPol'; Name = 'NewAdministratorName'; Op = 'ne'; Value = 'Administrator' }
            )
            Note = 'Renaming the built-in Administrator is one way to make it unusable; disabling it is another.'
        }
        @{
            Id = '4.8'
            Family = 'Config'
            Level = 'IG2'
            Title = 'Uninstall or disable unnecessary services'
            Checks = @('CM-NonessentialServices', 'CM-Smb1Disabled')
        }
        @{ Id = '4.10'; Family = 'Config'; Level = 'IG2'; Title = 'Lock portable devices after repeated failed logons'; Checks = @('AC-AccountLockout') }
        @{
            Id = '5.2'
            Family = 'Account'
            Level = 'IG1'
            Title = 'Use unique, strong passwords'
            Checks = @('IA-PasswordComplexity')
            Note = 'CIS asks for 14 characters without MFA, 8 with; the threshold assumes no MFA.'
        }
        @{
            Id = '5.4'
            Family = 'Account'
            Level = 'IG1'
            Title = 'Keep administrator rights to dedicated admin accounts'
            Checks = @('AC-LocalAdminCount', 'AC-UacEnabled')
        }
        @{ Id = '7.3'; Family = 'Vuln'; Level = 'IG1'; Title = 'Patch the operating system automatically'; Checks = @('SI-UpdateRecency') }
        @{ Id = '8.2'; Family = 'Audit'; Level = 'IG1'; Title = 'Collect audit logs'; Checks = @('AU-AuditPolicy') }
        @{ Id = '8.3'; Family = 'Audit'; Level = 'IG1'; Title = 'Keep enough audit log storage'; Checks = @('AU-SecurityLogSize') }
        @{ Id = '8.4'; Family = 'Audit'; Level = 'IG2'; Title = 'Synchronize time'; Checks = @('AU-TimeSync') }
        @{
            Id = '8.5'
            Family = 'Audit'
            Level = 'IG2'
            Title = 'Collect detailed audit logs'
            Checks = @('AU-AuditPolicy')
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Process Creation'; Setting = 'Success' }
            )
        }
        @{ Id = '10.1'; Family = 'Malware'; Level = 'IG1'; Title = 'Run anti-malware software'; Checks = @('SI-AntivirusActive') }
        @{ Id = '10.2'; Family = 'Malware'; Level = 'IG1'; Title = 'Update anti-malware signatures automatically'; Checks = @('SI-SignatureAge') }
        @{ Id = '10.3'; Family = 'Malware'; Level = 'IG1'; Title = 'Turn off autorun and autoplay for removable media'; Checks = @('CM-AutoplayDisabled') }
    )
}
