# HIPAA Security Rule (45 CFR Part 164, Subpart C): 17 standards and
# implementation specifications. All of 164.312 (technical safeguards) is here; from
# 164.308 and 164.310 only the specifications an endpoint can show evidence for.
# "Addressable" does not mean optional: it means implement it, or document why an
# equivalent measure is reasonable. The rule sets no numbers, so the thresholds
# are the example profile's. Complete = $false makes every report say this is a subset.
# Text: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C
# Field meanings are in frameworks/README.md.

@{
    Id = 'HIPAA'
    Name = 'HIPAA Security Rule (endpoint safeguards)'
    Source = 'https://www.hhs.gov/hipaa/for-professionals/security/'
    Levels = @('HIPAA')
    Complete = $false
    Thresholds = @{}
    Requirements = @(
        @{
            Id = '164.308(a)(1)(ii)(B)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Risk management (required)'
            Checks = @('SI-UpdateRecency', 'SI-AntivirusActive')
            Note = 'Endpoint evidence of security measures in place; the risk management plan itself is reviewed separately.'
        }
        @{
            Id = '164.308(a)(5)(ii)(B)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Protection from malicious software (addressable)'
            Checks = @('SI-AntivirusActive', 'SI-SignatureAge', 'SI-ScanRecency')
        }
        @{
            Id = '164.308(a)(5)(ii)(C)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Log-in monitoring (addressable)'
            Checks = @('AU-SecurityLogSize')
            Expect = @(
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Success' }
                @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Failure' }
            )
            Note = 'Shows that logons are recorded; who reviews them is reviewed separately.'
        }
        @{
            Id = '164.308(a)(5)(ii)(D)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Password management (addressable)'
            Checks = @('IA-PasswordComplexity', 'IA-PasswordHistory', 'IA-StoredPasswordProtection')
        }
        @{
            Id = '164.310(d)(1)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Device and media controls (required)'
            Checks = @('MP-RemovableStorage', 'CM-AutoplayDisabled')
            Note = 'Disposal, re-use and accountability records are reviewed separately.'
        }
        @{
            Id = '164.312(a)(1)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Access control (required)'
            Checks = @('AC-GuestDisabled', 'AC-LocalAdminCount', 'AC-UacEnabled')
        }
        @{
            Id = '164.312(a)(2)(i)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Unique user identification (required)'
            Checks = @('AC-GuestDisabled', 'AC-NoPasswordNotRequired')
        }
        @{
            Id = '164.312(a)(2)(ii)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Emergency access procedure (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.312(a)(2)(iii)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Automatic logoff (addressable)'
            Checks = @('AC-InactivityLock', 'AC-RdpIdleTimeout')
        }
        @{ Id = '164.312(a)(2)(iv)'; Family = 'Technical'; Level = 'HIPAA'; Title = 'Encryption and decryption (addressable)'; Checks = @('SC-BitLocker') }
        @{
            Id = '164.312(b)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Audit controls (required)'
            Checks = @('AU-AuditPolicy', 'AU-SecurityLogSize', 'AU-TimeSync')
        }
        @{
            Id = '164.312(c)(1)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Integrity (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.312(c)(2)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Mechanism to authenticate ePHI (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.312(d)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Person or entity authentication (required)'
            Checks = @('AC-NoPasswordNotRequired', 'IA-BlankPasswordConsoleOnly', 'IA-NtlmV2Only', 'AC-AccountLockout')
        }
        @{
            Id = '164.312(e)(1)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Transmission security (required)'
            Checks = @('SC-LegacyTlsDisabled', 'AC-RdpProtected')
        }
        @{ Id = '164.312(e)(2)(i)'; Family = 'Technical'; Level = 'HIPAA'; Title = 'Integrity controls (addressable)'; Checks = @('SC-LegacyTlsDisabled') }
        @{
            Id = '164.312(e)(2)(ii)'
            Family = 'Technical'
            Level = 'HIPAA'
            Title = 'Encryption (addressable)'
            Checks = @('SC-LegacyTlsDisabled', 'AC-RdpProtected')
        }
    )
}
