# HIPAA Security Rule (45 CFR Part 164, Subpart C, 164.308 to 164.316): every
# standard and implementation specification, 65 in all, cited as in the eCFR (current
# as of 2026-10-23). Most are administrative, physical or organizational and are
# Manual here; the ones an endpoint can show evidence for carry checks. "Addressable"
# does not mean optional: it means implement it, or document why an equivalent
# measure is reasonable. The rule sets no numbers, so the thresholds are the example
# profile's. The rule is a US government work; titles are its own headings.
# Text: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C
# Field meanings are in frameworks/README.md.

@{
    Id = 'HIPAA'
    Name = 'HIPAA Security Rule'
    Source = 'https://www.hhs.gov/hipaa/for-professionals/security/'
    Levels = @('HIPAA')
    Complete = $true
    Thresholds = @{}
    Requirements = @(
        @{
            Id = '164.308(a)(1)(i)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Security management process (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(1)(ii)(A)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Risk analysis (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(1)(ii)(B)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Risk management (required)'
            Checks = @('SI-UpdateRecency', 'SI-AntivirusActive')
            Note = 'Endpoint evidence of security measures in place; the risk management plan itself is reviewed separately.'
        }
        @{
            Id = '164.308(a)(1)(ii)(C)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Sanction policy (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(1)(ii)(D)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Information system activity review (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(2)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Assigned security responsibility (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(3)(i)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Workforce security (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(3)(ii)(A)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Authorization and/or supervision (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(3)(ii)(B)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Workforce clearance procedure (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(3)(ii)(C)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Termination procedures (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(4)(i)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Information access management (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(4)(ii)(A)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Isolating health care clearinghouse functions (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(4)(ii)(B)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Access authorization (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(4)(ii)(C)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Access establishment and modification (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(5)(i)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Security awareness and training (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(5)(ii)(A)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Security reminders (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
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
            Id = '164.308(a)(6)(i)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Security incident procedures (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(6)(ii)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Response and reporting (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(7)(i)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Contingency plan (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(7)(ii)(A)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Data backup plan (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(7)(ii)(B)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Disaster recovery plan (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(7)(ii)(C)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Emergency mode operation plan (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(7)(ii)(D)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Testing and revision procedures (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(7)(ii)(E)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Applications and data criticality analysis (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(a)(8)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Evaluation (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(b)(1)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Business associate contracts and other arrangements (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.308(b)(3)'
            Family = 'Admin'
            Level = 'HIPAA'
            Title = 'Written contract or other arrangement (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(a)(1)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Facility access controls (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(a)(2)(i)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Contingency operations (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(a)(2)(ii)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Facility security plan (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(a)(2)(iii)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Access control and validation procedures (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(a)(2)(iv)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Maintenance records (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(b)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Workstation use (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(c)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Workstation security (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
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
            Id = '164.310(d)(2)(i)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Disposal (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(d)(2)(ii)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Media re-use (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(d)(2)(iii)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Accountability (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.310(d)(2)(iv)'
            Family = 'Physical'
            Level = 'HIPAA'
            Title = 'Data backup and storage (addressable)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
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
        @{
            Id = '164.314(a)(1)'
            Family = 'Organizational'
            Level = 'HIPAA'
            Title = 'Business associate contracts or other arrangements (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.314(a)(2)(i)'
            Family = 'Organizational'
            Level = 'HIPAA'
            Title = 'Business associate contracts (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.314(a)(2)(ii)'
            Family = 'Organizational'
            Level = 'HIPAA'
            Title = 'Other arrangements (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.314(a)(2)(iii)'
            Family = 'Organizational'
            Level = 'HIPAA'
            Title = 'Business associate contracts with subcontractors (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.314(b)(1)'
            Family = 'Organizational'
            Level = 'HIPAA'
            Title = 'Requirements for group health plans (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.314(b)(2)'
            Family = 'Organizational'
            Level = 'HIPAA'
            Title = 'Plan document amendments (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.316(a)'
            Family = 'Documentation'
            Level = 'HIPAA'
            Title = 'Policies and procedures (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.316(b)(1)'
            Family = 'Documentation'
            Level = 'HIPAA'
            Title = 'Documentation (standard)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.316(b)(2)(i)'
            Family = 'Documentation'
            Level = 'HIPAA'
            Title = 'Time limit (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.316(b)(2)(ii)'
            Family = 'Documentation'
            Level = 'HIPAA'
            Title = 'Availability (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = '164.316(b)(2)(iii)'
            Family = 'Documentation'
            Level = 'HIPAA'
            Title = 'Updates (required)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
    )
}
