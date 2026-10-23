# NIST SP 800-53 Rev 5 (release 5.2.0): the 287 controls and enhancements in
# the SP 800-53B Moderate baseline, 149 of which are also in Low. Generated from
# NIST's OSCAL catalog and baseline profiles, https://github.com/usnistgov/oscal-content.
# Field meanings are in frameworks/README.md.

@{
    Id = 'NIST-800-53r5'
    Name = 'NIST SP 800-53 Rev 5 (5.2.0) Low/Moderate baselines'
    Source = 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'
    Levels = @('Low', 'Moderate')
    Complete = $true
    Thresholds = @{}
    Requirements = @(
        @{
            Id = 'AC-1'
            Family = 'AC'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'AC-2'; Family = 'AC'; Level = 'Low'; Title = 'Account Management'; Checks = @('AC-GuestDisabled', 'AC-NoPasswordNotRequired') }
        @{
            Id = 'AC-2(1)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Account Management | Automated System Account Management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-2(2)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Account Management | Automated Temporary and Emergency Account Management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-2(3)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Account Management | Disable Accounts'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-2(4)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Account Management | Automated Audit Actions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-2(5)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Account Management | Inactivity Logout'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-2(13)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Account Management | Disable Accounts for High-risk Individuals'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'AC-3'; Family = 'AC'; Level = 'Low'; Title = 'Access Enforcement'; Checks = @('AC-UacEnabled') }
        @{
            Id = 'AC-4'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Information Flow Enforcement'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-5'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Separation of Duties'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'AC-6'; Family = 'AC'; Level = 'Moderate'; Title = 'Least Privilege'; Checks = @('AC-LocalAdminCount') }
        @{
            Id = 'AC-6(1)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Least Privilege | Authorize Access to Security Functions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-6(2)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Least Privilege | Non-privileged Access for Nonsecurity Functions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-6(5)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Least Privilege | Privileged Accounts'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-6(7)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Least Privilege | Review of User Privileges'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-6(9)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Least Privilege | Log Use of Privileged Functions'
            Checks = @('AU-SensitivePrivilegeUse')
        }
        @{
            Id = 'AC-6(10)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Least Privilege | Prohibit Non-privileged Users from Executing Privileged Functions'
            Checks = @('AC-UacEnabled', 'AC-UacSecureDesktop', 'AC-UacPromptBehavior')
        }
        @{ Id = 'AC-7'; Family = 'AC'; Level = 'Low'; Title = 'Unsuccessful Logon Attempts'; Checks = @('AC-AccountLockout') }
        @{ Id = 'AC-8'; Family = 'AC'; Level = 'Low'; Title = 'System Use Notification'; Checks = @('AC-LogonBanner') }
        @{ Id = 'AC-11'; Family = 'AC'; Level = 'Moderate'; Title = 'Device Lock'; Checks = @('AC-InactivityLock') }
        @{ Id = 'AC-11(1)'; Family = 'AC'; Level = 'Moderate'; Title = 'Device Lock | Pattern-hiding Displays'; Checks = @('AC-InactivityLock') }
        @{ Id = 'AC-12'; Family = 'AC'; Level = 'Moderate'; Title = 'Session Termination'; Checks = @('AC-RdpIdleTimeout') }
        @{
            Id = 'AC-14'
            Family = 'AC'
            Level = 'Low'
            Title = 'Permitted Actions Without Identification or Authentication'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'AC-17'; Family = 'AC'; Level = 'Low'; Title = 'Remote Access'; Checks = @('AC-RdpProtected') }
        @{
            Id = 'AC-17(1)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Remote Access | Monitoring and Control'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-17(2)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Remote Access | Protection of Confidentiality and Integrity Using Encryption'
            Checks = @('AC-RdpProtected')
        }
        @{
            Id = 'AC-17(3)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Remote Access | Managed Access Control Points'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-17(4)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Remote Access | Privileged Commands and Access'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-18'
            Family = 'AC'
            Level = 'Low'
            Title = 'Wireless Access'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-18(1)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Wireless Access | Authentication and Encryption'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-18(3)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Wireless Access | Disable Wireless Networking'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-19'
            Family = 'AC'
            Level = 'Low'
            Title = 'Access Control for Mobile Devices'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-19(5)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Access Control for Mobile Devices | Full Device or Container-based Encryption'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-20'
            Family = 'AC'
            Level = 'Low'
            Title = 'Use of External Systems'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-20(1)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Use of External Systems | Limits on Authorized Use'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-20(2)'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Use of External Systems | Portable Storage Devices - Restricted Use'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-21'
            Family = 'AC'
            Level = 'Moderate'
            Title = 'Information Sharing'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AC-22'
            Family = 'AC'
            Level = 'Low'
            Title = 'Publicly Accessible Content'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AT-1'
            Family = 'AT'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AT-2'
            Family = 'AT'
            Level = 'Low'
            Title = 'Literacy Training and Awareness'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AT-2(2)'
            Family = 'AT'
            Level = 'Low'
            Title = 'Literacy Training and Awareness | Insider Threat'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AT-2(3)'
            Family = 'AT'
            Level = 'Moderate'
            Title = 'Literacy Training and Awareness | Social Engineering and Mining'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AT-3'
            Family = 'AT'
            Level = 'Low'
            Title = 'Role-based Training'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AT-4'
            Family = 'AT'
            Level = 'Low'
            Title = 'Training Records'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AU-1'
            Family = 'AU'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'AU-2'; Family = 'AU'; Level = 'Low'; Title = 'Event Logging'; Checks = @('AU-AuditPolicy') }
        @{
            Id = 'AU-3'
            Family = 'AU'
            Level = 'Low'
            Title = 'Content of Audit Records'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AU-3(1)'
            Family = 'AU'
            Level = 'Moderate'
            Title = 'Content of Audit Records | Additional Audit Information'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'AU-4'; Family = 'AU'; Level = 'Low'; Title = 'Audit Log Storage Capacity'; Checks = @('AU-SecurityLogSize') }
        @{
            Id = 'AU-5'
            Family = 'AU'
            Level = 'Low'
            Title = 'Response to Audit Logging Process Failures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AU-6'
            Family = 'AU'
            Level = 'Low'
            Title = 'Audit Record Review, Analysis, and Reporting'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AU-6(1)'
            Family = 'AU'
            Level = 'Moderate'
            Title = 'Audit Record Review, Analysis, and Reporting | Automated Process Integration'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AU-6(3)'
            Family = 'AU'
            Level = 'Moderate'
            Title = 'Audit Record Review, Analysis, and Reporting | Correlate Audit Record Repositories'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AU-7'
            Family = 'AU'
            Level = 'Moderate'
            Title = 'Audit Record Reduction and Report Generation'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AU-7(1)'
            Family = 'AU'
            Level = 'Moderate'
            Title = 'Audit Record Reduction and Report Generation | Automatic Processing'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'AU-8'; Family = 'AU'; Level = 'Low'; Title = 'Time Stamps'; Checks = @('AU-TimeSync') }
        @{
            Id = 'AU-9'
            Family = 'AU'
            Level = 'Low'
            Title = 'Protection of Audit Information'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AU-9(4)'
            Family = 'AU'
            Level = 'Moderate'
            Title = 'Protection of Audit Information | Access by Subset of Privileged Users'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'AU-11'
            Family = 'AU'
            Level = 'Low'
            Title = 'Audit Record Retention'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'AU-12'; Family = 'AU'; Level = 'Low'; Title = 'Audit Record Generation'; Checks = @('AU-AuditPolicy') }
        @{
            Id = 'CA-1'
            Family = 'CA'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CA-2'
            Family = 'CA'
            Level = 'Low'
            Title = 'Control Assessments'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CA-2(1)'
            Family = 'CA'
            Level = 'Moderate'
            Title = 'Control Assessments | Independent Assessors'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CA-3'
            Family = 'CA'
            Level = 'Low'
            Title = 'Information Exchange'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CA-5'
            Family = 'CA'
            Level = 'Low'
            Title = 'Plan of Action and Milestones'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CA-6'
            Family = 'CA'
            Level = 'Low'
            Title = 'Authorization'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CA-7'
            Family = 'CA'
            Level = 'Low'
            Title = 'Continuous Monitoring'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CA-7(1)'
            Family = 'CA'
            Level = 'Moderate'
            Title = 'Continuous Monitoring | Independent Assessment'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CA-7(4)'
            Family = 'CA'
            Level = 'Low'
            Title = 'Continuous Monitoring | Risk Monitoring'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CA-9'
            Family = 'CA'
            Level = 'Low'
            Title = 'Internal System Connections'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-1'
            Family = 'CM'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-2'
            Family = 'CM'
            Level = 'Low'
            Title = 'Baseline Configuration'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-2(2)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Baseline Configuration | Automation Support for Accuracy and Currency'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-2(3)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Baseline Configuration | Retention of Previous Configurations'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-2(7)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Baseline Configuration | Configure Systems and Components for High-risk Areas'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-3'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Configuration Change Control'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-3(2)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Configuration Change Control | Testing, Validation, and Documentation of Changes'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-3(4)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Configuration Change Control | Security and Privacy Representatives'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-4'
            Family = 'CM'
            Level = 'Low'
            Title = 'Impact Analyses'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-4(2)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Impact Analyses | Verification of Controls'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-5'
            Family = 'CM'
            Level = 'Low'
            Title = 'Access Restrictions for Change'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-6'
            Family = 'CM'
            Level = 'Low'
            Title = 'Configuration Settings'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-7'
            Family = 'CM'
            Level = 'Low'
            Title = 'Least Functionality'
            Checks = @('CM-Smb1Disabled', 'CM-NonessentialServices', 'CM-AutoplayDisabled')
        }
        @{
            Id = 'CM-7(1)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Least Functionality | Periodic Review'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-7(2)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Least Functionality | Prevent Program Execution'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-7(5)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Least Functionality | Authorized Software - Allow-by-exception'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-8'
            Family = 'CM'
            Level = 'Low'
            Title = 'System Component Inventory'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-8(1)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'System Component Inventory | Updates During Installation and Removal'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-8(3)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'System Component Inventory | Automated Unauthorized Component Detection'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-9'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Configuration Management Plan'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-10'
            Family = 'CM'
            Level = 'Low'
            Title = 'Software Usage Restrictions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'CM-11'; Family = 'CM'; Level = 'Low'; Title = 'User-installed Software'; Checks = @('CM-AlwaysInstallElevated') }
        @{
            Id = 'CM-12'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Information Location'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CM-12(1)'
            Family = 'CM'
            Level = 'Moderate'
            Title = 'Information Location | Automated Tools to Support Information Location'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-1'
            Family = 'CP'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-2'
            Family = 'CP'
            Level = 'Low'
            Title = 'Contingency Plan'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-2(1)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Contingency Plan | Coordinate with Related Plans'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-2(3)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Contingency Plan | Resume Mission and Business Functions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-2(8)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Contingency Plan | Identify Critical Assets'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-3'
            Family = 'CP'
            Level = 'Low'
            Title = 'Contingency Training'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-4'
            Family = 'CP'
            Level = 'Low'
            Title = 'Contingency Plan Testing'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-4(1)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Contingency Plan Testing | Coordinate with Related Plans'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-6'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Alternate Storage Site'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-6(1)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Alternate Storage Site | Separation from Primary Site'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-6(3)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Alternate Storage Site | Accessibility'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-7'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Alternate Processing Site'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-7(1)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Alternate Processing Site | Separation from Primary Site'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-7(2)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Alternate Processing Site | Accessibility'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-7(3)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Alternate Processing Site | Priority of Service'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-8'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Telecommunications Services'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-8(1)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Telecommunications Services | Priority of Service Provisions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-8(2)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'Telecommunications Services | Single Points of Failure'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-9'
            Family = 'CP'
            Level = 'Low'
            Title = 'System Backup'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-9(1)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'System Backup | Testing for Reliability and Integrity'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-9(8)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'System Backup | Cryptographic Protection'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-10'
            Family = 'CP'
            Level = 'Low'
            Title = 'System Recovery and Reconstitution'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'CP-10(2)'
            Family = 'CP'
            Level = 'Moderate'
            Title = 'System Recovery and Reconstitution | Transaction Recovery'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-1'
            Family = 'IA'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-2'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identification and Authentication (Organizational Users)'
            Checks = @('AC-NoPasswordNotRequired', 'IA-BlankPasswordConsoleOnly')
        }
        @{
            Id = 'IA-2(1)'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identification and Authentication (Organizational Users) | Multi-factor Authentication to Privileged Accounts'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-2(2)'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identification and Authentication (Organizational Users) | Multi-factor Authentication to Non-privileged Accounts'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-2(8)'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identification and Authentication (Organizational Users) | Access to Accounts - Replay Resistant'
            Checks = @('IA-NtlmV2Only')
        }
        @{
            Id = 'IA-2(12)'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identification and Authentication (Organizational Users) | Acceptance of PIV Credentials'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-3'
            Family = 'IA'
            Level = 'Moderate'
            Title = 'Device Identification and Authentication'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-4'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identifier Management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-4(4)'
            Family = 'IA'
            Level = 'Moderate'
            Title = 'Identifier Management | Identify User Status'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-5'
            Family = 'IA'
            Level = 'Low'
            Title = 'Authenticator Management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-5(1)'
            Family = 'IA'
            Level = 'Low'
            Title = 'Authenticator Management | Password-based Authentication'
            Checks = @('IA-PasswordComplexity', 'IA-PasswordHistory', 'IA-StoredPasswordProtection')
        }
        @{
            Id = 'IA-5(2)'
            Family = 'IA'
            Level = 'Moderate'
            Title = 'Authenticator Management | Public Key-based Authentication'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-5(6)'
            Family = 'IA'
            Level = 'Moderate'
            Title = 'Authenticator Management | Protection of Authenticators'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-6'
            Family = 'IA'
            Level = 'Low'
            Title = 'Authentication Feedback'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-7'
            Family = 'IA'
            Level = 'Low'
            Title = 'Cryptographic Module Authentication'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-8'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identification and Authentication (Non-organizational Users)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-8(1)'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identification and Authentication (Non-organizational Users) | Acceptance of PIV Credentials from Other Agencies'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-8(2)'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identification and Authentication (Non-organizational Users) | Acceptance of External Authenticators'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-8(4)'
            Family = 'IA'
            Level = 'Low'
            Title = 'Identification and Authentication (Non-organizational Users) | Use of Defined Profiles'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-11'
            Family = 'IA'
            Level = 'Low'
            Title = 'Re-authentication'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-12'
            Family = 'IA'
            Level = 'Moderate'
            Title = 'Identity Proofing'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-12(2)'
            Family = 'IA'
            Level = 'Moderate'
            Title = 'Identity Proofing | Identity Evidence'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-12(3)'
            Family = 'IA'
            Level = 'Moderate'
            Title = 'Identity Proofing | Identity Evidence Validation and Verification'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IA-12(5)'
            Family = 'IA'
            Level = 'Moderate'
            Title = 'Identity Proofing | Address Confirmation'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-1'
            Family = 'IR'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-2'
            Family = 'IR'
            Level = 'Low'
            Title = 'Incident Response Training'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-3'
            Family = 'IR'
            Level = 'Moderate'
            Title = 'Incident Response Testing'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-3(2)'
            Family = 'IR'
            Level = 'Moderate'
            Title = 'Incident Response Testing | Coordination with Related Plans'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-4'
            Family = 'IR'
            Level = 'Low'
            Title = 'Incident Handling'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-4(1)'
            Family = 'IR'
            Level = 'Moderate'
            Title = 'Incident Handling | Automated Incident Handling Processes'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-5'
            Family = 'IR'
            Level = 'Low'
            Title = 'Incident Monitoring'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-6'
            Family = 'IR'
            Level = 'Low'
            Title = 'Incident Reporting'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-6(1)'
            Family = 'IR'
            Level = 'Moderate'
            Title = 'Incident Reporting | Automated Reporting'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-6(3)'
            Family = 'IR'
            Level = 'Moderate'
            Title = 'Incident Reporting | Supply Chain Coordination'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-7'
            Family = 'IR'
            Level = 'Low'
            Title = 'Incident Response Assistance'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-7(1)'
            Family = 'IR'
            Level = 'Moderate'
            Title = 'Incident Response Assistance | Automation Support for Availability of Information and Support'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'IR-8'
            Family = 'IR'
            Level = 'Low'
            Title = 'Incident Response Plan'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MA-1'
            Family = 'MA'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MA-2'
            Family = 'MA'
            Level = 'Low'
            Title = 'Controlled Maintenance'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MA-3'
            Family = 'MA'
            Level = 'Moderate'
            Title = 'Maintenance Tools'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MA-3(1)'
            Family = 'MA'
            Level = 'Moderate'
            Title = 'Maintenance Tools | Inspect Tools'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MA-3(2)'
            Family = 'MA'
            Level = 'Moderate'
            Title = 'Maintenance Tools | Inspect Media'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MA-3(3)'
            Family = 'MA'
            Level = 'Moderate'
            Title = 'Maintenance Tools | Prevent Unauthorized Removal'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MA-4'
            Family = 'MA'
            Level = 'Low'
            Title = 'Nonlocal Maintenance'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MA-5'
            Family = 'MA'
            Level = 'Low'
            Title = 'Maintenance Personnel'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MA-6'
            Family = 'MA'
            Level = 'Moderate'
            Title = 'Timely Maintenance'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MP-1'
            Family = 'MP'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MP-2'
            Family = 'MP'
            Level = 'Low'
            Title = 'Media Access'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MP-3'
            Family = 'MP'
            Level = 'Moderate'
            Title = 'Media Marking'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MP-4'
            Family = 'MP'
            Level = 'Moderate'
            Title = 'Media Storage'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MP-5'
            Family = 'MP'
            Level = 'Moderate'
            Title = 'Media Transport'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'MP-6'
            Family = 'MP'
            Level = 'Low'
            Title = 'Media Sanitization'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'MP-7'; Family = 'MP'; Level = 'Low'; Title = 'Media Use'; Checks = @('MP-RemovableStorage') }
        @{
            Id = 'PE-1'
            Family = 'PE'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-2'
            Family = 'PE'
            Level = 'Low'
            Title = 'Physical Access Authorizations'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-3'
            Family = 'PE'
            Level = 'Low'
            Title = 'Physical Access Control'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-4'
            Family = 'PE'
            Level = 'Moderate'
            Title = 'Access Control for Transmission'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-5'
            Family = 'PE'
            Level = 'Moderate'
            Title = 'Access Control for Output Devices'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-6'
            Family = 'PE'
            Level = 'Low'
            Title = 'Monitoring Physical Access'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-6(1)'
            Family = 'PE'
            Level = 'Moderate'
            Title = 'Monitoring Physical Access | Intrusion Alarms and Surveillance Equipment'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-8'
            Family = 'PE'
            Level = 'Low'
            Title = 'Visitor Access Records'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-9'
            Family = 'PE'
            Level = 'Moderate'
            Title = 'Power Equipment and Cabling'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-10'
            Family = 'PE'
            Level = 'Moderate'
            Title = 'Emergency Shutoff'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-11'
            Family = 'PE'
            Level = 'Moderate'
            Title = 'Emergency Power'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-12'
            Family = 'PE'
            Level = 'Low'
            Title = 'Emergency Lighting'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-13'
            Family = 'PE'
            Level = 'Low'
            Title = 'Fire Protection'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-13(1)'
            Family = 'PE'
            Level = 'Moderate'
            Title = 'Fire Protection | Detection Systems - Automatic Activation and Notification'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-14'
            Family = 'PE'
            Level = 'Low'
            Title = 'Environmental Controls'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-15'
            Family = 'PE'
            Level = 'Low'
            Title = 'Water Damage Protection'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-16'
            Family = 'PE'
            Level = 'Low'
            Title = 'Delivery and Removal'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PE-17'
            Family = 'PE'
            Level = 'Moderate'
            Title = 'Alternate Work Site'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PL-1'
            Family = 'PL'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PL-2'
            Family = 'PL'
            Level = 'Low'
            Title = 'System Security and Privacy Plans'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PL-4'
            Family = 'PL'
            Level = 'Low'
            Title = 'Rules of Behavior'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PL-4(1)'
            Family = 'PL'
            Level = 'Low'
            Title = 'Rules of Behavior | Social Media and External Site/Application Usage Restrictions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PL-8'
            Family = 'PL'
            Level = 'Moderate'
            Title = 'Security and Privacy Architectures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PL-10'
            Family = 'PL'
            Level = 'Low'
            Title = 'Baseline Selection'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PL-11'
            Family = 'PL'
            Level = 'Low'
            Title = 'Baseline Tailoring'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PS-1'
            Family = 'PS'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PS-2'
            Family = 'PS'
            Level = 'Low'
            Title = 'Position Risk Designation'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PS-3'
            Family = 'PS'
            Level = 'Low'
            Title = 'Personnel Screening'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PS-4'
            Family = 'PS'
            Level = 'Low'
            Title = 'Personnel Termination'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PS-5'
            Family = 'PS'
            Level = 'Low'
            Title = 'Personnel Transfer'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PS-6'
            Family = 'PS'
            Level = 'Low'
            Title = 'Access Agreements'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PS-7'
            Family = 'PS'
            Level = 'Low'
            Title = 'External Personnel Security'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PS-8'
            Family = 'PS'
            Level = 'Low'
            Title = 'Personnel Sanctions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PS-9'
            Family = 'PS'
            Level = 'Low'
            Title = 'Position Descriptions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-1'
            Family = 'RA'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-2'
            Family = 'RA'
            Level = 'Low'
            Title = 'Security Categorization'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-3'
            Family = 'RA'
            Level = 'Low'
            Title = 'Risk Assessment'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-3(1)'
            Family = 'RA'
            Level = 'Low'
            Title = 'Risk Assessment | Supply Chain Risk Assessment'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-5'
            Family = 'RA'
            Level = 'Low'
            Title = 'Vulnerability Monitoring and Scanning'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-5(2)'
            Family = 'RA'
            Level = 'Low'
            Title = 'Vulnerability Monitoring and Scanning | Update Vulnerabilities to Be Scanned'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-5(5)'
            Family = 'RA'
            Level = 'Moderate'
            Title = 'Vulnerability Monitoring and Scanning | Privileged Access'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-5(11)'
            Family = 'RA'
            Level = 'Low'
            Title = 'Vulnerability Monitoring and Scanning | Public Disclosure Program'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-7'
            Family = 'RA'
            Level = 'Low'
            Title = 'Risk Response'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RA-9'
            Family = 'RA'
            Level = 'Moderate'
            Title = 'Criticality Analysis'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-1'
            Family = 'SA'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-2'
            Family = 'SA'
            Level = 'Low'
            Title = 'Allocation of Resources'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-3'
            Family = 'SA'
            Level = 'Low'
            Title = 'System Development Life Cycle'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-4'
            Family = 'SA'
            Level = 'Low'
            Title = 'Acquisition Process'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-4(1)'
            Family = 'SA'
            Level = 'Moderate'
            Title = 'Acquisition Process | Functional Properties of Controls'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-4(2)'
            Family = 'SA'
            Level = 'Moderate'
            Title = 'Acquisition Process | Design and Implementation Information for Controls'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-4(9)'
            Family = 'SA'
            Level = 'Moderate'
            Title = 'Acquisition Process | Functions, Ports, Protocols, and Services in Use'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-4(10)'
            Family = 'SA'
            Level = 'Low'
            Title = 'Acquisition Process | Use of Approved PIV Products'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-5'
            Family = 'SA'
            Level = 'Low'
            Title = 'System Documentation'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-8'
            Family = 'SA'
            Level = 'Low'
            Title = 'Security and Privacy Engineering Principles'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-9'
            Family = 'SA'
            Level = 'Low'
            Title = 'External System Services'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-9(2)'
            Family = 'SA'
            Level = 'Moderate'
            Title = 'External System Services | Identification of Functions, Ports, Protocols, and Services'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-10'
            Family = 'SA'
            Level = 'Moderate'
            Title = 'Developer Configuration Management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-11'
            Family = 'SA'
            Level = 'Moderate'
            Title = 'Developer Testing and Evaluation'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-15'
            Family = 'SA'
            Level = 'Moderate'
            Title = 'Development Process, Standards, and Tools'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-15(3)'
            Family = 'SA'
            Level = 'Moderate'
            Title = 'Development Process, Standards, and Tools | Criticality Analysis'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SA-22'
            Family = 'SA'
            Level = 'Low'
            Title = 'Unsupported System Components'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-1'
            Family = 'SC'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-2'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Separation of System and User Functionality'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-4'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Information in Shared System Resources'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-5'
            Family = 'SC'
            Level = 'Low'
            Title = 'Denial-of-service Protection'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'SC-7'; Family = 'SC'; Level = 'Low'; Title = 'Boundary Protection'; Checks = @('SC-FirewallEnabled') }
        @{
            Id = 'SC-7(3)'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Boundary Protection | Access Points'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-7(4)'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Boundary Protection | External Telecommunications Services'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-7(5)'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Boundary Protection | Deny by Default - Allow by Exception'
            Checks = @('SC-FirewallEnabled')
        }
        @{
            Id = 'SC-7(7)'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Boundary Protection | Split Tunneling for Remote Devices'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-7(8)'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Boundary Protection | Route Traffic to Authenticated Proxy Servers'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'SC-8'; Family = 'SC'; Level = 'Moderate'; Title = 'Transmission Confidentiality and Integrity'; Checks = @('SC-LegacyTlsDisabled') }
        @{
            Id = 'SC-8(1)'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Transmission Confidentiality and Integrity | Cryptographic Protection'
            Checks = @('SC-LegacyTlsDisabled')
        }
        @{ Id = 'SC-10'; Family = 'SC'; Level = 'Moderate'; Title = 'Network Disconnect'; Checks = @('AC-RdpIdleTimeout') }
        @{
            Id = 'SC-12'
            Family = 'SC'
            Level = 'Low'
            Title = 'Cryptographic Key Establishment and Management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'SC-13'; Family = 'SC'; Level = 'Low'; Title = 'Cryptographic Protection'; Checks = @('SC-FipsMode') }
        @{
            Id = 'SC-15'
            Family = 'SC'
            Level = 'Low'
            Title = 'Collaborative Computing Devices and Applications'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-17'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Public Key Infrastructure Certificates'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-18'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Mobile Code'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-20'
            Family = 'SC'
            Level = 'Low'
            Title = 'Secure Name/Address Resolution Service (Authoritative Source)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-21'
            Family = 'SC'
            Level = 'Low'
            Title = 'Secure Name/Address Resolution Service (Recursive or Caching Resolver)'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-22'
            Family = 'SC'
            Level = 'Low'
            Title = 'Architecture and Provisioning for Name/Address Resolution Service'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SC-23'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Session Authenticity'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'SC-28'; Family = 'SC'; Level = 'Moderate'; Title = 'Protection of Information at Rest'; Checks = @('SC-BitLocker') }
        @{
            Id = 'SC-28(1)'
            Family = 'SC'
            Level = 'Moderate'
            Title = 'Protection of Information at Rest | Cryptographic Protection'
            Checks = @('SC-BitLocker')
        }
        @{
            Id = 'SC-39'
            Family = 'SC'
            Level = 'Low'
            Title = 'Process Isolation'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-1'
            Family = 'SI'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'SI-2'; Family = 'SI'; Level = 'Low'; Title = 'Flaw Remediation'; Checks = @('SI-UpdateRecency') }
        @{
            Id = 'SI-2(2)'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'Flaw Remediation | Automated Flaw Remediation Status'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{ Id = 'SI-3'; Family = 'SI'; Level = 'Low'; Title = 'Malicious Code Protection'; Checks = @('SI-AntivirusActive', 'SI-SignatureAge', 'SI-ScanRecency') }
        @{
            Id = 'SI-4'
            Family = 'SI'
            Level = 'Low'
            Title = 'System Monitoring'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-4(2)'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'System Monitoring | Automated Tools and Mechanisms for Real-time Analysis'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-4(4)'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'System Monitoring | Inbound and Outbound Communications Traffic'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-4(5)'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'System Monitoring | System-generated Alerts'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-5'
            Family = 'SI'
            Level = 'Low'
            Title = 'Security Alerts, Advisories, and Directives'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-7'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'Software, Firmware, and Information Integrity'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-7(1)'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'Software, Firmware, and Information Integrity | Integrity Checks'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-7(7)'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'Software, Firmware, and Information Integrity | Integration of Detection and Response'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-8'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'Spam Protection'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-8(2)'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'Spam Protection | Automatic Updates'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-10'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'Information Input Validation'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-11'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'Error Handling'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-12'
            Family = 'SI'
            Level = 'Low'
            Title = 'Information Management and Retention'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SI-16'
            Family = 'SI'
            Level = 'Moderate'
            Title = 'Memory Protection'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-1'
            Family = 'SR'
            Level = 'Low'
            Title = 'Policy and Procedures'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-2'
            Family = 'SR'
            Level = 'Low'
            Title = 'Supply Chain Risk Management Plan'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-2(1)'
            Family = 'SR'
            Level = 'Low'
            Title = 'Supply Chain Risk Management Plan | Establish SCRM Team'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-3'
            Family = 'SR'
            Level = 'Low'
            Title = 'Supply Chain Controls and Processes'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-5'
            Family = 'SR'
            Level = 'Low'
            Title = 'Acquisition Strategies, Tools, and Methods'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-6'
            Family = 'SR'
            Level = 'Moderate'
            Title = 'Supplier Assessments and Reviews'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-8'
            Family = 'SR'
            Level = 'Low'
            Title = 'Notification Agreements'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-10'
            Family = 'SR'
            Level = 'Low'
            Title = 'Inspection of Systems or Components'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-11'
            Family = 'SR'
            Level = 'Low'
            Title = 'Component Authenticity'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-11(1)'
            Family = 'SR'
            Level = 'Low'
            Title = 'Component Authenticity | Anti-counterfeit Training'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-11(2)'
            Family = 'SR'
            Level = 'Low'
            Title = 'Component Authenticity | Configuration Control for Component Service and Repair'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'SR-12'
            Family = 'SR'
            Level = 'Low'
            Title = 'Component Disposal'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
    )
}
