# CMMC Level 1 and Level 2: NIST SP 800-171 Rev 2, the revision the CMMC program
# rule (32 CFR 170) assesses Level 2 against. All 110 requirements. L1 is the 17
# requirements that carry the FAR 52.204-21 safeguards; every other entry is L2
# only, and L2 includes L1.
#
# Reports show each requirement as a CMMC practice ID built from PracticeFormat,
# for example AC.L1-3.1.1 or AC.L2-3.1.8.
# Field meanings are in frameworks/README.md.

@{
    Id = 'CMMC'
    Name = 'CMMC Level 1/2 (NIST SP 800-171 Rev 2)'
    Source = 'https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final'
    Levels = @('L1', 'L2')
    Complete = $true
    PracticeFormat = '{Family}.{Level}-{Id}'
    Thresholds = @{}
    Requirements = @(
        # ---- Access Control (AC) ----
        @{ Id = '3.1.1';  Family = 'AC'; Level = 'L1'; Title = 'Limit system access to authorized users, processes and devices'
           Checks = @('AC-GuestDisabled', 'AC-NoPasswordNotRequired')
           Note = 'Endpoint shows local accounts only; domain accounts and the list of authorized users are reviewed separately.' }
        @{ Id = '3.1.2';  Family = 'AC'; Level = 'L1'; Title = 'Limit system access to permitted transactions and functions'
           Checks = @('AC-UacEnabled')
           Note = 'Role definitions and rights assignments are reviewed in the access control policy.' }
        @{ Id = '3.1.3';  Family = 'AC'; Level = 'L2'; Title = 'Control the flow of CUI per approved authorizations'
           Checks = @(); Note = 'Data flow controls (DLP, proxies, network segmentation) and flow diagrams.' }
        @{ Id = '3.1.4';  Family = 'AC'; Level = 'L2'; Title = 'Separate the duties of individuals'
           Checks = @(); Note = 'Documented separation of duties and the role assignments that enforce it.' }
        @{ Id = '3.1.5';  Family = 'AC'; Level = 'L2'; Title = 'Employ least privilege'
           Checks = @('AC-LocalAdminCount')
           Note = 'Shows local Administrators membership only; privileged account inventory is reviewed separately.' }
        @{ Id = '3.1.6';  Family = 'AC'; Level = 'L2'; Title = 'Use non-privileged accounts for nonsecurity functions'
           Checks = @(); Note = 'Separate admin and daily-use accounts, shown in the account inventory and procedures.' }
        @{ Id = '3.1.7';  Family = 'AC'; Level = 'L2'; Title = 'Prevent non-privileged users from executing privileged functions; audit their use'
           Checks = @('AC-UacEnabled', 'AC-UacSecureDesktop', 'AC-UacPromptBehavior', 'AU-SensitivePrivilegeUse') }
        @{ Id = '3.1.8';  Family = 'AC'; Level = 'L2'; Title = 'Limit unsuccessful logon attempts'
           Checks = @('AC-AccountLockout') }
        @{ Id = '3.1.9';  Family = 'AC'; Level = 'L2'; Title = 'Provide privacy and security notices'
           Checks = @('AC-LogonBanner')
           Note = 'Checks that a banner is set, not that its wording meets the applicable CUI rules.' }
        @{ Id = '3.1.10'; Family = 'AC'; Level = 'L2'; Title = 'Use session lock with pattern-hiding displays after inactivity'
           Checks = @('AC-InactivityLock') }
        @{ Id = '3.1.11'; Family = 'AC'; Level = 'L2'; Title = 'Terminate user sessions after a defined condition'
           Checks = @('AC-RdpIdleTimeout')
           Note = 'Covers Remote Desktop sessions; other session types are reviewed separately.' }
        @{ Id = '3.1.12'; Family = 'AC'; Level = 'L2'; Title = 'Monitor and control remote access sessions'
           Checks = @('AC-RdpProtected')
           Note = 'Remote access monitoring (VPN and gateway logs) is reviewed separately.' }
        @{ Id = '3.1.13'; Family = 'AC'; Level = 'L2'; Title = 'Use cryptography to protect remote access sessions'
           Checks = @('AC-RdpProtected') }
        @{ Id = '3.1.14'; Family = 'AC'; Level = 'L2'; Title = 'Route remote access via managed access control points'
           Checks = @(); Note = 'VPN or gateway architecture and firewall rules.' }
        @{ Id = '3.1.15'; Family = 'AC'; Level = 'L2'; Title = 'Authorize remote execution of privileged commands'
           Checks = @(); Note = 'Remote administration policy and the authorizations granted under it.' }
        @{ Id = '3.1.16'; Family = 'AC'; Level = 'L2'; Title = 'Authorize wireless access before allowing connections'
           Checks = @(); Note = 'Wireless access policy and wireless infrastructure configuration.' }
        @{ Id = '3.1.17'; Family = 'AC'; Level = 'L2'; Title = 'Protect wireless access with authentication and encryption'
           Checks = @(); Note = 'Wireless infrastructure configuration (WPA2/WPA3-Enterprise).' }
        @{ Id = '3.1.18'; Family = 'AC'; Level = 'L2'; Title = 'Control connection of mobile devices'
           Checks = @(); Note = 'Mobile device management enrollment and policy.' }
        @{ Id = '3.1.19'; Family = 'AC'; Level = 'L2'; Title = 'Encrypt CUI on mobile devices'
           Checks = @(); Note = 'Mobile device management encryption policy and compliance reports.' }
        @{ Id = '3.1.20'; Family = 'AC'; Level = 'L1'; Title = 'Verify and control connections to external systems'
           Checks = @(); Note = 'Policy on external systems and the agreements or technical controls that enforce it.' }
        @{ Id = '3.1.21'; Family = 'AC'; Level = 'L2'; Title = 'Limit use of portable storage on external systems'
           Checks = @(); Note = 'Policy and training on using organizational portable storage elsewhere.' }
        @{ Id = '3.1.22'; Family = 'AC'; Level = 'L1'; Title = 'Control CUI posted on publicly accessible systems'
           Checks = @(); Note = 'Review process and authorized posters for public websites and repositories.' }

        # ---- Awareness and Training (AT) ----
        @{ Id = '3.2.1';  Family = 'AT'; Level = 'L2'; Title = 'Make users aware of security risks and applicable policies'
           Checks = @(); Note = 'Awareness training content and completion records.' }
        @{ Id = '3.2.2';  Family = 'AT'; Level = 'L2'; Title = 'Train personnel for their security duties'
           Checks = @(); Note = 'Role-based training content and completion records.' }
        @{ Id = '3.2.3';  Family = 'AT'; Level = 'L2'; Title = 'Train on recognizing and reporting insider threat'
           Checks = @(); Note = 'Insider threat training content and completion records.' }

        # ---- Audit and Accountability (AU) ----
        @{ Id = '3.3.1';  Family = 'AU'; Level = 'L2'; Title = 'Create and retain audit logs'
           Checks = @('AU-AuditPolicy', 'AU-SecurityLogSize')
           Note = 'Retention beyond the local log (forwarding, SIEM) is reviewed separately.' }
        @{ Id = '3.3.2';  Family = 'AU'; Level = 'L2'; Title = 'Trace actions to individual users'
           Checks = @('AU-AuditPolicy')
           Note = 'Shared and generic account use is reviewed in the account inventory.' }
        @{ Id = '3.3.3';  Family = 'AU'; Level = 'L2'; Title = 'Review and update logged events'
           Checks = @(); Note = 'Record of periodic reviews of the audit policy.' }
        @{ Id = '3.3.4';  Family = 'AU'; Level = 'L2'; Title = 'Alert on audit logging process failure'
           Checks = @(); Note = 'SIEM or monitoring alert for log collection failures.' }
        @{ Id = '3.3.5';  Family = 'AU'; Level = 'L2'; Title = 'Correlate audit review, analysis and reporting'
           Checks = @(); Note = 'Central log correlation (SIEM) and review procedures.' }
        @{ Id = '3.3.6';  Family = 'AU'; Level = 'L2'; Title = 'Provide audit record reduction and report generation'
           Checks = @(); Note = 'SIEM or log tool reporting capability.' }
        @{ Id = '3.3.7';  Family = 'AU'; Level = 'L2'; Title = 'Synchronize system clocks with an authoritative source'
           Checks = @('AU-TimeSync') }
        @{ Id = '3.3.8';  Family = 'AU'; Level = 'L2'; Title = 'Protect audit information and tools'
           Checks = @(); Note = 'Log permissions and central log store access controls.' }
        @{ Id = '3.3.9';  Family = 'AU'; Level = 'L2'; Title = 'Limit audit logging management to a subset of privileged users'
           Checks = @(); Note = 'Membership of groups holding the Manage auditing and security log right.' }

        # ---- Configuration Management (CM) ----
        @{ Id = '3.4.1';  Family = 'CM'; Level = 'L2'; Title = 'Establish baseline configurations and inventories'
           Checks = @(); Note = 'Documented baselines and the hardware and software inventory.' }
        @{ Id = '3.4.2';  Family = 'CM'; Level = 'L2'; Title = 'Establish and enforce security configuration settings'
           Checks = @(); Note = 'Configuration standard and the GPO or MDM policies that enforce it. This scan is supporting evidence.' }
        @{ Id = '3.4.3';  Family = 'CM'; Level = 'L2'; Title = 'Track, approve and log changes'
           Checks = @(); Note = 'Change management records.' }
        @{ Id = '3.4.4';  Family = 'CM'; Level = 'L2'; Title = 'Analyze the security impact of changes'
           Checks = @(); Note = 'Security impact analysis in change records.' }
        @{ Id = '3.4.5';  Family = 'CM'; Level = 'L2'; Title = 'Enforce access restrictions for changes'
           Checks = @(); Note = 'Who can change systems, and how that is enforced.' }
        @{ Id = '3.4.6';  Family = 'CM'; Level = 'L2'; Title = 'Employ least functionality'
           Checks = @('CM-Smb1Disabled', 'CM-NonessentialServices', 'CM-AutoplayDisabled') }
        @{ Id = '3.4.7';  Family = 'CM'; Level = 'L2'; Title = 'Restrict nonessential programs, ports, protocols and services'
           Checks = @('CM-Smb1Disabled', 'CM-NonessentialServices')
           Note = 'Checks a fixed list of services; the full list of essential services is in the baseline.' }
        @{ Id = '3.4.8';  Family = 'CM'; Level = 'L2'; Title = 'Apply deny-by-exception or permit-by-exception to software'
           Checks = @(); Note = 'Application control policy (AppLocker, WDAC or a third-party product).' }
        @{ Id = '3.4.9';  Family = 'CM'; Level = 'L2'; Title = 'Control and monitor user-installed software'
           Checks = @('CM-AlwaysInstallElevated')
           Note = 'Software installation policy and monitoring are reviewed separately.' }

        # ---- Identification and Authentication (IA) ----
        @{ Id = '3.5.1';  Family = 'IA'; Level = 'L1'; Title = 'Identify users, processes and devices'
           Checks = @(); Note = 'Account inventory showing unique identifiers for users and devices.' }
        @{ Id = '3.5.2';  Family = 'IA'; Level = 'L1'; Title = 'Authenticate users, processes and devices before access'
           Checks = @('AC-NoPasswordNotRequired', 'IA-BlankPasswordConsoleOnly')
           Note = 'Device and service authentication are reviewed separately.' }
        @{ Id = '3.5.3';  Family = 'IA'; Level = 'L2'; Title = 'Use multifactor authentication'
           Checks = @(); Note = 'MFA configuration for privileged and network access (identity provider, VPN).' }
        @{ Id = '3.5.4';  Family = 'IA'; Level = 'L2'; Title = 'Use replay-resistant authentication'
           Checks = @('IA-NtlmV2Only') }
        @{ Id = '3.5.5';  Family = 'IA'; Level = 'L2'; Title = 'Prevent reuse of identifiers'
           Checks = @(); Note = 'Account provisioning procedure.' }
        @{ Id = '3.5.6';  Family = 'IA'; Level = 'L2'; Title = 'Disable identifiers after inactivity'
           Checks = @(); Note = 'Inactive account review or automation in the directory.' }
        @{ Id = '3.5.7';  Family = 'IA'; Level = 'L2'; Title = 'Enforce password complexity'
           Checks = @('IA-PasswordComplexity') }
        @{ Id = '3.5.8';  Family = 'IA'; Level = 'L2'; Title = 'Prohibit password reuse'
           Checks = @('IA-PasswordHistory') }
        @{ Id = '3.5.9';  Family = 'IA'; Level = 'L2'; Title = 'Require temporary passwords to be changed at first logon'
           Checks = @(); Note = 'Account provisioning procedure (user must change password at next logon).' }
        @{ Id = '3.5.10'; Family = 'IA'; Level = 'L2'; Title = 'Store and transmit only protected passwords'
           Checks = @('IA-StoredPasswordProtection', 'IA-NtlmV2Only') }
        @{ Id = '3.5.11'; Family = 'IA'; Level = 'L2'; Title = 'Obscure feedback of authentication information'
           Checks = @(); Note = 'Windows masks password entry by default; confirm for other applications.' }

        # ---- Incident Response (IR) ----
        @{ Id = '3.6.1';  Family = 'IR'; Level = 'L2'; Title = 'Establish an incident-handling capability'
           Checks = @(); Note = 'Incident response plan.' }
        @{ Id = '3.6.2';  Family = 'IR'; Level = 'L2'; Title = 'Track, document and report incidents'
           Checks = @(); Note = 'Incident records and reporting procedure.' }
        @{ Id = '3.6.3';  Family = 'IR'; Level = 'L2'; Title = 'Test the incident response capability'
           Checks = @(); Note = 'Records of incident response exercises.' }

        # ---- Maintenance (MA) ----
        @{ Id = '3.7.1';  Family = 'MA'; Level = 'L2'; Title = 'Perform maintenance'
           Checks = @(); Note = 'Maintenance records.' }
        @{ Id = '3.7.2';  Family = 'MA'; Level = 'L2'; Title = 'Control maintenance tools, techniques and personnel'
           Checks = @(); Note = 'Approved maintenance tools and personnel.' }
        @{ Id = '3.7.3';  Family = 'MA'; Level = 'L2'; Title = 'Sanitize equipment removed for off-site maintenance'
           Checks = @(); Note = 'Sanitization records for equipment sent out.' }
        @{ Id = '3.7.4';  Family = 'MA'; Level = 'L2'; Title = 'Check diagnostic media for malicious code'
           Checks = @(); Note = 'Procedure for scanning maintenance media.' }
        @{ Id = '3.7.5';  Family = 'MA'; Level = 'L2'; Title = 'Require MFA for nonlocal maintenance'
           Checks = @(); Note = 'Remote support tool configuration and MFA.' }
        @{ Id = '3.7.6';  Family = 'MA'; Level = 'L2'; Title = 'Supervise maintenance personnel without access'
           Checks = @(); Note = 'Escort and supervision procedure.' }

        # ---- Media Protection (MP) ----
        @{ Id = '3.8.1';  Family = 'MP'; Level = 'L2'; Title = 'Protect system media containing CUI'
           Checks = @(); Note = 'Physical storage controls for media.' }
        @{ Id = '3.8.2';  Family = 'MP'; Level = 'L2'; Title = 'Limit access to CUI on media'
           Checks = @(); Note = 'Media access controls.' }
        @{ Id = '3.8.3';  Family = 'MP'; Level = 'L1'; Title = 'Sanitize or destroy media before disposal or reuse'
           Checks = @(); Note = 'Sanitization procedure and destruction records.' }
        @{ Id = '3.8.4';  Family = 'MP'; Level = 'L2'; Title = 'Mark media with CUI markings'
           Checks = @(); Note = 'Marking procedure and samples.' }
        @{ Id = '3.8.5';  Family = 'MP'; Level = 'L2'; Title = 'Control media during transport'
           Checks = @(); Note = 'Transport procedure and custody records.' }
        @{ Id = '3.8.6';  Family = 'MP'; Level = 'L2'; Title = 'Encrypt CUI on digital media during transport'
           Checks = @(); Note = 'Encryption of portable media (BitLocker To Go or equivalent).' }
        @{ Id = '3.8.7';  Family = 'MP'; Level = 'L2'; Title = 'Control removable media'
           Checks = @('MP-RemovableStorage', 'CM-AutoplayDisabled') }
        @{ Id = '3.8.8';  Family = 'MP'; Level = 'L2'; Title = 'Prohibit portable storage with no identifiable owner'
           Checks = @(); Note = 'Policy and device control allow-list.' }
        @{ Id = '3.8.9';  Family = 'MP'; Level = 'L2'; Title = 'Protect backup CUI at storage locations'
           Checks = @(); Note = 'Backup encryption and storage location controls.' }

        # ---- Personnel Security (PS) ----
        @{ Id = '3.9.1';  Family = 'PS'; Level = 'L2'; Title = 'Screen individuals before granting access'
           Checks = @(); Note = 'Screening records.' }
        @{ Id = '3.9.2';  Family = 'PS'; Level = 'L2'; Title = 'Protect systems during personnel actions'
           Checks = @(); Note = 'Termination and transfer procedure and records.' }

        # ---- Physical Protection (PE) ----
        @{ Id = '3.10.1'; Family = 'PE'; Level = 'L1'; Title = 'Limit physical access to authorized individuals'
           Checks = @(); Note = 'Facility access controls and authorized access list.' }
        @{ Id = '3.10.2'; Family = 'PE'; Level = 'L2'; Title = 'Protect and monitor the physical facility'
           Checks = @(); Note = 'Facility monitoring (cameras, alarms) and support infrastructure.' }
        @{ Id = '3.10.3'; Family = 'PE'; Level = 'L1'; Title = 'Escort and monitor visitors'
           Checks = @(); Note = 'Visitor procedure and logs.' }
        @{ Id = '3.10.4'; Family = 'PE'; Level = 'L1'; Title = 'Keep audit logs of physical access'
           Checks = @(); Note = 'Physical access logs.' }
        @{ Id = '3.10.5'; Family = 'PE'; Level = 'L1'; Title = 'Control and manage physical access devices'
           Checks = @(); Note = 'Key and badge inventory.' }
        @{ Id = '3.10.6'; Family = 'PE'; Level = 'L2'; Title = 'Safeguard CUI at alternate work sites'
           Checks = @(); Note = 'Telework policy and agreements.' }

        # ---- Risk Assessment (RA) ----
        @{ Id = '3.11.1'; Family = 'RA'; Level = 'L2'; Title = 'Periodically assess risk'
           Checks = @(); Note = 'Risk assessment.' }
        @{ Id = '3.11.2'; Family = 'RA'; Level = 'L2'; Title = 'Scan for vulnerabilities periodically'
           Checks = @(); Note = 'Vulnerability scanner schedule and reports.' }
        @{ Id = '3.11.3'; Family = 'RA'; Level = 'L2'; Title = 'Remediate vulnerabilities per risk assessments'
           Checks = @(); Note = 'Remediation tracking against scan results.' }

        # ---- Security Assessment (CA) ----
        @{ Id = '3.12.1'; Family = 'CA'; Level = 'L2'; Title = 'Periodically assess security controls'
           Checks = @(); Note = 'Control assessment records. This scan can be part of that evidence.' }
        @{ Id = '3.12.2'; Family = 'CA'; Level = 'L2'; Title = 'Develop and implement plans of action'
           Checks = @(); Note = 'Plan of action and milestones (POA&M).' }
        @{ Id = '3.12.3'; Family = 'CA'; Level = 'L2'; Title = 'Monitor security controls on an ongoing basis'
           Checks = @(); Note = 'Continuous monitoring procedure and records.' }
        @{ Id = '3.12.4'; Family = 'CA'; Level = 'L2'; Title = 'Develop and maintain system security plans'
           Checks = @(); Note = 'System security plan (SSP).' }

        # ---- System and Communications Protection (SC) ----
        @{ Id = '3.13.1'; Family = 'SC'; Level = 'L1'; Title = 'Monitor, control and protect communications at boundaries'
           Checks = @('SC-FirewallEnabled')
           Note = 'Covers the host firewall; network boundary devices are reviewed separately.' }
        @{ Id = '3.13.2'; Family = 'SC'; Level = 'L2'; Title = 'Use architectures and engineering that promote security'
           Checks = @(); Note = 'Architecture documentation.' }
        @{ Id = '3.13.3'; Family = 'SC'; Level = 'L2'; Title = 'Separate user functionality from system management'
           Checks = @(); Note = 'Separate admin interfaces and accounts.' }
        @{ Id = '3.13.4'; Family = 'SC'; Level = 'L2'; Title = 'Prevent unintended transfer via shared resources'
           Checks = @(); Note = 'Shared resource configuration.' }
        @{ Id = '3.13.5'; Family = 'SC'; Level = 'L1'; Title = 'Separate publicly accessible subnetworks'
           Checks = @(); Note = 'Network diagram showing a DMZ or separated public systems.' }
        @{ Id = '3.13.6'; Family = 'SC'; Level = 'L2'; Title = 'Deny network traffic by default, allow by exception'
           Checks = @('SC-FirewallEnabled')
           Note = 'Covers inbound host traffic; outbound and network rules are reviewed separately.' }
        @{ Id = '3.13.7'; Family = 'SC'; Level = 'L2'; Title = 'Prevent split tunneling'
           Checks = @(); Note = 'VPN client configuration.' }
        @{ Id = '3.13.8'; Family = 'SC'; Level = 'L2'; Title = 'Use cryptography to protect CUI in transit'
           Checks = @('SC-LegacyTlsDisabled') }
        @{ Id = '3.13.9'; Family = 'SC'; Level = 'L2'; Title = 'Terminate network connections after inactivity'
           Checks = @('AC-RdpIdleTimeout') }
        @{ Id = '3.13.10'; Family = 'SC'; Level = 'L2'; Title = 'Establish and manage cryptographic keys'
           Checks = @(); Note = 'Key management procedure (BitLocker recovery key escrow, PKI).' }
        @{ Id = '3.13.11'; Family = 'SC'; Level = 'L2'; Title = 'Use FIPS-validated cryptography to protect CUI'
           Checks = @('SC-FipsMode') }
        @{ Id = '3.13.12'; Family = 'SC'; Level = 'L2'; Title = 'Prohibit remote activation of collaborative devices'
           Checks = @(); Note = 'Camera and microphone policy for conferencing devices.' }
        @{ Id = '3.13.13'; Family = 'SC'; Level = 'L2'; Title = 'Control and monitor mobile code'
           Checks = @(); Note = 'Browser and script policy.' }
        @{ Id = '3.13.14'; Family = 'SC'; Level = 'L2'; Title = 'Control and monitor VoIP'
           Checks = @(); Note = 'VoIP system configuration.' }
        @{ Id = '3.13.15'; Family = 'SC'; Level = 'L2'; Title = 'Protect the authenticity of communications sessions'
           Checks = @(); Note = 'TLS and session protection on systems handling CUI.' }
        @{ Id = '3.13.16'; Family = 'SC'; Level = 'L2'; Title = 'Protect the confidentiality of CUI at rest'
           Checks = @('SC-BitLocker')
           Note = 'Covers the operating system volume only.' }

        # ---- System and Information Integrity (SI) ----
        @{ Id = '3.14.1'; Family = 'SI'; Level = 'L1'; Title = 'Identify, report and correct flaws in a timely manner'
           Checks = @('SI-UpdateRecency')
           Note = 'Covers Windows updates; third-party software patching is reviewed separately.' }
        @{ Id = '3.14.2'; Family = 'SI'; Level = 'L1'; Title = 'Provide protection from malicious code'
           Checks = @('SI-AntivirusActive') }
        @{ Id = '3.14.3'; Family = 'SI'; Level = 'L2'; Title = 'Monitor security alerts and advisories'
           Checks = @(); Note = 'Subscription to advisories and records of action taken.' }
        @{ Id = '3.14.4'; Family = 'SI'; Level = 'L1'; Title = 'Update malicious code protection'
           Checks = @('SI-SignatureAge') }
        @{ Id = '3.14.5'; Family = 'SI'; Level = 'L1'; Title = 'Perform periodic and real-time scans'
           Checks = @('SI-ScanRecency', 'SI-AntivirusActive') }
        @{ Id = '3.14.6'; Family = 'SI'; Level = 'L2'; Title = 'Monitor systems and traffic to detect attacks'
           Checks = @(); Note = 'EDR, IDS or SIEM monitoring.' }
        @{ Id = '3.14.7'; Family = 'SI'; Level = 'L2'; Title = 'Identify unauthorized use of systems'
           Checks = @(); Note = 'Monitoring and review procedures for unauthorized use.' }
    )
}
