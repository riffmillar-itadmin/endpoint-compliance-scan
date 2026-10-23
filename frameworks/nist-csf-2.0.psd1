# NIST Cybersecurity Framework 2.0: all 106 subcategories. CSF describes outcomes,
# not settings, so most are Manual and the mapped ones report endpoint evidence
# toward the outcome. Generated from NIST's OSCAL catalog,
# https://github.com/usnistgov/oscal-content (nist.gov/CSF/v2.0).
# Field meanings are in frameworks/README.md.

@{
    Id = 'NIST-CSF-2.0'
    Name = 'NIST Cybersecurity Framework 2.0'
    Source = 'https://www.nist.gov/cyberframework'
    Levels = @('CSF')
    Complete = $true
    Thresholds = @{}
    Requirements = @(
        @{
            Id = 'GV.OC-01'
            Family = 'GV.OC'
            Level = 'CSF'
            Title = 'The organizational mission is understood and informs cybersecurity risk management'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.OC-02'
            Family = 'GV.OC'
            Level = 'CSF'
            Title = 'Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.OC-03'
            Family = 'GV.OC'
            Level = 'CSF'
            Title = 'Legal, regulatory, and contractual requirements regarding cybersecurity - including privacy and civil liberties obligations - are understood and managed'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.OC-04'
            Family = 'GV.OC'
            Level = 'CSF'
            Title = 'Critical objectives, capabilities, and services that external stakeholders depend on or expect from the organization are understood and communicated'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.OC-05'
            Family = 'GV.OC'
            Level = 'CSF'
            Title = 'Outcomes, capabilities, and services that the organization depends on are understood and communicated'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.OV-01'
            Family = 'GV.OV'
            Level = 'CSF'
            Title = 'Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy and direction'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.OV-02'
            Family = 'GV.OV'
            Level = 'CSF'
            Title = 'The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements and risks'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.OV-03'
            Family = 'GV.OV'
            Level = 'CSF'
            Title = 'Organizational cybersecurity risk management performance is evaluated and reviewed for adjustments needed'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.PO-01'
            Family = 'GV.PO'
            Level = 'CSF'
            Title = 'Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.PO-02'
            Family = 'GV.PO'
            Level = 'CSF'
            Title = 'Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RM-01'
            Family = 'GV.RM'
            Level = 'CSF'
            Title = 'Risk management objectives are established and agreed to by organizational stakeholders'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RM-02'
            Family = 'GV.RM'
            Level = 'CSF'
            Title = 'Risk appetite and risk tolerance statements are established, communicated, and maintained'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RM-03'
            Family = 'GV.RM'
            Level = 'CSF'
            Title = 'Cybersecurity risk management activities and outcomes are included in enterprise risk management processes'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RM-04'
            Family = 'GV.RM'
            Level = 'CSF'
            Title = 'Strategic direction that describes appropriate risk response options is established and communicated'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RM-05'
            Family = 'GV.RM'
            Level = 'CSF'
            Title = 'Lines of communication across the organization are established for cybersecurity risks, including risks from suppliers and other third parties'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RM-06'
            Family = 'GV.RM'
            Level = 'CSF'
            Title = 'A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RM-07'
            Family = 'GV.RM'
            Level = 'CSF'
            Title = 'Strategic opportunities (i.e., positive risks) are characterized and are included in organizational cybersecurity risk discussions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RR-01'
            Family = 'GV.RR'
            Level = 'CSF'
            Title = 'Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RR-02'
            Family = 'GV.RR'
            Level = 'CSF'
            Title = 'Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RR-03'
            Family = 'GV.RR'
            Level = 'CSF'
            Title = 'Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.RR-04'
            Family = 'GV.RR'
            Level = 'CSF'
            Title = 'Cybersecurity is included in human resources practices'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-01'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-02'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated internally and externally'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-03'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-04'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'Suppliers are known and prioritized by criticality'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-05'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts and other types of agreements with suppliers and other relevant third parties'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-06'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-07'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'The risks posed by a supplier, their products and services, and other third parties are understood, recorded, prioritized, assessed, responded to, and monitored over the course of the relationship'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-08'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'Relevant suppliers and other third parties are included in incident planning, response, and recovery activities'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-09'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'Supply chain security practices are integrated into cybersecurity and enterprise risk management programs, and their performance is monitored throughout the technology product and service life cycle'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'GV.SC-10'
            Family = 'GV.SC'
            Level = 'CSF'
            Title = 'Cybersecurity supply chain risk management plans include provisions for activities that occur after the conclusion of a partnership or service agreement'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.AM-01'
            Family = 'ID.AM'
            Level = 'CSF'
            Title = 'Inventories of hardware managed by the organization are maintained'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.AM-02'
            Family = 'ID.AM'
            Level = 'CSF'
            Title = 'Inventories of software, services, and systems managed by the organization are maintained'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.AM-03'
            Family = 'ID.AM'
            Level = 'CSF'
            Title = 'Representations of the organization''s authorized network communication and internal and external network data flows are maintained'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.AM-04'
            Family = 'ID.AM'
            Level = 'CSF'
            Title = 'Inventories of services provided by suppliers are maintained'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.AM-05'
            Family = 'ID.AM'
            Level = 'CSF'
            Title = 'Assets are prioritized based on classification, criticality, resources, and impact on the mission'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.AM-07'
            Family = 'ID.AM'
            Level = 'CSF'
            Title = 'Inventories of data and corresponding metadata for designated data types are maintained'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.AM-08'
            Family = 'ID.AM'
            Level = 'CSF'
            Title = 'Systems, hardware, software, services, and data are managed throughout their life cycles'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.IM-01'
            Family = 'ID.IM'
            Level = 'CSF'
            Title = 'Improvements are identified from evaluations'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.IM-02'
            Family = 'ID.IM'
            Level = 'CSF'
            Title = 'Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.IM-03'
            Family = 'ID.IM'
            Level = 'CSF'
            Title = 'Improvements are identified from execution of operational processes, procedures, and activities'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.IM-04'
            Family = 'ID.IM'
            Level = 'CSF'
            Title = 'Incident response plans and other cybersecurity plans that affect operations are established, communicated, maintained, and improved'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-01'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'Vulnerabilities in assets are identified, validated, and recorded'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-02'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'Cyber threat intelligence is received from information sharing forums and sources'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-03'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'Internal and external threats to the organization are identified and recorded'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-04'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-05'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-06'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'Risk responses are chosen, prioritized, planned, tracked, and communicated'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-07'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'Changes and exceptions are managed, assessed for risk impact, recorded, and tracked'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-08'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'Processes for receiving, analyzing, and responding to vulnerability disclosures are established'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-09'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'The authenticity and integrity of hardware and software are assessed prior to acquisition and use'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'ID.RA-10'
            Family = 'ID.RA'
            Level = 'CSF'
            Title = 'Critical suppliers are assessed prior to acquisition'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.AA-01'
            Family = 'PR.AA'
            Level = 'CSF'
            Title = 'Identities and credentials for authorized users, services, and hardware are managed by the organization'
            Checks = @('AC-GuestDisabled', 'AC-NoPasswordNotRequired', 'IA-PasswordComplexity', 'IA-PasswordHistory', 'IA-StoredPasswordProtection')
        }
        @{
            Id = 'PR.AA-02'
            Family = 'PR.AA'
            Level = 'CSF'
            Title = 'Identities are proofed and bound to credentials based on the context of interactions'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.AA-03'
            Family = 'PR.AA'
            Level = 'CSF'
            Title = 'Users, services, and hardware are authenticated'
            Checks = @('IA-NtlmV2Only', 'AC-AccountLockout', 'IA-BlankPasswordConsoleOnly')
        }
        @{
            Id = 'PR.AA-04'
            Family = 'PR.AA'
            Level = 'CSF'
            Title = 'Identity assertions are protected, conveyed, and verified'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.AA-05'
            Family = 'PR.AA'
            Level = 'CSF'
            Title = 'Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties'
            Checks = @('AC-LocalAdminCount', 'AC-UacEnabled', 'AC-UacPromptBehavior')
        }
        @{
            Id = 'PR.AA-06'
            Family = 'PR.AA'
            Level = 'CSF'
            Title = 'Physical access to assets is managed, monitored, and enforced commensurate with risk'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.AT-01'
            Family = 'PR.AT'
            Level = 'CSF'
            Title = 'Personnel are provided with awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.AT-02'
            Family = 'PR.AT'
            Level = 'CSF'
            Title = 'Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.DS-01'
            Family = 'PR.DS'
            Level = 'CSF'
            Title = 'The confidentiality, integrity, and availability of data-at-rest are protected'
            Checks = @('SC-BitLocker')
        }
        @{
            Id = 'PR.DS-02'
            Family = 'PR.DS'
            Level = 'CSF'
            Title = 'The confidentiality, integrity, and availability of data-in-transit are protected'
            Checks = @('SC-LegacyTlsDisabled', 'AC-RdpProtected')
        }
        @{
            Id = 'PR.DS-10'
            Family = 'PR.DS'
            Level = 'CSF'
            Title = 'The confidentiality, integrity, and availability of data-in-use are protected'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.DS-11'
            Family = 'PR.DS'
            Level = 'CSF'
            Title = 'Backups of data are created, protected, maintained, and tested'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.IR-01'
            Family = 'PR.IR'
            Level = 'CSF'
            Title = 'Networks and environments are protected from unauthorized logical access and usage'
            Checks = @('SC-FirewallEnabled')
        }
        @{
            Id = 'PR.IR-02'
            Family = 'PR.IR'
            Level = 'CSF'
            Title = 'The organization''s technology assets are protected from environmental threats'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.IR-03'
            Family = 'PR.IR'
            Level = 'CSF'
            Title = 'Mechanisms are implemented to achieve resilience requirements in normal and adverse situations'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.IR-04'
            Family = 'PR.IR'
            Level = 'CSF'
            Title = 'Adequate resource capacity to ensure availability is maintained'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.PS-01'
            Family = 'PR.PS'
            Level = 'CSF'
            Title = 'Configuration management practices are established and applied'
            Checks = @('CM-Smb1Disabled', 'CM-NonessentialServices', 'CM-AutoplayDisabled', 'AC-InactivityLock', 'AC-LogonBanner', 'MP-RemovableStorage')
        }
        @{
            Id = 'PR.PS-02'
            Family = 'PR.PS'
            Level = 'CSF'
            Title = 'Software is maintained, replaced, and removed commensurate with risk'
            Checks = @('SI-UpdateRecency')
        }
        @{
            Id = 'PR.PS-03'
            Family = 'PR.PS'
            Level = 'CSF'
            Title = 'Hardware is maintained, replaced, and removed commensurate with risk'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'PR.PS-04'
            Family = 'PR.PS'
            Level = 'CSF'
            Title = 'Log records are generated and made available for continuous monitoring'
            Checks = @('AU-AuditPolicy', 'AU-SecurityLogSize', 'AU-TimeSync')
        }
        @{
            Id = 'PR.PS-05'
            Family = 'PR.PS'
            Level = 'CSF'
            Title = 'Installation and execution of unauthorized software are prevented'
            Checks = @('CM-AlwaysInstallElevated')
        }
        @{
            Id = 'PR.PS-06'
            Family = 'PR.PS'
            Level = 'CSF'
            Title = 'Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.AE-02'
            Family = 'DE.AE'
            Level = 'CSF'
            Title = 'Potentially adverse events are analyzed to better understand associated activities'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.AE-03'
            Family = 'DE.AE'
            Level = 'CSF'
            Title = 'Information is correlated from multiple sources'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.AE-04'
            Family = 'DE.AE'
            Level = 'CSF'
            Title = 'The estimated impact and scope of adverse events are understood'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.AE-06'
            Family = 'DE.AE'
            Level = 'CSF'
            Title = 'Information on adverse events is provided to authorized staff and tools'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.AE-07'
            Family = 'DE.AE'
            Level = 'CSF'
            Title = 'Cyber threat intelligence and other contextual information are integrated into the analysis'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.AE-08'
            Family = 'DE.AE'
            Level = 'CSF'
            Title = 'Incidents are declared when adverse events meet the defined incident criteria'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.CM-01'
            Family = 'DE.CM'
            Level = 'CSF'
            Title = 'Networks and network services are monitored to find potentially adverse events'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.CM-02'
            Family = 'DE.CM'
            Level = 'CSF'
            Title = 'The physical environment is monitored to find potentially adverse events'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.CM-03'
            Family = 'DE.CM'
            Level = 'CSF'
            Title = 'Personnel activity and technology usage are monitored to find potentially adverse events'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.CM-06'
            Family = 'DE.CM'
            Level = 'CSF'
            Title = 'External service provider activities and services are monitored to find potentially adverse events'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'DE.CM-09'
            Family = 'DE.CM'
            Level = 'CSF'
            Title = 'Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events'
            Checks = @('SI-AntivirusActive', 'SI-SignatureAge', 'SI-ScanRecency')
        }
        @{
            Id = 'RS.AN-03'
            Family = 'RS.AN'
            Level = 'CSF'
            Title = 'Analysis is performed to establish what has taken place during an incident and the root cause of the incident'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.AN-06'
            Family = 'RS.AN'
            Level = 'CSF'
            Title = 'Actions performed during an investigation are recorded, and the records'' integrity and provenance are preserved'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.AN-07'
            Family = 'RS.AN'
            Level = 'CSF'
            Title = 'Incident data and metadata are collected, and their integrity and provenance are preserved'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.AN-08'
            Family = 'RS.AN'
            Level = 'CSF'
            Title = 'An incident''s magnitude is estimated and validated'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.CO-02'
            Family = 'RS.CO'
            Level = 'CSF'
            Title = 'Internal and external stakeholders are notified of incidents'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.CO-03'
            Family = 'RS.CO'
            Level = 'CSF'
            Title = 'Information is shared with designated internal and external stakeholders'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.MA-01'
            Family = 'RS.MA'
            Level = 'CSF'
            Title = 'The incident response plan is executed in coordination with relevant third parties once an incident is declared'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.MA-02'
            Family = 'RS.MA'
            Level = 'CSF'
            Title = 'Incident reports are triaged and validated'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.MA-03'
            Family = 'RS.MA'
            Level = 'CSF'
            Title = 'Incidents are categorized and prioritized'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.MA-04'
            Family = 'RS.MA'
            Level = 'CSF'
            Title = 'Incidents are escalated or elevated as needed'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.MA-05'
            Family = 'RS.MA'
            Level = 'CSF'
            Title = 'The criteria for initiating incident recovery are applied'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.MI-01'
            Family = 'RS.MI'
            Level = 'CSF'
            Title = 'Incidents are contained'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RS.MI-02'
            Family = 'RS.MI'
            Level = 'CSF'
            Title = 'Incidents are eradicated'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RC.CO-03'
            Family = 'RC.CO'
            Level = 'CSF'
            Title = 'Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RC.CO-04'
            Family = 'RC.CO'
            Level = 'CSF'
            Title = 'Public updates on incident recovery are shared using approved methods and messaging'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RC.RP-01'
            Family = 'RC.RP'
            Level = 'CSF'
            Title = 'The recovery portion of the incident response plan is executed once initiated from the incident response process'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RC.RP-02'
            Family = 'RC.RP'
            Level = 'CSF'
            Title = 'Recovery actions are selected, scoped, prioritized, and performed'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RC.RP-03'
            Family = 'RC.RP'
            Level = 'CSF'
            Title = 'The integrity of backups and other restoration assets is verified before using them for restoration'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RC.RP-04'
            Family = 'RC.RP'
            Level = 'CSF'
            Title = 'Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RC.RP-05'
            Family = 'RC.RP'
            Level = 'CSF'
            Title = 'The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
        @{
            Id = 'RC.RP-06'
            Family = 'RC.RP'
            Level = 'CSF'
            Title = 'The end of incident recovery is declared based on criteria, and incident-related documentation is completed'
            Checks = @()
            Note = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
        }
    )
}
