# endpoint-compliance-scan

A read-only PowerShell scanner that checks a Windows workstation or server
against one compliance framework, chosen at run time, and reports a result with
evidence for each requirement.

| Framework | `-Framework` | Levels | Requirements | With endpoint evidence |
| --- | --- | --- | --- | --- |
| CMMC Level 1/2 ([NIST SP 800-171 Rev 2](https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final)) | `CMMC` | L1, L2 | 110 | 32 |
| [NIST SP 800-171 Rev 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final) | `NIST-800-171r3` | Rev3 | 97 | 24 |
| [NIST SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), Low and Moderate baselines | `NIST-800-53r5` | Low, Moderate | 287 | 32 |
| [DISA Windows 11 STIG](https://public.cyber.mil/stigs/) V2R11 | `DISA-STIG-Win11` | CAT I, CAT II, CAT III | 276 | 220 |
| DISA Windows Server 2019 STIG V3R8 (sunset by DISA), member server | `DISA-STIG-WS2019-MS` | CAT I, CAT II, CAT III | 247 | 188 |
| DISA Windows Server 2019 STIG V3R8 (sunset by DISA), domain controller | `DISA-STIG-WS2019-DC` | CAT I, CAT II, CAT III | 277 | 195 |
| DISA Windows Server 2022 STIG V2R11, member server | `DISA-STIG-WS2022-MS` | CAT I, CAT II, CAT III | 242 | 187 |
| DISA Windows Server 2022 STIG V2R11, domain controller | `DISA-STIG-WS2022-DC` | CAT I, CAT II, CAT III | 271 | 193 |
| DISA Windows Server 2025 STIG V1R4, member server | `DISA-STIG-WS2025-MS` | CAT I, CAT II, CAT III | 258 | 181 |
| DISA Windows Server 2025 STIG V1R4, domain controller | `DISA-STIG-WS2025-DC` | CAT I, CAT II, CAT III | 288 | 190 |
| [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1), endpoint safeguards | `CIS-v8.1` | IG1, IG2 | 18 (partial) | 18 |
| [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) | `NIST-CSF-2.0` | CSF | 106 | 11 |
| [PCI DSS v4.0.1](https://www.pcisecuritystandards.org/document_library/), endpoint requirements | `PCI-DSS-4.0.1` | PCI | 22 (partial) | 22 |
| [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/), endpoint safeguards | `HIPAA` | HIPAA | 17 (partial) | 14 |

It is evidence for an assessment, not a verdict. Most requirements in most
frameworks are procedural, or need evidence from outside the endpoint (identity
provider, network, facility, records). The report marks those Manual and says
what an assessor would look at instead. It never states that a machine is
compliant and never computes a score.

The CIS, PCI DSS and HIPAA catalogs are partial: they list only the requirements
an endpoint can show evidence for, with titles written for this project. The
standards themselves have the authoritative text, and every report from a
partial catalog says it is a subset. [frameworks/README.md](frameworks/README.md)
has the sources and the catalog format.

Runs on Windows PowerShell 5.1 and PowerShell 7. No modules to install.

## Choosing a STIG

DISA writes a separate STIG for each Windows release, and for Windows Server a
separate one for domain controllers. Pick the one that matches the machine:

| Machine | `-Framework` |
| --- | --- |
| Windows 11 | `DISA-STIG-Win11` |
| Windows Server 2019, 2022 or 2025, member or standalone server | `DISA-STIG-WS2019-MS`, `DISA-STIG-WS2022-MS`, `DISA-STIG-WS2025-MS` |
| Windows Server 2019, 2022 or 2025, domain controller | `DISA-STIG-WS2019-DC`, `DISA-STIG-WS2022-DC`, `DISA-STIG-WS2025-DC` |

`winver` or `(Get-CimInstance Win32_OperatingSystem).Caption` shows the release.
Each STIG catalog names the edition and build it was written for. Scan with
another and the scan still runs, but it warns, and the report carries the
warning in `PlatformWarning`.

A STIG rule is in one of three categories. CAT I rules are the most severe: a
finding there can lead directly to a compromise. CAT II and CAT III are medium
and low. `-Level 'CAT I'` runs only the CAT I rules, and with no `-Level` the scan
covers all three.

Between a fifth and a third of each STIG can't be read from the machine: a rule
about documented procedures, an account review, or a setting the STIG leaves to
the organization. Those are Manual, and STIG Viewer has the full check text.
On a domain controller the local-account checks are NotApplicable, since a
domain controller has none; its accounts are reviewed in Active Directory.

## What it changes

Nothing. It reads the registry, security policy, user rights, audit policy,
services, Windows features, firewall, Defender, BitLocker, local accounts and
installed updates. It makes no network calls. Its only side effects are
temporary files (the `secedit` and `auditpol` exports), deleted as soon as they
are read, and the report files.

## Usage

```powershell
# Run without -Framework to list the frameworks and their levels.
.\Invoke-EndpointComplianceScan.ps1

# Full CMMC Level 2 scan. Run elevated, or the checks that need elevation are Skipped.
.\Invoke-EndpointComplianceScan.ps1 -Framework CMMC

# CMMC Level 1 only (the 17 FAR 52.204-21 requirements); 1 and L1 both work
.\Invoke-EndpointComplianceScan.ps1 -Framework CMMC -Level 1

# STIG CAT I rules only, and keep the raw snapshot
.\Invoke-EndpointComplianceScan.ps1 -Framework DISA-STIG-Win11 -Level 'CAT I' -SnapshotPath .\pc01.snapshot.json

# Windows Server 2022 member server STIG, with STIG Viewer checklists, into a shared folder
.\Invoke-EndpointComplianceScan.ps1 -Framework DISA-STIG-WS2022-MS -StigPath .\U_MS_Windows_Server_2022_V2R11_STIG.zip -OutputPath \\fileserver\scans

# Evaluate a saved snapshot against another framework, on any OS
pwsh -File ./Invoke-EndpointComplianceScan.ps1 -Framework NIST-800-53r5 -Level Low -FromSnapshot ./pc01.snapshot.json
```

`-Framework` takes a framework's Id or its catalog file name, ignoring case
(`disa-stig-win11` works). A level includes the levels before it: `-Level
Moderate` covers Low and Moderate, and `-Level 'CAT II'` covers CAT I and CAT II.
Without `-Level` the scan uses the framework's highest level.

One snapshot holds the facts for every framework, so a machine scanned once can
be evaluated against any of them with `-FromSnapshot`.

Reports go to `.\Reports` or `-OutputPath`; see [Reports](#reports).

| Exit code | Meaning |
| --- | --- |
| 0 | No Fail and no Error |
| 1 | At least one Fail |
| 2 | At least one Error, or the scan couldn't start (including no `-Framework`) |

## Reports

Each run writes these files, named `compliance-scan-<scan id>-<framework>`. The
scan ID is the computer and the UTC time the snapshot was collected, for example
`PC01-20261020T150000Z`. In a folder of many machines' reports the names sort by
computer, then time, and evaluating the same snapshot again replaces its reports.

| File | For |
| --- | --- |
| `.html` | People. One self-contained page that opens offline, can be emailed, and prints to PDF. It has summary counts and a table by family, and lists requirements that can be filtered by state, family and text, each expanding to its evidence. |
| `.records.json` | Power BI and other tools. A flat array with one record per requirement, each repeating the scan ID, computer, collection time, OS, framework and level. |
| `.csv` | Spreadsheets. One row per requirement. |
| `.json` | The full record: requirements, every check's evidence, and the thresholds used. |
| `.cklb` | STIG Viewer 3. Written for a STIG framework when `-StigPath` names the STIG. |
| `.ckl` | STIG Viewer 2, and tools that read the older format. Written with the `.cklb`. |

The reports name the computer and its local accounts, so treat them as internal
records.

### Power BI

Point every machine's `-OutputPath` at one shared folder. In Power BI, choose
Get data, then Folder, pick that folder, and filter the file list to names
ending in `.records.json`. Combine the files: each record becomes a row. Group by
`ScanId` for one scan, or by `ComputerName` and `CollectedUtc` for trends. With
several frameworks scanned, filter on `Framework`.

### STIG Viewer checklists

The catalogs hold short titles, not DISA's rule text, so the checklists need the
STIG itself. Download the STIG zip from [cyber.mil](https://public.cyber.mil/stigs/downloads/)
and pass it, or the XCCDF file inside it, with `-StigPath`:

```powershell
.\Invoke-EndpointComplianceScan.ps1 -Framework DISA-STIG-WS2022-MS -StigPath .\U_MS_Windows_Server_2022_V2R11_STIG.zip
```

Open the `.cklb` in STIG Viewer 3, which doesn't open `.ckl` files. The `.ckl`
holds the same results for STIG Viewer 2. Both list every rule of the STIG, along
with its text:

| Scan result | Checklist status |
| --- | --- |
| Pass | Not a Finding |
| Fail | Open |
| NotApplicable | Not Applicable |
| Manual, Skipped, Error | Not Reviewed |
| Not in the catalog, or above `-Level` | Not Reviewed, with a comment saying why |

Finding Details holds the evidence, and Comments holds the scan ID and any
note. Where the catalog splits a rule in parts (`V-254343.a`, `.b`), the
checklists take the worst part. If the file shares fewer than 80% of the
catalog's Vuln IDs, it is another STIG or release, and the scan stops before
collecting anything. Without `-StigPath`, a STIG scan says how to get the
checklists and writes the other reports.

## Results

| State | Meaning |
| --- | --- |
| Pass | Evidence collected and it meets the threshold |
| Fail | Evidence collected and it misses the threshold |
| Error | A collector or check threw; the message is in the report |
| Skipped | The check applies but couldn't run (usually: not elevated) |
| Manual | The endpoint can't show this; the note says what can |
| NotApplicable | The thing checked is absent, for example RDP idle limits with RDP off, or local accounts on a domain controller |

A requirement takes the worst state among its evidence. Nothing passes by
default: a fact missing from the snapshot is an Error, and a requirement whose
checks were Skipped is Skipped, not Pass. Where Windows has a documented default
for an unset value (for example `EnableLUA`), a check uses it and says so in the
evidence.

The CSV has one row per requirement: `Requirement` (the catalog Id),
`Reference` (the ID to quote, such as the CMMC practice `AC.L2-3.1.8`), `Level`,
`Family`, `Title`, `State`, `Checks` (each piece of evidence and its state),
`Evidence`, `Findings` (only the evidence that didn't pass) and `Note`.

## Evidence

A requirement gets its evidence from two places.

**Named checks** in the script, which apply judgement: 33 of them.

| Family | Checks |
| --- | --- |
| AC | Guest disabled; no enabled account without a password requirement; UAC on, prompting on the secure desktop, and never elevating without a prompt; local Administrators count; account lockout; logon banner; machine inactivity lock; RDP off or NLA required; RDP idle timeout |
| AU | Advanced audit subcategories (matched by GUID, so any display language works); Sensitive Privilege Use; Security log size; time sync |
| CM | SMBv1 off; listed nonessential services absent or disabled; AlwaysInstallElevated off; Autorun and AutoPlay off |
| IA | Password complexity and length; password history; no LM hashes or reversible encryption; NTLMv2 only; blank passwords limited to console logon |
| MP | Removable storage policy |
| SC | Host firewall on with inbound Block on every profile; TLS 1.0 and 1.1 off; FIPS mode; BitLocker on the OS volume |
| SI | Recent Windows update; real-time antivirus (Defender, or another product registered with Security Center); signature age; recent scan |

**Setting expectations** in the catalog, for rules that are a single setting:
a registry value, a security policy value, an audit subcategory, a user right, a
service's start type or a Windows feature. Most of the STIGs' automated rules are
these.

User rights are matched by SID, so the result is the same in any Windows display
language. Domain Admins and Enterprise Admins are required only on a machine in
a domain.

The password checks read the local account policy. On a domain-joined machine,
domain accounts follow the domain password policy, which is assessed on the
domain controllers.

## Thresholds

Most frameworks leave values to the organization. Thresholds apply in this
order, later winning:

1. [`ComplianceScan.example.psd1`](ComplianceScan.example.psd1), the defaults
2. the framework's own `Thresholds` in its catalog, for example the STIG's
   14-character passwords and lockout after 3 attempts, or PCI DSS's 30-minute
   lockout
3. `ComplianceScan.local.psd1` beside the script, or the file `-ProfilePath`
   names

To change a value, create `ComplianceScan.local.psd1` with only the keys you
change; it is gitignored. If your value is looser than one the framework sets,
the scan warns and uses yours.

`RequireFipsMode` and `RequireRemovableMediaPolicy` can be set to `$false` when
FIPS-validated modules or device control are evidenced some other way. Those
checks then report Manual instead of Fail.

## Testing

```powershell
.\Test-ComplianceScan.ps1 -BothEditions    # Pester suite under 5.1 and 7
.\Test-ComplianceScanLint.ps1              # PSScriptAnalyzer; run under pwsh and powershell.exe
```

The suite feeds fixture snapshots to the checks, so it needs no network, no
elevation and no Windows. For every framework it checks the catalog's shape and
that a snapshot meeting every expectation passes. Skipped tests fail the run.
The Tests workflow runs the suite, lint on both editions, and a live scan of the
runner on both editions, evaluated against every framework.

## Updating the catalogs

The NIST and DISA STIG catalogs are generated from published data by
`tools/Update-FrameworkCatalog.ps1`; the CMMC, CIS, PCI DSS and HIPAA catalogs are
written by hand.

```powershell
.\tools\Update-FrameworkCatalog.ps1                                  # rebuild from the pinned sources
.\tools\Update-FrameworkCatalog.ps1 -SourcePath .\sources -Offline   # from saved files only
.\tools\Update-FrameworkCatalog.ps1 -Framework DISA-STIG-Win11 -StigPath .\U_MS_Windows_11_V2R12_STIG.zip -WhatIf
```

Which checks answer which requirement is data in `tools/mappings/`, not code.
`tools/mappings/sources.psd1` pins every source file by SHA-256: NIST's OSCAL
content, Microsoft's PowerStig processed STIGs, and DISA's STIG zips. Each file
comes from the first place that has it with the right hash: `-SourcePath`, the
download cache, each mirror in turn, then the PowerStig package on the PowerShell
Gallery. A source that is down or hands back other content is reported and the
next one is tried.

A STIG catalog with a DISA zip follows that DISA release: its rules, severities
and version are DISA's, and the automated checks come from PowerStig by Vuln ID.
Rules new in the release are Manual until mapped, and retired rules are dropped.
Where DISA has reworded the check of an automated rule since PowerStig's release,
the generator lists the rule, so a person can confirm the expected value and
record it as an override or as reviewed in `tools/mappings/disa-stig.psd1`.
`-StigPath` tries a newer DISA release before it is pinned.

## Changelog

| Version | Date | Changes |
| --- | --- | --- |
| 0.7.0 | 2026-10-24 | The Windows Server 2022 and 2025 STIG catalogs follow DISA's current releases, V2R11 and V1R4, and each rule DISA changed was reviewed. Maximum password age is 180 days, the Security log example size is DISA's 5120000 KB, and the 2025 domain controller checks LDAP server signing (`LDAPServerEnforceIntegrity`). Hardened UNC paths, Credential Guard and virtualization-based security are NotApplicable on a system that isn't joined to a domain, through a new `DomainOnly` expectation key. The 12 rules new in 2025 V1R4 (11 for OpenSSH, one for the servicing level) are Manual, and retired rules are dropped. The role split follows DISA's STIG IDs. Registry values DISA allows to be absent now pass when absent on Server 2019 and 2022, which fixes false failures. Server 2019 stays on V3R8, because DISA has sunset that STIG. |
| 0.6.0 | 2026-10-24 | Catalog generator `tools/Update-FrameworkCatalog.ps1`, in PowerShell, with the check mappings as data in `tools/mappings/`. Sources are pinned by SHA-256 and fetched with failover across mirrors and the PowerShell Gallery, or read offline with `-SourcePath`. STIG catalogs can follow a DISA release newer than PowerStig's. The Windows 11 STIG catalog now follows DISA's V2R11: 276 rules, 2 new rules Manual, 8 retired rules dropped, and the maximum password age raised from 60 to 180 days. |
| 0.5.0 | 2026-10-24 | STIG Viewer 3 checklist (`.cklb`), written beside the `.ckl` when `-StigPath` names the STIG, because STIG Viewer 3 doesn't open `.ckl` files. It follows the layout STIG Viewer 3.8.1 saves. |
| 0.4.1 | 2026-10-24 | Fix: the STIG Viewer checklist failed with "hexadecimal value 0x00, is an invalid character" when evidence held a NUL, as some registry values do. Characters XML can't hold are now dropped from the `.ckl`, and registry strings drop trailing NULs. |
| 0.4.0 | 2026-10-24 | Reports. A self-contained HTML report, flat JSON records for Power BI, and a STIG Viewer checklist (`.ckl`) when `-StigPath` names the DISA STIG zip or XCCDF file. Reports are named by scan ID (computer and collection time), so a shared folder sorts by computer, then time. |
| 0.3.0 | 2026-10-23 | Windows Server: DISA STIGs for Windows Server 2019, 2022 and 2025, each for member servers and domain controllers. User rights expectations and collector, added to every STIG catalog. Kerberos policy on domain controllers. Server roles and features. Each STIG catalog names its Windows edition and build, and the scan warns when the machine differs. Local-account checks are NotApplicable on a domain controller. Snapshot schema 3. |
| 0.2.0 | 2026-10-23 | Renamed from cmmc-endpoint-scan. Eight frameworks, one chosen per run with `-Framework` and `-Level`: CMMC, NIST SP 800-171 Rev 3, NIST SP 800-53 Rev 5 Low/Moderate, DISA Windows 11 STIG, CIS Controls v8.1, NIST CSF 2.0, PCI DSS 4.0.1, HIPAA Security Rule. Setting expectations in catalogs; optional features collector; new checks for UAC prompt behaviour, AutoPlay and blank-password logons; per-framework thresholds; snapshot schema 2. |
| 0.1.0 | 2026-10-23 | First draft: catalog of all 110 requirements, 30 endpoint checks, CSV and JSON reports, Pester suite, CI on both editions. |

## License

Apache-2.0. See [LICENSE](LICENSE). Framework content belongs to its publishers;
see [frameworks/README.md](frameworks/README.md).
