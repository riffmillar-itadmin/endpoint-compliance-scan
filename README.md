# cmmc-endpoint-scan

A read-only PowerShell scanner that checks a Windows endpoint against
[NIST SP 800-171 Rev 2](https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final),
the requirements CMMC Level 1 and Level 2 are assessed against, and reports a
result with evidence for each requirement.

It is evidence for an assessment, not a verdict. Most of the 110 requirements are
procedural, or need evidence from outside the endpoint (identity provider,
network, facility, records). The report marks those Manual and says what an
assessor would look at instead. It never states that a machine is compliant and
never computes an SPRS score.

Runs on Windows PowerShell 5.1 and PowerShell 7. No modules to install.

## What it changes

Nothing. It reads the registry, security policy, audit policy, services,
firewall, Defender, BitLocker, local accounts and installed updates. It makes no
network calls. Its only side effects are two temporary files (the `secedit` and
`auditpol` exports), deleted as soon as they are read, and the report files.

## Usage

```powershell
# Full Level 2 scan. Run elevated, or the checks that need elevation are Skipped.
.\Invoke-CmmcEndpointScan.ps1

# Level 1 only (the 17 FAR 52.204-21 requirements), and keep the raw snapshot
.\Invoke-CmmcEndpointScan.ps1 -Level 1 -SnapshotPath .\pc01.snapshot.json

# Re-evaluate a saved snapshot, on any OS
pwsh -File ./Invoke-CmmcEndpointScan.ps1 -FromSnapshot ./pc01.snapshot.json
```

Each run writes `cmmc-scan-<computer>-<timestamp>.csv` (one row per requirement)
and a `.json` with every check's evidence and the thresholds used, into
`.\Reports` or `-OutputPath`. Both name the computer and its local accounts, so
treat them as internal records.

| Exit code | Meaning |
| --- | --- |
| 0 | No Fail and no Error |
| 1 | At least one Fail |
| 2 | At least one Error, or the scan couldn't start |

## Results

| State | Meaning |
| --- | --- |
| Pass | Evidence collected and it meets the threshold |
| Fail | Evidence collected and it misses the threshold |
| Error | A collector or check threw; the message is in the report |
| Skipped | The check applies but couldn't run (usually: not elevated) |
| Manual | The endpoint can't show this; the note says what can |
| NotApplicable | The thing checked is absent, for example RDP idle limits with RDP off |

A requirement takes the worst state among its checks. Nothing passes by default:
a fact missing from the snapshot is an Error, and a requirement whose checks were
Skipped is Skipped, not Pass. Where Windows has a documented default for an unset
value (for example `EnableLUA`), the check uses it and says so in the evidence.

## Checks

30 checks supply evidence for 32 requirements: 8 of the 17 at Level 1 (the other
9 are physical, media or policy controls) and 24 more at Level 2. [`CmmcControls.psd1`](CmmcControls.psd1) maps every one of
the 110 requirements to its checks, or to a note on the evidence to collect.

| Family | Checks |
| --- | --- |
| AC | Guest disabled; no enabled account without a password requirement; UAC on and prompting on the secure desktop; local Administrators count; account lockout; logon banner; machine inactivity lock; RDP off or NLA required; RDP idle timeout |
| AU | Advanced audit subcategories (matched by GUID, so any display language works); Sensitive Privilege Use; Security log size; time sync |
| CM | SMBv1 off; listed nonessential services absent or disabled; AlwaysInstallElevated off |
| IA | Password complexity and length; password history; no LM hashes or reversible encryption; NTLMv2 only |
| MP | Removable storage policy |
| SC | Host firewall on with inbound Block on every profile; TLS 1.0 and 1.1 off; FIPS mode; BitLocker on the OS volume |
| SI | Recent Windows update; real-time antivirus (Defender, or another product registered with Security Center); signature age; recent scan |

The password checks read the local account policy. On a domain-joined machine,
domain accounts follow the domain password policy, which is assessed on the
domain controllers.

## Thresholds

800-171 leaves most values to the organization. The defaults are in
[`CmmcScan.example.psd1`](CmmcScan.example.psd1). To change one, create
`CmmcScan.local.psd1` beside the script with only the keys you change; it is
gitignored and its keys win. `-ProfilePath` uses a different file instead.

`RequireFipsMode` and `RequireRemovableMediaPolicy` can be set to `$false` when
FIPS-validated modules or device control are evidenced some other way. Those
checks then report Manual instead of Fail.

## Testing

```powershell
.\Test-CmmcScan.ps1 -BothEditions    # Pester suite under 5.1 and 7
.\Test-CmmcScanLint.ps1              # PSScriptAnalyzer; run under pwsh and powershell.exe
```

The suite feeds fixture snapshots to the checks, so it needs no network, no
elevation and no Windows. Skipped tests fail the run. The Tests workflow runs
the suite, lint on both editions, and a live scan of the runner on both
editions.

## Changelog

| Version | Date | Changes |
| --- | --- | --- |
| 0.1.0 | 2026-10-23 | First draft: catalog of all 110 requirements, 30 endpoint checks, CSV and JSON reports, Pester suite, CI on both editions. |

## License

Apache-2.0. See [LICENSE](LICENSE).
