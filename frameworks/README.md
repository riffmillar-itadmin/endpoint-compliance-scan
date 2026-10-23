# Framework catalogs

Each `.psd1` file here is one framework the scanner can evaluate. The scanner
loads every file in this folder, so adding a framework means adding a catalog;
the script itself doesn't change unless a requirement needs a new named check.

## Sources

| Catalog | Source | Coverage |
| --- | --- | --- |
| `cmmc.psd1` | NIST SP 800-171 Rev 2, as assessed by the CMMC program rule (32 CFR 170) | All 110 requirements, written by hand |
| `nist-800-171r3.psd1` | NIST's OSCAL catalog, [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content) | All 97 requirements in force (withdrawn ones are left out) |
| `nist-800-53r5.psd1` | NIST's OSCAL catalog and SP 800-53B baseline profiles, release 5.2.0 | The 287 controls and enhancements in the Moderate baseline, 149 of them also in Low |
| `nist-csf-2.0.psd1` | NIST's OSCAL CSF 2.0 catalog | All 106 subcategories |
| `disa-stig-win11.psd1` | DISA Windows 11 STIG V2R7, as processed by Microsoft's [PowerStig](https://github.com/microsoft/PowerStig) (MIT) | All 282 rules by Vuln ID; titles are short summaries, so STIG Viewer has the full text |
| `cis-controls-v8.1.psd1` | CIS Critical Security Controls v8.1 | Partial: the 18 IG1/IG2 safeguards an endpoint can show evidence for |
| `pci-dss-4.0.1.psd1` | PCI DSS v4.0.1 | Partial: the 22 requirements an endpoint can show evidence for |
| `hipaa-security-rule.psd1` | 45 CFR Part 164, Subpart C | Partial: all of 164.312, plus the endpoint-relevant specifications of 164.308 and 164.310 |

NIST publications and the HIPAA regulation are US government works. The CIS
Controls and PCI DSS are copyrighted by their publishers, so their catalogs carry
only requirement numbers and titles written for this project, never the
standards' text. Get the standards from their publishers for the authoritative
wording.

## Format

```powershell
@{
    Id             = 'CMMC'                  # what -Framework takes (the file name works too)
    Name           = 'CMMC Level 1/2 (...)'  # shown in the summary and the JSON report
    Source         = 'https://...'           # where the framework is published
    Levels         = @('L1', 'L2')           # in order; a level includes the ones before it
    Complete       = $true                   # $false: the catalog is a subset, and reports say so
    PracticeFormat = '{Family}.{Level}-{Id}' # optional: how the Reference column is built (default '{Id}')
    Thresholds     = @{ MinPasswordLength = 14 }  # optional: overrides ComplianceScan.example.psd1
    Requirements   = @(
        @{
            Id     = '3.1.8'                 # unique within the catalog
            Family = 'AC'                    # groups the summary table
            Level  = 'L2'                    # one of Levels
            Title  = 'Limit unsuccessful logon attempts'
            Checks = @('AC-AccountLockout')  # named checks in the script; all are evaluated
            Expect = @( ... )                # optional setting expectations, below
            Note   = '...'                   # for a requirement with no evidence: what to look at
                                             # instead; otherwise: what the evidence leaves out
        }
    )
}
```

A requirement with neither `Checks` nor `Expect` is Manual and must have a
`Note`. Otherwise its state is the worst of its checks and expectations.

Catalogs are read as data in PowerShell's restricted language: literals, arrays
and hashtables only, no commands and no variables other than `$true`, `$false`
and `$null`. A catalog that tries anything else is refused.

### Expectations

Each expectation is one setting with a required value.

| Source | Fields | Reads |
| --- | --- | --- |
| `Registry` | `Path` (`HKLM:\...` or `HKCU:\...`), `Name`, an operator | The registry value. Unset fails, unless `AbsentOk = $true`. `HKCU` is the scanning user's hive. |
| `SecPol` | `Name` (a `[System Access]` key from `secedit /export`), an operator | The local security policy. Undefined fails. |
| `Audit` | `Subcategory` (English name), `Setting` (`Success`, `Failure` or `SuccessAndFailure`) | Advanced audit policy, matched by GUID, so any display language works |
| `Service` | `Name`, `StartType` | The service's start type. A service that isn't installed passes. |
| `Feature` | `Name`, `State = 'Disabled'` | A Windows optional feature. One this Windows build doesn't have passes. Needs elevation. |

Operators for `Registry` and `SecPol`:

| `Op` | Field | Passes when the value |
| --- | --- | --- |
| `eq` | `Value` | equals it (text comparison ignores case and spaces) |
| `ne` | `Value` | differs from it |
| `ge` | `Value` | is a number at least this large |
| `between` | `Min`, `Max` | is a number in this range, inclusive |
| `in` | `Values` | equals one of them |
| `notempty` | | is not blank |

`Also = @(...)` lists extra values that pass, for example `Also = @(0, -1)` on a
lockout duration where 0 and -1 mean "until an administrator unlocks it".

The test suite checks every catalog's shape, and checks that a snapshot meeting
every expectation in it passes, so a malformed catalog fails CI rather than a
scan.
