# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x, latest release | Yes |
| 0.x | No. Update to 1.x; [Compatibility](README.md#compatibility) says what changed from 0.x. |

Fixes go into the latest 1.x release only, on GitHub and on the PowerShell
Gallery.

## What it does to a machine

A scan is read-only. It changes no setting and writes nothing to the registry.
It writes temporary `secedit` and `auditpol` exports, deleted as soon as they
are read, and its reports. With `-FallbackPath` and `-LogPath` it also keeps
reports that couldn't be delivered and a run log. Its only network traffic is
writing reports to a share named by `-OutputPath`, and on a domain controller
reading Active Directory from itself.

`Register-ComplianceScanTask.ps1` does change the machine, and is meant to:

- it copies the scanner to `%ProgramFiles%\EndpointComplianceScan`, so the task
  never runs code from a user's folder or a share;
- it registers a scheduled task that runs that copy as SYSTEM;
- it creates `%ProgramData%\EndpointComplianceScan` (the fallback folder and run
  log) and limits it to SYSTEM and Administrators, because ProgramData lets any
  user create files in a subfolder.

The scanner trusts a waiting report, the fallback folder and the default local
profile in `%ProgramData%\EndpointComplianceScan` only when SYSTEM,
Administrators, TrustedInstaller or the account running the scan owns them and
none is a junction or link.

## What to report

Reports name real machines and accounts, and the tool promises to change
nothing when it scans, so report anything that could break either promise, or
let one user act through the scheduled task, for example:

- a code path in a scan that changes a setting, writes to the registry, or
  makes a network call it shouldn't;
- a way for a snapshot, catalog or profile file to run code (all are meant to
  be data only);
- a way for a standard user to get a file delivered as another computer's
  report, or to change what the SYSTEM task runs or reads, such as its profile;
- a check that reports Pass without the evidence to back it;
- a vulnerability in a GitHub Action the workflow uses.

## How to report

Use **Report a vulnerability** on this repository's **Security** tab, which
opens a private advisory only the maintainer can see. Please don't open a public
issue for a security problem.

Include what you found, how to reproduce it, and which version you tested
(`$ComplianceScanVersion` in `Invoke-EndpointComplianceScan.ps1`, the release
tag, or `(Get-Module EndpointComplianceScan -ListAvailable).Version`).

## What to expect

This project has one maintainer, so responses are best effort.
