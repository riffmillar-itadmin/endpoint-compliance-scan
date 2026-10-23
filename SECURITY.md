# Security policy

## What to report

The scanner is read-only and its reports name real machines and accounts, so
report anything that could break either promise, for example:

- a code path that changes a setting, writes to the registry, or makes a network call;
- a way for a snapshot or profile file to run code (both are meant to be data only);
- a check that reports Pass without the evidence to back it;
- a vulnerability in a GitHub Action the workflow uses.

## How to report

Use **Report a vulnerability** on this repository's **Security** tab, which
opens a private advisory only the maintainer can see. Please don't open a public
issue for a security problem.

Include what you found, how to reproduce it, and which version you tested
(`$ComplianceScanVersion` in `Invoke-EndpointComplianceScan.ps1`, or the
release tag).

## What to expect

This project has one maintainer, so responses are best effort. Fixes go into the
latest release only.
