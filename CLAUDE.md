# CLAUDE.md

Rules for Claude Code sessions working in this repository. Personal paths and
workflow belong in a gitignored `CLAUDE.local.md` beside this file, not here.

## Changes and commits

- Show the full diff for review before committing. Nothing is committed until
  the maintainer approves it.
- Every commit is a release. Bump `$CmmcScanVersion` in `Invoke-CmmcEndpointScan.ps1`,
  add a line to the version notes in its header, and add an entry to the README
  changelog. Then push.
- Commit messages start with `v<version>: <summary>` and are followed by a
  bulleted body describing each change.
- When asking for approval, make the approve option specific and keep the
  "I want changes" option neutral. Don't pre-scope the answer.

## Signing and releases

- Commits and tags must be signed, because GitHub vigilant mode is on. An
  unsigned commit shows as Unverified. A session that can't sign with the
  maintainer's key prepares changes on a branch, and the signed release is done
  where the key is.
- Chain commit, tag and push so a failed step stops the rest (`set -e`). A
  failed commit must not leave a stray tag behind.
- Sign tags with `git tag -s v<version>`. Create a Release only from the
  existing tag: `gh release create v<version> --verify-tag`.
- After pushing, check every job in the Tests workflow (Pester suite, lint on
  5.1 and 7, live scan on 5.1 and 7) and report each result.

## Testing

- The scanner supports Windows PowerShell 5.1 and PowerShell 7, and a pass on
  one says nothing about the other. Before every commit, run both of these:
  - `.\Test-CmmcScan.ps1 -BothEditions`
  - `Test-CmmcScanLint.ps1` under `pwsh` and under `powershell.exe`
- Lint fails only on Error, Warning or ParseError. Suppress a rule only with a
  `SuppressMessageAttribute` on the function, with a justification, or in
  `PSScriptAnalyzerSettings.psd1` with a comment saying why.
- Run `actionlint` whenever a file under `.github/workflows/` changes.
- A silent pass is the worst outcome. Checks that can't apply are skipped and
  counted, never passed vacuously.
- Add a regression case to `tests/CmmcEndpointScan.Tests.ps1` for every check
  bug fixed.
- Checks read only the snapshot, never the machine, so every rule is testable
  without Windows. A new check gets a Fail case and, where it can be skipped or
  not apply, a case for that too.

## PowerShell traps

- A one-item array unwraps on return. Wrap the result with `@(...)` where a
  list is expected.
- Variable names aren't case-sensitive (`$V` and `$v` are the same variable).
  Avoid names that collide with built-in aliases, such as `R`.
- An array passed through `pwsh -File` arrives as one string.
- `-replace` replaces every match. Anchor the pattern when a file contains
  repeats, such as markup inside a script string.
- Never leave a catch block empty. Log a reason, at least with
  `Write-Verbose`.
- Never put an ambient-state lookup in a parameter default.

## Privacy

This repository is public. Tracked files must not contain:

- real computer names, domains, account names, IP addresses or employers (the
  fixtures use the fictional domain WESTMARK)
- scan reports or snapshots from real machines
- personal paths, email addresses, or third-person references to the maintainer

Personal settings live in gitignored files: `CmmcScan.local*.psd1` and
`*.local*.md`. Scan output (`Reports/`, `cmmc-scan-*`, `*.snapshot.json`) is
gitignored too. Never stage any of them. Confirm that they are absent from the
diff, not just ignored.

Before pushing, grep the diff for these patterns and report a count for each,
rather than declaring the diff clean.
