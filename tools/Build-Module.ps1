<#
.SYNOPSIS
    Builds the EndpointComplianceScan module, the form the scanner takes on the
    PowerShell Gallery.

.DESCRIPTION
    Copies the scanner, the roll-up, the task script, the example profile, the
    framework catalogs and the licence into -OutputPath\EndpointComplianceScan,
    and writes a manifest and a root module beside them.

    The root module has one command per script, Invoke-EndpointComplianceScan,
    New-ComplianceRollup and Register-ComplianceScanTask, each with the script's
    own parameters and help, generated from the script, so the two can't drift.
    Each command runs the script beside it and leaves the script's exit code in
    $LASTEXITCODE.

    The manifest takes its version from $ComplianceScanVersion in the scanner,
    the author from the copyright line in LICENSE, and the release notes from
    that version's row in the README changelog. A build stops if any of them is
    missing.

    The scripts run from the repository exactly as before; the module is only
    another way to install them.

    To publish, give Publish-PSResource the manifest file, not the module
    folder. Given a folder, it reads the first .psd1 there by name, which is
    ComplianceScan.example.psd1, and stops with "No author was provided". The
    older Publish-Module (PowerShellGet 2) packs with dotnet, which fails on a
    machine with a newer .NET SDK.

.PARAMETER OutputPath
    The folder to build in. The module goes in an EndpointComplianceScan folder
    inside it, replacing an earlier build. Defaults to out under the repository,
    which git ignores.

.EXAMPLE
    .\tools\Build-Module.ps1
    Publish-PSResource -Path .\out\EndpointComplianceScan\EndpointComplianceScan.psd1 -Repository PSGallery -ApiKey $key
    Build, then publish to the PowerShell Gallery.

.NOTES
    Part of endpoint-compliance-scan. Windows PowerShell 5.1 or PowerShell 7, on
    any operating system.
#>

[CmdletBinding()]
param(
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ModuleName = 'EndpointComplianceScan'
# The Gallery knows the module by this GUID. Never change it.
$ModuleGuid = 'f56b4274-590a-4778-baef-955f0d37e8e0'
$ProjectUri = 'https://github.com/riffmillar-itadmin/endpoint-compliance-scan'

# The scripts the module runs, and anything the generated command needs on top
# of the script's own attributes.
$Commands = [ordered]@{
    'Invoke-EndpointComplianceScan' = ''
    # The script it runs writes report files only and has no -WhatIf.
    'New-ComplianceRollup'          = "[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Runs New-ComplianceRollup.ps1, which only writes report files and has no -WhatIf.')]"
    # -WhatIf and -Confirm pass through to the script, which calls ShouldProcess.
    'Register-ComplianceScanTask'   = "[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Passes -WhatIf and -Confirm to Register-ComplianceScanTask.ps1, which calls ShouldProcess.')]"
}

function Get-ModuleVersion {
    # $ComplianceScanVersion, read from the scanner's text rather than run.
    param([string]$ScannerPath)
    $m = [regex]::Match([IO.File]::ReadAllText($ScannerPath), "(?m)^\`$ComplianceScanVersion = '(\d+\.\d+\.\d+)'")
    if (-not $m.Success) { throw "Can't find `$ComplianceScanVersion in $ScannerPath." }
    $m.Groups[1].Value
}

function Get-CopyrightHolder {
    # The name on LICENSE's copyright line, such as 'Copyright 2026 A. Name'.
    param([string]$LicensePath)
    $m = [regex]::Match([IO.File]::ReadAllText($LicensePath), '(?m)^\s*Copyright (\d{4}) (\S.*?)\s*$')
    if (-not $m.Success) { throw "Can't find a copyright line in $LicensePath." }
    [pscustomobject]@{ Year = $m.Groups[1].Value; Name = $m.Groups[2].Value }
}

function Get-ReleaseNote {
    # This version's row of the README changelog, as plain text.
    param([string]$ReadmePath, [string]$Version)
    $pattern = '^\| ' + [regex]::Escape($Version) + ' \| \d{4}-\d{2}-\d{2} \| (.+) \|\s*$'
    foreach ($line in [IO.File]::ReadAllLines($ReadmePath)) {
        $m = [regex]::Match($line, $pattern)
        if ($m.Success) { return ($m.Groups[1].Value -replace '`', '' -replace '\[([^\]]+)\]\([^)]+\)', '$1') }
    }
    throw "The README changelog has no row for $Version."
}

function ConvertTo-ModuleFunction {
    # A function that runs one script, with that script's help, attributes and
    # parameters. Script names in the help become command names.
    param([string]$ScriptPath, [string]$Name, [string]$ExtraAttribute)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -gt 0) { throw "$ScriptPath doesn't parse: $($errors[0].Message)" }
    $help = @($tokens | Where-Object { $_.Kind -eq 'Comment' -and $_.Text.StartsWith('<#') })
    if ($help.Count -eq 0) { throw "$ScriptPath has no comment-based help." }
    $helpText = $help[0].Text
    $names = ($Commands.Keys | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $helpText = $helpText -replace "pwsh -File \./($names)\.ps1", '$1'
    $helpText = $helpText -replace "(?:\.[\\/])?\b($names)\.ps1", '$1'
    $block = $ast.ParamBlock
    if (-not $block) { throw "$ScriptPath has no param block." }
    $text = $ast.Extent.Text
    $start = $block.Extent.StartOffset
    foreach ($a in @($block.Attributes)) { $start = [math]::Min($start, $a.Extent.StartOffset) }
    $paramText = $text.Substring($start - $ast.Extent.StartOffset, $block.Extent.EndOffset - $start)
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("function $Name {")
    $lines.Add($helpText)
    if ($ExtraAttribute) { $lines.Add($ExtraAttribute) }
    $lines.Add($paramText)
    $lines.Add('')
    $lines.Add("    & (Join-Path `$PSScriptRoot '$Name.ps1') @PSBoundParameters")
    $lines.Add('}')
    $lines -join "`n"
}

function Get-ModuleFile {
    # The repository files that go in the module, as Source and the path in it.
    param([string]$Root)
    $files = [Collections.Generic.List[object]]::new()
    foreach ($name in @($Commands.Keys | ForEach-Object { "$_.ps1" }) + 'ComplianceScan.example.psd1', 'LICENSE') {
        $files.Add([pscustomobject]@{ Source = Join-Path $Root $name; Target = $name })
    }
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $Root 'frameworks') -File | Where-Object { $_.Extension -in '.psd1', '.md' } | Sort-Object Name)) {
        $files.Add([pscustomobject]@{ Source = $f.FullName; Target = Join-Path 'frameworks' $f.Name })
    }
    foreach ($f in $files) {
        if (-not (Test-Path -LiteralPath $f.Source -PathType Leaf)) { throw "Can't find $($f.Source)." }
    }
    $files.ToArray()
}

# Dot-sourced (as the tests do): define the functions above and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

$root = Split-Path $PSScriptRoot -Parent
if (-not $OutputPath) { $OutputPath = Join-Path $root 'out' }
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$moduleRoot = Join-Path $OutputPath $ModuleName

$version = Get-ModuleVersion (Join-Path $root 'Invoke-EndpointComplianceScan.ps1')
$holder = Get-CopyrightHolder (Join-Path $root 'LICENSE')
$notes = Get-ReleaseNote -ReadmePath (Join-Path $root 'README.md') -Version $version
$files = @(Get-ModuleFile $root)

# An earlier build is replaced, but only a folder that holds this module, so a
# wrong -OutputPath can't remove anything else.
if (Test-Path -LiteralPath $moduleRoot) {
    if (-not (Test-Path -LiteralPath (Join-Path $moduleRoot "$ModuleName.psd1"))) {
        throw "$moduleRoot exists and doesn't hold an earlier build of $ModuleName, so it isn't replaced."
    }
    Remove-Item -LiteralPath $moduleRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path (Join-Path $moduleRoot 'frameworks') -Force
foreach ($f in $files) { Copy-Item -LiteralPath $f.Source -Destination (Join-Path $moduleRoot $f.Target) }

# With a BOM, so Windows PowerShell 5.1 reads any non-ASCII text as UTF-8.
$utf8 = [Text.UTF8Encoding]::new($true)
$module = [Collections.Generic.List[string]]::new()
$module.Add("# $ModuleName $version, built by tools/Build-Module.ps1 from the scripts")
$module.Add('# beside this file. Each command runs its script; change the scripts, not this.')
$module.Add('')
foreach ($name in $Commands.Keys) {
    $module.Add((ConvertTo-ModuleFunction -ScriptPath (Join-Path $root "$name.ps1") -Name $name -ExtraAttribute $Commands[$name]))
    $module.Add('')
}
$module.Add("Export-ModuleMember -Function $(@($Commands.Keys) -join ', ')")
[IO.File]::WriteAllText((Join-Path $moduleRoot "$ModuleName.psm1"), (($module -join "`n") + "`n"), $utf8)

$manifest = @{
    Path                 = Join-Path $moduleRoot "$ModuleName.psd1"
    RootModule           = "$ModuleName.psm1"
    ModuleVersion        = $version
    Guid                 = $ModuleGuid
    Author               = $holder.Name
    CompanyName          = $holder.Name
    Copyright            = "Copyright $($holder.Year) $($holder.Name). Apache License 2.0."
    Description          = 'A read-only scanner that checks a Windows workstation or server against compliance frameworks chosen at run time (CMMC, NIST SP 800-171 and 800-53, DISA STIGs, CIS Controls, NIST CSF, PCI DSS, HIPAA) and reports a result with evidence for each requirement. Includes a roll-up across machines and a scheduled-scan installer.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @($Commands.Keys)
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    Tags                 = @('Compliance', 'Security', 'Audit', 'CMMC', 'NIST', 'STIG', 'DISA', 'CIS', 'PCI-DSS', 'HIPAA', 'Windows', 'PSEdition_Desktop', 'PSEdition_Core')
    ProjectUri           = $ProjectUri
    LicenseUri           = "$ProjectUri/blob/main/LICENSE"
    ReleaseNotes         = "$version`: $notes Changelog: $ProjectUri#changelog"
}
New-ModuleManifest @manifest
# New-ModuleManifest writes UTF-16 on Windows PowerShell 5.1, and leaves
# trailing spaces; keep one encoding and no trailing spaces.
$text = [IO.File]::ReadAllText($manifest.Path) -replace '[ \t]+(\r?\n)', '$1'
# PowerShell 7 comments out an empty export list, which then means everything.
# State each one, so the module exports its three functions and nothing more.
foreach ($key in 'CmdletsToExport', 'VariablesToExport', 'AliasesToExport') {
    $text = $text -replace "(?m)^#?[ \t]*$key = [^\r\n]*", "$key = @()"
}
[IO.File]::WriteAllText($manifest.Path, $text, $utf8)

Write-Host "Built $ModuleName $version in $moduleRoot" -ForegroundColor Cyan
Write-Host "To publish: Publish-PSResource -Path '$($manifest.Path)' -Repository PSGallery -ApiKey <key>"
Get-Item -LiteralPath $moduleRoot
