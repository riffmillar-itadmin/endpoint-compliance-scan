<#
.SYNOPSIS
    Builds the framework catalogs that come from published data.

.DESCRIPTION
    Writes these catalogs in frameworks/ from their published sources and the
    project's check mappings in tools/mappings/:

        nist-800-171r3.psd1     NIST OSCAL catalog
        nist-800-53r5.psd1      NIST OSCAL catalog and the Low/Moderate baselines
        nist-csf-2.0.psd1       NIST OSCAL catalog
        disa-stig-*.psd1        PowerStig processed STIG data, and the DISA STIG zip

    CMMC, CIS Controls, PCI DSS and HIPAA catalogs are written by hand and are not
    touched.

    Sources are pinned by SHA-256 in tools/mappings/sources.psd1. Each file is
    taken from the first source that has it with the right hash: -SourcePath, the
    download cache, then each mirror in turn, then the PowerShell Gallery package
    for PowerStig files. A source that fails or hands back other content is
    reported and the next one is tried.

    A STIG catalog with a DISA zip (from sources.psd1, or -StigPath) follows that
    DISA release: its rules, severities and version are DISA's. Automated checks
    come from PowerStig's processed data for every rule PowerStig has; rules new
    in the DISA release are Manual until mapped, and rules DISA retired are
    dropped. Without a DISA zip the catalog follows PowerStig's release.

    Output is plain data in the restricted language, in ASCII, so Windows
    PowerShell 5.1 reads it the same way.

.PARAMETER Framework
    Catalog Ids to build, such as NIST-800-53r5 or DISA-STIG-Win11. Defaults to
    every catalog this script builds.

.PARAMETER SourcePath
    A folder searched (recursively) for source files before anything is
    downloaded, such as a PowerStig clone or a folder of saved files. Files are
    still checked against their pinned hashes.

.PARAMETER StigPath
    DISA STIG zips or XCCDF files to use instead of the pinned ones, matched to
    catalogs by the benchmark ID inside. Not hash-checked, so a newer DISA release
    can be tried before it is pinned.

.PARAMETER OutputPath
    Folder for the catalogs. Defaults to frameworks/ in this repository.

.PARAMETER CachePath
    Folder for downloaded sources. Defaults to a folder in the temp directory.

.PARAMETER MappingPath
    Folder holding the mapping and source data files. Defaults to tools/mappings.

.PARAMETER Offline
    Use only -SourcePath, -StigPath and the cache; download nothing.

.EXAMPLE
    ./tools/Update-FrameworkCatalog.ps1
    Rebuilds every generated catalog from the pinned sources.

.EXAMPLE
    ./tools/Update-FrameworkCatalog.ps1 -Framework DISA-STIG-Win11 -StigPath .\U_MS_Windows_11_V2R12_STIG.zip -WhatIf
    Shows what a newer DISA release would change, without writing.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$Framework,
    [string]$SourcePath,
    [string[]]$StigPath,
    [string]$OutputPath,
    [string]$CachePath,
    [string]$MappingPath,
    [switch]$Offline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path $PSScriptRoot -Parent

# Get-Prop and Read-StigBenchmark come from the scanner itself, so the catalogs
# and the checklists read DISA's files the same way. Only those two functions are
# loaded: dot-sourcing the whole script would also bind its parameters here.
$scanner = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'Invoke-EndpointComplianceScan.ps1'), [ref]$null, [ref]$null)
foreach ($fn in $scanner.FindAll({ param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -in 'Get-Prop', 'Read-StigBenchmark' }, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}

$Manual = 'Not observable on the endpoint; assess from organizational evidence (policy, procedures, records, other systems).'
$NotAutomated = 'Not automated by this scanner; check it with STIG Viewer or another SCAP tool.'

#region Data files

function ConvertFrom-DataAst {
    # A literal, array or hashtable from a data file's syntax tree. Hashtables
    # come back ordered, so the order written in the file is kept.
    param($Ast)
    switch ($Ast) {
        { $_ -is [Management.Automation.Language.PipelineAst] } {
            if ($Ast.PipelineElements.Count -ne 1) { throw "Data files hold values only (line $($Ast.Extent.StartLineNumber))." }
            return ConvertFrom-DataAst $Ast.PipelineElements[0]
        }
        { $_ -is [Management.Automation.Language.CommandExpressionAst] } { return ConvertFrom-DataAst $Ast.Expression }
        { $_ -is [Management.Automation.Language.StringConstantExpressionAst] } { return $Ast.Value }
        { $_ -is [Management.Automation.Language.ConstantExpressionAst] } { return $Ast.Value }
        { $_ -is [Management.Automation.Language.UnaryExpressionAst] -and $Ast.TokenKind -eq 'Minus' } { return -(ConvertFrom-DataAst $Ast.Child) }
        { $_ -is [Management.Automation.Language.VariableExpressionAst] } {
            switch ($Ast.VariablePath.UserPath) { 'true' { return $true } 'false' { return $false } 'null' { return $null } }
            throw "Data files can't use variables (line $($Ast.Extent.StartLineNumber))."
        }
        { $_ -is [Management.Automation.Language.ArrayExpressionAst] } {
            $items = [Collections.Generic.List[object]]::new()
            foreach ($s in $Ast.SubExpression.Statements) {
                $v = ConvertFrom-DataAst $s
                # @('a', 'b') parses as one statement holding an array literal.
                if ($s.PipelineElements[0].Expression -is [Management.Automation.Language.ArrayLiteralAst]) { $items.AddRange([object[]]$v) } else { $items.Add($v) }
            }
            return , $items.ToArray()
        }
        { $_ -is [Management.Automation.Language.ArrayLiteralAst] } { return , @($Ast.Elements | ForEach-Object { ConvertFrom-DataAst $_ }) }
        { $_ -is [Management.Automation.Language.HashtableAst] } {
            $h = [ordered]@{}
            foreach ($pair in $Ast.KeyValuePairs) { $h[(ConvertFrom-DataAst $pair.Item1)] = ConvertFrom-DataAst $pair.Item2 }
            return $h
        }
    }
    throw "Data files hold literals, arrays and hashtables only; found $($Ast.GetType().Name) at line $($Ast.Extent.StartLineNumber)."
}

function Read-DataFile {
    param([string]$Path)
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
    if ($errors) { throw "$Path does not parse: $($errors[0].Message)" }
    $statements = @($ast.EndBlock.Statements)
    if ($statements.Count -ne 1) { throw "$Path must hold one hashtable." }
    ConvertFrom-DataAst $statements[0]
}

function ConvertTo-DataText {
    # One value as restricted-language text, formatted as the catalogs have always
    # been: short hashtables and flat arrays on one line, the rest one item a line.
    param($Value, [int]$Indent = 0)
    $pad = '    ' * $Indent
    if ($null -eq $Value) { return '$null' }
    if ($Value -is [bool]) { if ($Value) { return '$true' } else { return '$false' } }
    if ($Value -is [int] -or $Value -is [long]) { return [string]$Value }
    if ($Value -is [string]) {
        # ASCII only, so Windows PowerShell 5.1 reads the file the same way.
        $s = $Value.Replace([string][char]0x2013, '-').Replace([string][char]0x2014, '-').Replace([string][char]0x2018, "'").Replace([string][char]0x2019, "'")
        $s = $s.Replace([string][char]0x201c, '"').Replace([string][char]0x201d, '"').Replace([string][char]0xa0, ' ')
        if ($s -match '[^\x00-\x7F]') { throw "Not ASCII: $s" }
        return "'" + $s.Replace("'", "''") + "'"
    }
    if ($Value -is [Collections.IDictionary]) {
        if ($Value.Count -eq 0) { return '@{}' }
        $inner = @(foreach ($k in $Value.Keys) { "$k = $(ConvertTo-DataText $Value[$k] ($Indent + 1))" }) -join '; '
        $nested = @($Value.Values | Where-Object {
                ($_ -is [Collections.IDictionary] -and $_.Count -gt 0) -or
                ($_ -is [Collections.IList] -and @($_ | Where-Object { $_ -is [Collections.IDictionary] }).Count -gt 0)
            }).Count -gt 0
        if ($inner.Length -lt 150 -and -not $nested) { return "@{ $inner }" }
        return "@{`n" + (@(foreach ($k in $Value.Keys) { "$pad    $k = $(ConvertTo-DataText $Value[$k] ($Indent + 1))" }) -join "`n") + "`n$pad}"
    }
    if ($Value -is [Collections.IList]) {
        if ($Value.Count -eq 0) { return '@()' }
        if (@($Value | Where-Object { $_ -is [Collections.IDictionary] -or $_ -is [Collections.IList] }).Count -eq 0) {
            return '@(' + (@($Value | ForEach-Object { ConvertTo-DataText $_ }) -join ', ') + ')'
        }
        return "@(`n" + (@($Value | ForEach-Object { "$pad    $(ConvertTo-DataText $_ ($Indent + 1))" }) -join "`n") + "`n$pad)"
    }
    throw "Can't write a $($Value.GetType().Name) to a catalog."
}

function ConvertTo-CatalogText {
    param([string]$Header, $Meta, $Requirements)
    $sb = [Text.StringBuilder]::new()
    $null = $sb.Append($Header.TrimEnd()).Append("`n`n@{`n")
    foreach ($k in $Meta.Keys) { $null = $sb.Append("    $k = $(ConvertTo-DataText $Meta[$k] 1)`n") }
    $null = $sb.Append("    Requirements = @(`n")
    foreach ($r in $Requirements) { $null = $sb.Append("        $(ConvertTo-DataText $r 2)`n") }
    $null = $sb.Append("    )`n}`n")
    $sb.ToString()
}

function Format-HeaderComment {
    # Wraps text at 82 columns as '# ' comment lines.
    param([string]$Text)
    $lines = [Collections.Generic.List[string]]::new()
    $line = ''
    foreach ($word in ($Text -split '\s+' | Where-Object { $_ })) {
        if ($line -and ($line.Length + 1 + $word.Length) -gt 82) { $lines.Add($line); $line = $word }
        elseif ($line) { $line += " $word" }
        else { $line = $word }
    }
    if ($line) { $lines.Add($line) }
    (@($lines | ForEach-Object { "# $_" }) -join "`n")
}

function New-Requirement {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Returns a new table; changes no system state.')]
    param([string]$Id, [string]$Family, [string]$Level, [string]$Title, [string[]]$Checks = @(), [object[]]$Expect = @(), [string]$Note)
    $Expect = @($Expect | Where-Object { $null -ne $_ })
    $r = [ordered]@{ Id = $Id; Family = $Family; Level = $Level; Title = $Title; Checks = @($Checks | Where-Object { $_ }) }
    if (@($Expect).Count -gt 0) { $r.Expect = @($Expect) }
    if ($Note) { $r.Note = $Note }
    elseif ($r.Checks.Count -eq 0 -and @($Expect).Count -eq 0) { $r.Note = $Manual }
    $r
}

#endregion

#region Sources

function Get-FileSha256 {
    param([string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Save-Url {
    param([string]$Url, [string]$Path)
    # Windows PowerShell 5.1 may not offer TLS 1.2 by default.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing -TimeoutSec 120
}

function Get-SourceFile {
    # The local path of a pinned source file, from the first source holding it
    # with the right hash. Records where each file came from in $SourceLog.
    param([string]$Name, [string]$Sha256, [string[]]$Urls = @(), [string]$Package, [string]$SourcePath, [string]$CachePath, [switch]$Offline)
    $tried = [Collections.Generic.List[string]]::new()
    $candidates = @()
    if ($SourcePath) { $candidates += @(Get-ChildItem -LiteralPath $SourcePath -Filter $Name -File -Recurse -ErrorAction SilentlyContinue) }
    $cached = Join-Path $CachePath $Name
    if (Test-Path -LiteralPath $cached) { $candidates += Get-Item -LiteralPath $cached }
    foreach ($c in $candidates) {
        if ((Get-FileSha256 $c.FullName) -eq $Sha256) {
            $script:SourceLog.Add([pscustomobject]@{ File = $Name; From = $c.FullName })
            return $c.FullName
        }
        $tried.Add("$($c.FullName) (other content)")
        Write-Warning "$($c.FullName) doesn't match the pinned SHA-256 for $Name; trying the next source."
    }
    if ($Offline) { throw "$Name not found with the pinned hash, and -Offline was given. Tried: $(if ($tried.Count) { $tried -join '; ' } else { 'nothing local' })." }
    $tmp = "$cached.download"
    foreach ($url in $Urls) {
        try {
            Save-Url $url $tmp
            if ((Get-FileSha256 $tmp) -eq $Sha256) {
                Move-Item -LiteralPath $tmp -Destination $cached -Force
                $script:SourceLog.Add([pscustomobject]@{ File = $Name; From = $url })
                return $cached
            }
            $tried.Add("$url (other content)")
            Write-Warning "$url returned other content than the pinned $Name; trying the next source."
        } catch {
            $tried.Add("$url ($($_.Exception.Message))")
            Write-Warning "Couldn't download $Name from ${url}: $($_.Exception.Message)"
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
    if ($Package) {
        try {
            $file = Get-PackageEntry $Package $Name $CachePath
            if ((Get-FileSha256 $file) -eq $Sha256) {
                $script:SourceLog.Add([pscustomobject]@{ File = $Name; From = $Package })
                return $file
            }
            Remove-Item -LiteralPath $file -Force
            $tried.Add("$Package (other content)")
        } catch {
            $tried.Add("$Package ($($_.Exception.Message))")
            Write-Warning "Couldn't take $Name from ${Package}: $($_.Exception.Message)"
        }
    }
    throw "No source had $Name with the pinned SHA-256. Tried: $($tried -join '; '). Save the file and pass its folder with -SourcePath."
}

function Get-PackageEntry {
    # Extracts one StigData/Processed file from a module package (a zip) into the
    # cache, downloading the package once.
    param([string]$Url, [string]$Name, [string]$CachePath)
    $pkg = Join-Path $CachePath (($Url -replace '^https?://', '' -replace '[^A-Za-z0-9.-]', '_') + '.zip')
    if (-not (Test-Path -LiteralPath $pkg)) { Save-Url $Url $pkg }
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($pkg)
    try {
        $entry = @($zip.Entries | Where-Object { ([Uri]::UnescapeDataString($_.FullName) -replace '\\', '/') -like "*StigData/Processed/$Name" })
        if ($entry.Count -eq 0) { throw "$Name is not in the package." }
        $out = Join-Path $CachePath $Name
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry[0], $out, $true)
        $out
    } finally { $zip.Dispose() }
}

function Get-PinnedFile {
    # A source file pinned in sources.psd1, by its group (Oscal, PowerStig) and name.
    param([string]$Group, [string]$Name)
    $g = $Sources[$Group]
    $f = @($g.Files | Where-Object { $_.Name -eq $Name })
    if ($f.Count -eq 0) { throw "$Name is not pinned in tools/mappings/sources.psd1 ($Group)." }
    $urls = @($g.Mirrors | ForEach-Object { $_.Replace('{Ref}', $g.Ref).Replace('{Path}', $f[0].Path) })
    $package = if ($g.Contains('Package')) { $g.Package } else { $null }
    Get-SourceFile -Name $Name -Sha256 $f[0].Sha256 -Urls $urls -Package $package @Fetch
}

function Read-Json {
    param([string]$Path)
    [IO.File]::ReadAllText($Path) | ConvertFrom-Json
}

function Read-Xml {
    param([string]$Path)
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create($Path, $settings)
    try {
        $doc = [Xml.XmlDocument]::new()
        $doc.Load($reader)
        $doc
    } finally { $reader.Dispose() }
}

#endregion

#region NIST

function Get-PropTable {
    # An OSCAL object's props as a name -> value table.
    param($Object)
    $t = @{}
    foreach ($p in @(Get-Prop $Object 'props')) { if ($p) { $t[$p.name] = Get-Prop $p 'value' } }
    $t
}

function Assert-Mapped {
    # Every mapped ID must exist in the source, so a typo can't drop a mapping.
    param([string]$Catalog, $Map, [string[]]$Ids)
    $missing = @($Map.Keys | Where-Object { $Ids -notcontains $_ })
    if ($missing.Count -gt 0) { throw "tools/mappings maps IDs that $Catalog doesn't have: $($missing -join ', ')." }
}

function Build-Nist171 {
    $map = Read-DataFile (Join-Path $Mappings 'nist-800-171r3.psd1')
    $cat = (Read-Json (Get-PinnedFile Oscal 'NIST_SP800-171_rev3_catalog.json')).catalog
    $reqs = [Collections.Generic.List[object]]::new()
    foreach ($g in @($cat.groups)) {
        foreach ($x in @(Get-Prop $g 'controls')) {
            if (-not $x -or (Get-PropTable $x)['status'] -eq 'withdrawn') { continue }
            $id = $x.id -replace '^SP_800_171_', ''
            $reqs.Add((New-Requirement $id $map.Families[$g.title] 'Rev3' $x.title @($map.Checks[$id])))
        }
    }
    Assert-Mapped 'NIST SP 800-171r3' $map.Checks @($reqs | ForEach-Object { $_.Id })
    $header = @"
# NIST SP 800-171 Rev 3 (May 2024): all $($reqs.Count) security requirements still in force
# (withdrawn ones are left out). Generated from NIST's OSCAL catalog,
# https://github.com/usnistgov/oscal-content (nist.gov/SP800-171/rev3).
# Field meanings are in frameworks/README.md.
"@
    $meta = [ordered]@{ Id = 'NIST-800-171r3'; Name = 'NIST SP 800-171 Rev 3'; Source = 'https://csrc.nist.gov/pubs/sp/800/171/r3/final'
        Levels = @('Rev3'); Complete = $true; Thresholds = [ordered]@{}
    }
    [pscustomobject]@{ Id = $meta.Id; File = 'nist-800-171r3'; Text = (ConvertTo-CatalogText $header $meta $reqs); Requirements = $reqs.Count; Note = ''; Reworded = @() }
}

function Build-Nist53 {
    $map = Read-DataFile (Join-Path $Mappings 'nist-800-53r5.psd1')
    $profileIds = {
        param($File)
        @(foreach ($imp in @((Read-Json (Get-PinnedFile Oscal $File)).profile.imports)) {
                foreach ($ic in @(Get-Prop $imp 'include-controls')) { if ($ic) { @(Get-Prop $ic 'with-ids') } }
            })
    }
    $low = @(& $profileIds 'NIST_SP-800-53_rev5_LOW-baseline_profile.json')
    $mod = @(& $profileIds 'NIST_SP-800-53_rev5_MODERATE-baseline_profile.json')
    $cat = (Read-Json (Get-PinnedFile Oscal 'NIST_SP-800-53_rev5_catalog.json')).catalog
    $titles = @{}
    $labels = @{}
    $walk = {
        param($Node, $Parent)
        foreach ($k in @(Get-Prop $Node 'controls')) {
            if (-not $k) { continue }
            $label = @(@(Get-Prop $k 'props') | Where-Object { $_ -and $_.name -eq 'label' -and (Get-Prop $_ 'class') -ne 'zero-padded' } | ForEach-Object { $_.value })
            $titles[$k.id] = if ($null -eq $Parent) { $k.title } else { "$($titles[$Parent]) | $($k.title)" }
            $labels[$k.id] = if ($label.Count -gt 0) { $label[0] } else { $k.id.ToUpperInvariant() }
            & $walk $k $k.id
        }
    }
    foreach ($g in @($cat.groups)) { & $walk $g $null }
    $reqs = [Collections.Generic.List[object]]::new()
    foreach ($id in $mod) {
        $level = if ($low -contains $id) { 'Low' } else { 'Moderate' }
        $reqs.Add((New-Requirement $labels[$id] ($labels[$id] -split '-')[0] $level $titles[$id] @($map.Checks[$id])))
    }
    Assert-Mapped 'the NIST SP 800-53 Moderate baseline' $map.Checks $mod
    $version = $cat.metadata.version
    $header = @"
# NIST SP 800-53 Rev 5 (release $version): the $($mod.Count) controls and enhancements in
# the SP 800-53B Moderate baseline, $($low.Count) of which are also in Low. Generated from
# NIST's OSCAL catalog and baseline profiles, https://github.com/usnistgov/oscal-content.
# Field meanings are in frameworks/README.md.
"@
    $meta = [ordered]@{ Id = 'NIST-800-53r5'; Name = "NIST SP 800-53 Rev 5 ($version) Low/Moderate baselines"; Source = 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'
        Levels = @('Low', 'Moderate'); Complete = $true; Thresholds = [ordered]@{}
    }
    [pscustomobject]@{ Id = $meta.Id; File = 'nist-800-53r5'; Text = (ConvertTo-CatalogText $header $meta $reqs); Requirements = $reqs.Count; Note = ''; Reworded = @() }
}

function Build-NistCsf {
    $map = Read-DataFile (Join-Path $Mappings 'nist-csf-2.0.psd1')
    $cat = (Read-Json (Get-PinnedFile Oscal 'NIST_CSF_v2.0_catalog.json')).catalog
    $reqs = [Collections.Generic.List[object]]::new()
    $walk = {
        param($Node)
        foreach ($k in @(@(Get-Prop $Node 'groups') + @(Get-Prop $Node 'controls'))) {
            if (-not $k) { continue }
            if ((Get-Prop $k 'class') -eq 'subcategory' -and (Get-PropTable $k)['status'] -ne 'withdrawn') {
                $prose = (@(@(Get-Prop $k 'parts') | Where-Object { $_ -and $_.name -eq 'statement' } | ForEach-Object { "$(Get-Prop $_ 'prose')" }) -join ' ').Trim()
                $reqs.Add((New-Requirement $k.id ($k.id -split '-')[0] 'CSF' $prose @($map.Checks[$k.id])))
            }
            & $walk $k
        }
    }
    & $walk $cat
    Assert-Mapped 'NIST CSF 2.0' $map.Checks @($reqs | ForEach-Object { $_.Id })
    $header = @"
# NIST Cybersecurity Framework 2.0: all $($reqs.Count) subcategories. CSF describes outcomes,
# not settings, so most are Manual and the mapped ones report endpoint evidence
# toward the outcome. Generated from NIST's OSCAL catalog,
# https://github.com/usnistgov/oscal-content (nist.gov/CSF/v2.0).
# Field meanings are in frameworks/README.md.
"@
    $meta = [ordered]@{ Id = 'NIST-CSF-2.0'; Name = 'NIST Cybersecurity Framework 2.0'; Source = 'https://www.nist.gov/cyberframework'
        Levels = @('CSF'); Complete = $true; Thresholds = [ordered]@{}
    }
    [pscustomobject]@{ Id = $meta.Id; File = 'nist-csf-2.0'; Text = (ConvertTo-CatalogText $header $meta $reqs); Requirements = $reqs.Count; Note = ''; Reworded = @() }
}

#endregion

#region STIG

$Severity = @{ high = 'CAT I'; medium = 'CAT II'; low = 'CAT III' }
$RuleFamily = @{ AccountPolicyRule = 'Account'; AuditPolicyRule = 'Audit'; RegistryRule = 'Config'; SecurityOptionRule = 'SecOpt'
    UserRightRule = 'Rights'; ServiceRule = 'Feature'; WindowsFeatureRule = 'Feature'
}

function Get-Sentence {
    # The first sentence of a text, at most 120 characters.
    param([string]$Text)
    $s = ([regex]::Replace($Text, '\s+', ' ')).Trim()
    $s = ([regex]::Split($s, '(?<=[.])\s'))[0]
    if ($s.Length -gt 120) { $s.Substring(0, 117) + '...' } else { $s }
}

function Get-FirstSentence {
    # The first sentence of a PowerStig rule's discussion.
    param([string]$Description)
    $m = [regex]::Match([Net.WebUtility]::HtmlDecode($Description), '<VulnDiscussion>(.*?)</VulnDiscussion>', 'Singleline')
    Get-Sentence $(if ($m.Success) { $m.Groups[1].Value } else { '' })
}

function ConvertTo-Number {
    param([string]$Text)
    if ($Text -match '^\s*0[xX]([0-9a-fA-F]+)\s*$') { return [Convert]::ToInt64($Matches[1], 16) }
    if ($Text -match '^\s*[+-]?\d+\s*$') { return [long]$Text }
    $null
}

function ConvertTo-CatalogNumber {
    # Numbers fit [int] in every catalog; keep them [int] so they write as before.
    param($Value)
    if ($Value -is [long] -and $Value -le [int]::MaxValue -and $Value -ge [int]::MinValue) { return [int]$Value }
    $Value
}

function ConvertFrom-OrgTest {
    # An expectation from PowerStig's test for an organization-defined value.
    param([string]$Test, $Base)
    $t = $Test.Replace("''", "'")
    $e = [ordered]@{}
    foreach ($k in $Base.Keys) { $e[$k] = $Base[$k] }
    if ($t -cmatch "^\s*'[^']+' -le '(\d+)' -and '[^']+' -(?:gt|ne) '0'\s*\z") { $e.Op = 'between'; $e.Min = 1; $e.Max = [int]$Matches[1]; return $e }
    if ($t -cmatch "^\s*'[^']+' -ge '(\d+)'\s*\z") { $e.Op = 'ge'; $e.Value = [int]$Matches[1]; return $e }
    if ($t -cmatch "^\s*'[^']+' -le '(\d+)'\s*\z") { $e.Op = 'between'; $e.Min = 0; $e.Max = [int]$Matches[1]; return $e }
    if ($t -cmatch "^\s*'[^']+' -ge '(\d+)' -or '[^']+' -eq '0'\s*\z") { $e.Op = 'ge'; $e.Value = [int]$Matches[1]; $e.Also = @(0, -1); return $e }
    if ($t -cmatch "^\s*'[^']+' -match '([0-9|A-Za-z]+)'\s*\z") {
        $values = @($Matches[1] -split '\|')
        $e.Op = 'in'
        $e.Values = @($values | Where-Object { $_ -ne 'ShouldBeAbsent' } | ForEach-Object { [int]$_ })
        if ($values -contains 'ShouldBeAbsent') { $e.AbsentOk = $true }
        return $e
    }
    if ($t -cmatch "^\s*'[^']+' -ne '([^']+)'\s*\z") { $e.Op = 'ne'; $e.Value = $Matches[1]; return $e }
    if ($t -cmatch '^\s*ValueData is set to 0x[0-9a-fA-F]+ \((\d+)\) or greater\s*\z') { $e.Op = 'ge'; $e.Value = [int]$Matches[1]; return $e }
    $null
}

function Get-Identity {
    # 'Administrators,Local account .' -> 'Administrators', 'Local account'.
    # Org-defined values come from a regex, so '\\' is unescaped.
    param([string]$Text)
    @($Text -split ',' | Where-Object { $_.Trim().Trim('.') } | ForEach-Object { ($_.Trim() -replace '\s*\.$', '').Replace('\\', '\') })
}

function Read-PowerStig {
    # PowerStig's processed STIG: its metadata, rules (in file order, each as a
    # table of child element text) and organization-defined tests.
    param([string]$Name)
    $doc = Read-Xml (Get-PinnedFile PowerStig "$Name.xml")
    $orgText = [IO.File]::ReadAllText((Get-PinnedFile PowerStig "$Name.org.default.xml"))
    $org = @{}
    foreach ($m in [regex]::Matches($orgText, '<!-- Ensure (.*?)-->\s*<OrganizationalSetting id="([^"]+)"([^>]*)/>', 'Singleline')) {
        $org[$m.Groups[2].Value] = $m.Groups[1].Value
    }
    $rules = [Collections.Generic.List[object]]::new()
    foreach ($group in @($doc.DocumentElement.ChildNodes | Where-Object { $_ -is [Xml.XmlElement] })) {
        foreach ($rule in @($group.ChildNodes | Where-Object { $_ -is [Xml.XmlElement] })) {
            $d = @{}
            foreach ($c in @($rule.ChildNodes | Where-Object { $_ -is [Xml.XmlElement] })) { $d[$c.LocalName] = $c.InnerText.Trim() }
            $rules.Add([pscustomobject]@{ Type = $group.LocalName; Id = $rule.GetAttribute('id'); Severity = $rule.GetAttribute('severity'); Data = $d })
        }
    }
    $root = $doc.DocumentElement
    [pscustomobject]@{
        Name = $Name; StigId = $root.GetAttribute('stigid'); Title = $root.GetAttribute('title'); Version = $root.GetAttribute('version')
        ReleaseInfo = $root.GetAttribute('releaseinfo'); Rules = @($rules); Org = $org
    }
}

function Get-StigData {
    param([Collections.IDictionary]$Data, [string]$Name)
    if ($Data.Contains($Name)) { $Data[$Name] } else { '' }
}

function ConvertTo-StigRequirement {
    # One PowerStig rule as a catalog requirement, automated where the rule type
    # maps to a collector.
    param($Rule, $Stig, $Named, $Map)
    $d = $Rule.Data
    $id = $Rule.Id
    $type = $Rule.Type
    $family = if ($RuleFamily.ContainsKey($type)) { $RuleFamily[$type] } else { 'Other' }
    $expect = $null
    $title = $null
    $checks = @()
    $note = $null
    if ($Named.Contains($id)) {
        $checks = @($Named[$id].Checks)
        $note = if ($Named[$id].Contains('Note')) { $Named[$id].Note } else { $null }
        $title = Get-FirstSentence (Get-StigData $d 'Description')
    } elseif ($type -eq 'RegistryRule') {
        $key = $d.Key.Replace('HKEY_LOCAL_MACHINE', 'HKLM:').Replace('HKEY_CURRENT_USER', 'HKCU:')
        $name = $d.ValueName
        $title = "$name ($(@($key -split '\\')[-1]))"
        $base = [ordered]@{ Source = 'Registry'; Path = $key; Name = $name }
        $valueType = (Get-StigData $d 'ValueType').ToLowerInvariant()
        if ((Get-StigData $d 'OrganizationValueRequired') -eq 'True') {
            if ($name -cin 'LegalNoticeText', 'LegalNoticeCaption') {
                $expect = [ordered]@{}; foreach ($k in $base.Keys) { $expect[$k] = $base[$k] }; $expect.Op = 'notempty'
                $note = 'The STIG requires the DoD notice and consent text; this check confirms one is set.'
            } elseif ($Stig.Org.ContainsKey($id)) { $expect = ConvertFrom-OrgTest $Stig.Org[$id] $base }
            if ($expect) {
                $title += ' ' + $(switch ($expect.Op) {
                        'between' { "between $($expect.Min) and $($expect.Max)" }
                        'ge' { ">= $($expect.Value)" }
                        'in' { 'in ' + (@($expect.Values) -join '/') }
                        'notempty' { 'is set' }
                        default { '' }
                    })
            }
        } elseif ($valueType -ne 'multistring') {
            $v = Get-StigData $d 'ValueData'
            $n = if ($valueType -eq 'dword') { ConvertTo-Number $v } else { $null }
            $expect = [ordered]@{}; foreach ($k in $base.Keys) { $expect[$k] = $base[$k] }
            $expect.Op = 'eq'
            $expect.Value = if ($null -ne $n) { ConvertTo-CatalogNumber $n } else { $v }
            $title += " = $v"
        }
    } elseif ($type -in 'AccountPolicyRule', 'SecurityOptionRule') {
        $policy = if (Get-StigData $d 'PolicyName') { $d.PolicyName } else { Get-StigData $d 'OptionName' }
        $value = if (Get-StigData $d 'PolicyValue') { $d.PolicyValue } else { Get-StigData $d 'OptionValue' }
        if ($Map.SecurityOptionRegistry.Contains($policy)) {
            $expect = $Map.SecurityOptionRegistry[$policy].Expect
            $title = $Map.SecurityOptionRegistry[$policy].Title
        } else {
            if (-not $Map.SecurityPolicy.Contains($policy)) { throw "$($Stig.Name) $id uses security policy '$policy', which tools/mappings/disa-stig.psd1 doesn't name." }
            $title = $policy
            $base = [ordered]@{ Source = 'SecPol'; Name = $Map.SecurityPolicy[$policy] }
            if ($Stig.Org.ContainsKey($id) -and (Get-StigData $d 'OrganizationValueRequired') -eq 'True') { $expect = ConvertFrom-OrgTest $Stig.Org[$id] $base }
            elseif ($value -cin 'Enabled', 'Disabled') {
                $expect = [ordered]@{ Source = 'SecPol'; Name = $base.Name; Op = 'eq'; Value = $(if ($value -eq 'Enabled') { 1 } else { 0 }) }
            }
            if ($expect) {
                $title += $(switch ($expect.Op) {
                        'between' { ": $($expect.Min) to $($expect.Max)" }
                        'ge' { ": $($expect.Value) or more" }
                        'eq' { ": $value" }
                        'ne' { ": not '$($expect.Value)'" }
                        default { '' }
                    })
            }
        }
    } elseif ($type -eq 'AuditPolicyRule') {
        $expect = [ordered]@{ Source = 'Audit'; Subcategory = $d.Subcategory; Setting = $d.AuditFlag }
        $title = "Audit $($d.Subcategory): $($d.AuditFlag)"
    } elseif ($type -eq 'UserRightRule') {
        $op = if ($d.Force -eq 'True') { 'only' } else { 'includes' }
        if ($d.OrganizationValueRequired -eq 'True') {
            $pattern = [regex]::Match($Stig.Org[$id], "-match '(.*)'").Groups[1].Value
            $whole = [regex]::Match($pattern, '^\^\((.*)\)\$\z')
            if ($whole.Success) {
                # '^(A,B|A)$': the list must be one of these; allow the union of them.
                $ids = [Collections.Generic.List[string]]::new()
                foreach ($alt in ($whole.Groups[1].Value -split '\|')) { foreach ($i in (Get-Identity $alt)) { if (-not $ids.Contains($i)) { $ids.Add($i) } } }
                $ids = @($ids)
                $op = 'only'
            } else {
                # 'A,B,(C|D),E': must include each; keep alternatives as 'C|D'.
                $ids = @(foreach ($p in [regex]::Split($pattern, ',(?![^(]*\))')) {
                        if (@(Get-Identity $p.Trim('(', ')')).Count -eq 0) { continue }
                        if ($p.Contains('|')) { (Get-Identity ($p.Trim('(', ')').Replace('|', ','))) -join '|' } else { @(Get-Identity $p)[0] }
                    })
                $op = 'includes'
            }
        } else {
            $ids = @(Get-Identity $d.Identity)
        }
        $expect = [ordered]@{ Source = 'UserRight'; Name = $d.Constant; Op = $op; Identities = @($ids) }
        $title = if ($op -eq 'only') {
            "$($d.DisplayName): " + $(if ($ids.Count) { ($ids -join ', ') + ' only' } else { 'no one' })
        } else {
            "$($d.DisplayName): includes " + (@($ids | ForEach-Object { $_.Replace('|', ' or ') }) -join ', ')
        }
    } elseif ($type -eq 'ServiceRule') {
        if (Get-StigData $d 'ServiceName') {
            $expect = [ordered]@{ Source = 'Service'; Name = $d.ServiceName; StartType = $d.StartupType }
            $title = "Service $($d.ServiceName) is $($d.StartupType)"
        }
    } elseif ($type -eq 'WindowsFeatureRule') {
        $expect = [ordered]@{ Source = 'Feature'; Name = $d.Name; State = 'Disabled' }
        $title = "Feature $($d.Name) is not installed"
    }
    if (-not $title) { $title = Get-FirstSentence (Get-StigData $d 'Description'); if (-not $title) { $title = $id } }
    if (-not ($note -or $checks.Count -or $expect)) { $note = $NotAutomated }
    New-Requirement $id $family $Severity[$Rule.Severity] $title $checks $(if ($expect) { , $expect } else { @() }) $note
}

function Get-NamedByText {
    # Named checks for manual rules, matched by the start of their discussion.
    param($Stig, $Map, [bool]$DomainController)
    $named = [ordered]@{}
    foreach ($rule in @($Stig.Rules | Where-Object { $_.Type -in 'ManualRule', 'DocumentRule' })) {
        $text = Get-FirstSentence (Get-StigData $rule.Data 'Description')
        foreach ($n in @($Map.NamedByText)) {
            if ($DomainController -and $n.Contains('NotOnDomainController') -and $n.NotOnDomainController) { continue }
            if ($text -cmatch "^(?:$($n.Pattern))") {
                $named[$rule.Id] = [ordered]@{ Checks = @($n.Checks) }
                if ($n.Contains('Note')) { $named[$rule.Id].Note = $n.Note }
                break
            }
        }
    }
    $named
}

function Set-StigOverride {
    # Applies the catalog's overrides, for rules DISA changed after PowerStig's
    # release: replaced fields, or a part moved to the Vuln ID DISA gave it.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Returns a changed copy of the requirement list; changes no system state.')]
    param($Requirements, $Overrides, $Disa, $Reworded)
    $list = [Collections.Generic.List[object]]::new()
    foreach ($r in $Requirements) { $list.Add($r) }
    foreach ($id in $Overrides.Keys) {
        $o = $Overrides[$id]
        $r = @($list | Where-Object { $_.Id -eq $id })
        if ($r.Count -eq 0) { throw "tools/mappings overrides $id, which this release doesn't have; review the override." }
        $r = $r[0]
        if ($o.Contains('MoveTo')) {
            $target = @($list | Where-Object { $_.Id -eq $o.MoveTo })
            if ($target.Count -gt 0) { $null = $list.Remove($target[0]) }
            $r.Id = $o.MoveTo
            $r.Level = $Severity[$Disa[$o.MoveTo].Severity]
        }
        foreach ($k in 'Title', 'Checks', 'Expect', 'Note') { if ($o.Contains($k)) { $r[$k] = $o[$k] } }
        $null = $Reworded.Remove($id)
    }
    , $list
}

function Build-Stig {
    param($Entry, $Map, $Benchmarks)
    $stig = Read-PowerStig $Entry.PowerStig
    $dc = $Entry.Contains('Role') -and $Entry.Role -eq 'domain controller'
    $named = if ($Entry.Contains('Named')) { $Entry.Named } elseif ($Entry.Contains('NamedByText') -and $Entry.NamedByText) { Get-NamedByText $stig $Map $dc } else { [ordered]@{} }
    $missingNamed = @($named.Keys | Where-Object { @($stig.Rules | ForEach-Object { $_.Id }) -notcontains $_ })
    if ($missingNamed.Count -gt 0) { throw "tools/mappings names checks for rules $($Entry.PowerStig) doesn't have: $($missingNamed -join ', ')." }
    $reqs = [Collections.Generic.List[object]]::new()
    foreach ($rule in $stig.Rules) { $reqs.Add((ConvertTo-StigRequirement $rule $stig $named $Map)) }

    if (-not ($stig.ReleaseInfo -match 'Release: (\d+) Benchmark Date: (\d+ \w+ \d+)')) { throw "$($Entry.PowerStig): unexpected release info '$($stig.ReleaseInfo)'." }
    $release = $Matches[1]
    $date = $Matches[2]
    $version = $stig.Version
    $source = "Rule data from the processed STIG in Microsoft's PowerStig project (MIT), https://github.com/microsoft/PowerStig;"
    $note = "PowerStig $($Entry.PowerStig)"
    $reworded = [Collections.Generic.List[string]]::new()

    $bench = $Benchmarks[$stig.StigId]
    if ($bench) {
        # Follow the DISA release: its rules and severities, PowerStig's automation.
        if (-not ($bench.ReleaseInfo -match 'Release: (\d+) Benchmark Date: (\d+ \w+ \d+)')) { throw "$($bench.FileName): unexpected release info '$($bench.ReleaseInfo)'." }
        $release = $Matches[1]
        $date = $Matches[2]
        $version = $bench.Version
        # A rule PowerStig splits in parts (V-1.a, V-1.b) is one DISA rule (V-1).
        $baseId = { param($Id) $Id -replace '\.[a-z]$', '' }
        $have = @($reqs | ForEach-Object { & $baseId $_.Id } | Select-Object -Unique)
        $disa = @{}
        foreach ($b in $bench.Rules) { $disa[$b.GroupId] = $b }
        $retired = @($have | Where-Object { -not $disa.ContainsKey($_) })
        # The other role's PowerStig file says which server rules aren't for this role.
        $otherRole = @()
        if ($Entry.Contains('Role')) {
            $other = if ($dc) { $Entry.PowerStig -replace '-DC-', '-MS-' } else { $Entry.PowerStig -replace '-MS-', '-DC-' }
            $otherRole = @((Read-PowerStig $other).Rules | ForEach-Object { $_.Id -replace '\.[a-z]$', '' })
        }
        $kept = [Collections.Generic.List[object]]::new()
        $flat = { param($Text) ([regex]::Replace("$Text", '\s+', ' ')).Trim().ToLowerInvariant() }
        $raw = @{}
        foreach ($rule in $stig.Rules) { $raw[$rule.Id] = Get-StigData $rule.Data 'RawString' }
        foreach ($r in $reqs) {
            $b = $disa[(& $baseId $r.Id)]
            if (-not $b) { continue }
            $r.Level = $Severity[$b.Severity]
            # Automation carries over by Vuln ID. Where DISA has since reworded the
            # check, list the rule so a person can confirm the expected value.
            if (($r.Contains('Expect') -or $r.Checks.Count -gt 0) -and -not (& $flat $b.CheckContent).Contains((& $flat $raw[$r.Id]))) {
                $reworded.Add($r.Id)
            }
            $kept.Add($r)
        }
        foreach ($b in $bench.Rules) {
            if ($have -contains $b.GroupId -or $otherRole -contains $b.GroupId) { continue }
            $title = Get-Sentence $b.RuleTitle
            $kept.Add((New-Requirement $b.GroupId 'Other' $Severity[$b.Severity] $title @() @() "New in $($bench.Title -replace 'Security Technical Implementation Guide', 'STIG') V$($version)R$release and not automated yet; check it with STIG Viewer or another SCAP tool."))
        }
        $reqs = $kept
        if ($Entry.Contains('Overrides')) { $reqs = Set-StigOverride $reqs $Entry.Overrides $disa $reworded }
        # Rules a person has checked against this release don't need listing again.
        if ($Entry.Contains('Reviewed') -and $Entry.Reviewed.Release -eq "V$($version)R$release") {
            foreach ($id in @($Entry.Reviewed.Rules)) { $null = $reworded.Remove($id) }
        }
        $source = "Rules and severities from DISA's STIG ($([IO.Path]::GetFileName($bench.FileName))); automated checks from the processed STIG $($Entry.PowerStig) in Microsoft's PowerStig project (MIT), https://github.com/microsoft/PowerStig;"
        $added = @($reqs | Where-Object { $_.Contains('Note') -and $_.Note -like 'New in *' }).Count
        $note = "DISA V$($version)R$release, PowerStig $($Entry.PowerStig): $added new rule(s) Manual, $($retired.Count) retired rule(s) dropped$(if ($retired.Count) { " ($($retired -join ', '))" })"
    }

    $auto = @($reqs | Where-Object { $_.Contains('Expect') -or $_.Checks.Count -gt 0 }).Count
    $extra = if ($Entry.Contains('Role')) { " ($($Entry.Role))" } else { '' }
    $head = "DISA $($stig.Title.Replace('Security Technical Implementation Guide', 'STIG'))$extra, Version $version Release $release " +
        "(benchmark date $date): all $($reqs.Count) rules, by Vuln ID. $source STIG content is published by DISA at " +
        'https://public.cyber.mil/stigs/. Titles here are short summaries; STIG Viewer has the full rule text. ' +
        'Levels are the severity categories.'
    $header = (Format-HeaderComment $head) + "`n# Field meanings are in frameworks/README.md."
    $meta = [ordered]@{
        Id = $Entry.Id; Name = "DISA $($Entry.Product) STIG V$($version)R$release"; Source = 'https://public.cyber.mil/stigs/'; StigId = $stig.StigId
        Levels = @('CAT I', 'CAT II', 'CAT III'); Complete = $true; AppliesTo = $Entry.AppliesTo; Thresholds = $Map.Thresholds
    }
    [pscustomobject]@{ Id = $Entry.Id; File = $Entry.File; Text = (ConvertTo-CatalogText $header $meta $reqs); Requirements = $reqs.Count; Note = "$auto automated; $note"; Reworded = @($reworded) }
}

#endregion

# Dot-sourced (by the tests), only the functions are wanted.
if ($MyInvocation.InvocationName -eq '.') { return }

if (-not $OutputPath) { $OutputPath = Join-Path $Root 'frameworks' }
$Mappings = if ($MappingPath) { $MappingPath } else { Join-Path $PSScriptRoot 'mappings' }
if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath }
if (-not $CachePath) { $CachePath = Join-Path ([IO.Path]::GetTempPath()) 'endpoint-compliance-scan-sources' }
if (-not (Test-Path -LiteralPath $CachePath)) { $null = New-Item -ItemType Directory -Path $CachePath -WhatIf:$false }
$Fetch = @{ SourcePath = $SourcePath; CachePath = $CachePath; Offline = $Offline }
$script:SourceLog = [Collections.Generic.List[object]]::new()
$Sources = Read-DataFile (Join-Path $Mappings 'sources.psd1')
$stigMap = Read-DataFile (Join-Path $Mappings 'disa-stig.psd1')

$builders = [ordered]@{ 'NIST-800-171r3' = { Build-Nist171 }; 'NIST-800-53r5' = { Build-Nist53 }; 'NIST-CSF-2.0' = { Build-NistCsf } }
foreach ($entry in @($stigMap.Catalogs)) { $builders[$entry.Id] = $entry }
if (-not $Framework) { $Framework = @($builders.Keys) }
$unknown = @($Framework | Where-Object { -not $builders.Contains($_) })
if ($unknown.Count -gt 0) { throw "This script doesn't build $($unknown -join ', '). It builds: $(@($builders.Keys) -join ', ')." }

# The DISA releases to follow, by benchmark ID: -StigPath first, then the pinned zips.
$benchmarks = @{}
foreach ($p in @($StigPath | Where-Object { $_ })) {
    $b = Read-StigBenchmark $p
    $benchmarks[$b.Id] = $b
    $script:SourceLog.Add([pscustomobject]@{ File = [IO.Path]::GetFileName($p); From = (Resolve-Path -LiteralPath $p).ProviderPath })
}
$wantStigs = @($stigMap.Catalogs | Where-Object { $Framework -contains $_.Id })
foreach ($d in @($Sources.Disa)) {
    if ($benchmarks.ContainsKey($d.Benchmark)) { continue }
    $needed = @($wantStigs | Where-Object { (Read-PowerStig $_.PowerStig).StigId -eq $d.Benchmark }).Count -gt 0
    if (-not $needed) { continue }
    $benchmarks[$d.Benchmark] = Read-StigBenchmark (Get-SourceFile -Name $d.Name -Sha256 $d.Sha256 -Urls @($d.Urls) @Fetch)
}

foreach ($id in $Framework) {
    $b = $builders[$id]
    $result = if ($b -is [scriptblock]) { & $b } else { Build-Stig $b $stigMap $benchmarks }
    $path = Join-Path $OutputPath "$($result.File).psd1"
    $old = if (Test-Path -LiteralPath $path) { [IO.File]::ReadAllText($path) } else { $null }
    $changed = $old -ne $result.Text
    if ($changed -and $PSCmdlet.ShouldProcess($path, 'Write catalog')) {
        [IO.File]::WriteAllText($path, $result.Text, [Text.UTF8Encoding]::new($false))
    }
    if ($result.Reworded.Count -gt 0) {
        Write-Warning "$($result.Id): DISA reworded the check of $($result.Reworded.Count) automated rule(s) since PowerStig's release; confirm their expected values: $($result.Reworded -join ', ')"
    }
    [pscustomobject]@{ Id = $result.Id; File = "$($result.File).psd1"; Requirements = $result.Requirements; Changed = $changed; Note = $result.Note; Reworded = $result.Reworded }
}

foreach ($s in $script:SourceLog) { Write-Verbose "Source: $($s.File) from $($s.From)" }
