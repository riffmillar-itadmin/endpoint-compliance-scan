# Pester tests for the Power BI project in powerbi\. Power BI Desktop is what
# opens it, so these check what can be checked without it: the files parse,
# every field a visual or filter uses exists in the model, the model reads the
# fields the scanner writes, and nothing local is in the files.
#
# Run through ..\Test-ComplianceScan.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeDiscovery {
    $discoveryRoot = Split-Path $PSScriptRoot -Parent
    # Desktop leaves its own settings in .pbi\localSettings.json; git ignores them.
    $script:JsonFiles = @(Get-ChildItem -LiteralPath (Join-Path $discoveryRoot 'powerbi') -Recurse -File -Force |
        Where-Object { $_.Extension -in '.json', '.pbir', '.pbism', '.pbip', '.platform' -and $_.Name -ne 'localSettings.json' } |
        ForEach-Object {
            $name = $_.FullName.Substring($discoveryRoot.Length + 1)
            $doc = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
            # Desktop writes .pbip, .pbir, .pbism and its layout and editor
            # settings without a $schema. Report definition files always have one.
            $needsSchema = [bool]$doc.PSObject.Properties['$schema'] -or $name -match '[\\/]definition[\\/]'
            @{ Path = $_.FullName; Name = $name; NeedsSchema = $needsSchema }
        })
    $script:SchemaFiles = @($JsonFiles | Where-Object { $_.NeedsSchema })
}

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:Project = Join-Path $Root 'powerbi'
    $script:Model = Join-Path $Project 'EndpointComplianceScan.SemanticModel/definition'
    $script:Report = Join-Path $Project 'EndpointComplianceScan.Report/definition'
    . (Join-Path $Root 'Invoke-EndpointComplianceScan.ps1')

    function ConvertFrom-TmdlName {
        # 'Fail count' -> Fail count; 'it''s' -> it's
        param([string]$Name)
        $Name = $Name.Trim()
        if ($Name.StartsWith("'")) { return $Name.Substring(1, $Name.Length - 2).Replace("''", "'") }
        $Name
    }

    function Get-ModelTable {
        # Each table file: its name, column names and measure names.
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $Model 'tables') -Filter '*.tmdl') {
            $lines = [IO.File]::ReadAllLines($file.FullName)
            $name = ConvertFrom-TmdlName (@($lines | Where-Object { $_ -match '^table ' })[0] -replace '^table ', '')
            [pscustomobject]@{
                Name     = $name
                File     = $file.FullName
                Text     = [IO.File]::ReadAllText($file.FullName)
                Columns  = @($lines | Where-Object { $_ -match '^\tcolumn ' } | ForEach-Object { ConvertFrom-TmdlName ($_ -replace '^\tcolumn ', '') })
                Measures = @($lines | Where-Object { $_ -match '^\tmeasure ' } | ForEach-Object { ConvertFrom-TmdlName (($_ -replace '^\tmeasure ', '') -replace '\s*=.*$', '') })
            }
        }
    }

    function Get-FieldReference {
        # Every Column and Measure reference in a report JSON object, as
        # Kind / Entity / Property. Filters name their table through an alias in
        # From, so the aliases are carried down.
        param($Node, [hashtable]$Alias = @{})
        if ($null -eq $Node -or $Node -is [string] -or $Node -is [ValueType]) { return }
        if ($Node -is [Collections.IEnumerable]) {
            foreach ($item in $Node) { Get-FieldReference $item $Alias }
            return
        }
        $props = @($Node.PSObject.Properties | ForEach-Object { $_.Name })
        if ($props -contains 'From' -and $props -contains 'Where') {
            $Alias = $Alias.Clone()
            foreach ($f in @($Node.From)) { $Alias[$f.Name] = $f.Entity }
        }
        foreach ($kind in 'Column', 'Measure') {
            if ($props -contains $kind) {
                $ref = $Node.$kind.Expression.SourceRef
                $entity = if ($ref.PSObject.Properties['Entity']) { $ref.Entity } else { $Alias[$ref.Source] }
                [pscustomobject]@{ Kind = $kind; Entity = $entity; Property = $Node.$kind.Property }
            }
        }
        foreach ($p in $Node.PSObject.Properties) { Get-FieldReference $p.Value $Alias }
    }

    function Get-CommittedProjectFile {
        # The project files git would commit: tracked, or new and not ignored.
        # Desktop keeps a data cache and local settings beside them, which a
        # plain folder listing would include. $null when git can't say.
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) { return $null }
        $listed = @(& git -C $Root ls-files --cached --others --exclude-standard -- powerbi 2>$null)
        if ($LASTEXITCODE -ne 0) { return $null }
        @($listed | ForEach-Object { Join-Path $Root $_ } | Where-Object { Test-Path -LiteralPath $_ })
    }

    function Read-JsonFile {
        param([string]$Path)
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
}

Describe 'Power BI project files' {
    It '<Name> is JSON' -ForEach $JsonFiles {
        { Read-JsonFile $Path } | Should -Not -Throw
    }

    It '<Name> names a Fabric schema' -ForEach $SchemaFiles {
        (Read-JsonFile $Path).'$schema' | Should -Match '^https://developer\.microsoft\.com/json-schemas/fabric/'
    }

    It 'lists every model table it has a file for' {
        # Not $model: names aren't case-sensitive, and $Model is the folder.
        $modelText = [IO.File]::ReadAllText((Join-Path $Model 'model.tmdl'))
        $listed = @([regex]::Matches($modelText, '(?m)^ref table (.+)$') | ForEach-Object { ConvertFrom-TmdlName $_.Groups[1].Value })
        @(Get-ModelTable | ForEach-Object Name | Sort-Object) | Should -Be @($listed | Sort-Object)
    }

    It 'relates columns that exist' {
        $tables = @(Get-ModelTable)
        $text = [IO.File]::ReadAllText((Join-Path $Model 'relationships.tmdl'))
        $ends = @([regex]::Matches($text, '(?m)^\t(?:fromColumn|toColumn): (\w+)\.(.+)$'))
        $ends.Count | Should -Be 6
        foreach ($e in $ends) {
            $t = $tables | Where-Object Name -eq $e.Groups[1].Value
            $t | Should -Not -BeNullOrEmpty -Because $e.Value
            $t.Columns | Should -Contain (ConvertFrom-TmdlName $e.Groups[2].Value) -Because $e.Value
        }
    }

    It 'opens the report on the semantic model in the project, by relative path' {
        $pbir = Read-JsonFile (Join-Path $Project 'EndpointComplianceScan.Report/definition.pbir')
        $pbir.datasetReference.byPath.path | Should -Be '../EndpointComplianceScan.SemanticModel'
        Test-Path -LiteralPath (Join-Path $Project 'EndpointComplianceScan.SemanticModel/definition.pbism') | Should -BeTrue
    }

    It 'orders pages that exist, and names each page and visual after its folder' {
        $pages = Read-JsonFile (Join-Path $Report 'pages/pages.json')
        $folders = @(Get-ChildItem -LiteralPath (Join-Path $Report 'pages') -Directory | ForEach-Object Name)
        @($pages.pageOrder | Sort-Object) | Should -Be @($folders | Sort-Object)
        foreach ($folder in $folders) {
            (Read-JsonFile (Join-Path $Report "pages/$folder/page.json")).name | Should -Be $folder
            foreach ($v in @(Get-ChildItem -LiteralPath (Join-Path $Report "pages/$folder/visuals") -Directory)) {
                (Read-JsonFile (Join-Path $v.FullName 'visual.json')).name | Should -Be $v.Name
            }
        }
    }
}

Describe 'Power BI readability' {
    BeforeAll {
        $script:Visuals = @(Get-ChildItem -LiteralPath (Join-Path $Report 'pages') -Recurse -Filter 'visual.json' |
            ForEach-Object { Read-JsonFile $_.FullName })
    }

    It 'sets grid text to at least 11pt in every table and matrix' {
        $grids = @($Visuals | Where-Object { $_.visual.visualType -in 'tableEx', 'pivotTable' })
        $grids.Count | Should -BeGreaterThan 0
        foreach ($v in $grids) {
            foreach ($card in 'values', 'columnHeaders') {
                $size = $v.visual.objects.$card[0].properties.fontSize.expr.Literal.Value
                $size | Should -Not -BeNullOrEmpty -Because "$($v.name) $card"
                [double]($size -replace 'D$', '') | Should -BeGreaterOrEqual 11 -Because "$($v.name) $card"
            }
        }
    }

    It 'draws every line chart with lines thicker than the default' {
        $lines = @($Visuals | Where-Object { $_.visual.visualType -eq 'lineChart' })
        $lines.Count | Should -BeGreaterThan 0
        foreach ($v in $lines) {
            $width = $v.visual.objects.lineStyles[0].properties.strokeWidth.expr.Literal.Value
            $width | Should -Not -BeNullOrEmpty -Because $v.name
            [int]($width -replace 'L$', '') | Should -BeGreaterOrEqual 3 -Because $v.name
        }
    }
}

Describe 'Power BI fields' {
    BeforeAll {
        $script:Tables = @(Get-ModelTable)
        $script:Refs = @(Get-ChildItem -LiteralPath $Report -Recurse -Filter '*.json' |
            ForEach-Object { Get-FieldReference (Read-JsonFile $_.FullName) })
    }

    It 'finds the fields the report uses' {
        # A silent pass if the walk found nothing.
        @($Refs | Where-Object Kind -eq 'Column').Count | Should -BeGreaterThan 20
        @($Refs | Where-Object Kind -eq 'Measure').Count | Should -BeGreaterThan 10
    }

    It 'uses only columns and measures the model has' {
        $missing = @(foreach ($r in $Refs) {
            $t = $Tables | Where-Object Name -eq $r.Entity
            $names = if ($null -eq $t) { @() } elseif ($r.Kind -eq 'Column') { $t.Columns } else { $t.Measures }
            if ($names -notcontains $r.Property) { "$($r.Kind) $($r.Entity)[$($r.Property)]" }
        })
        $missing | Should -BeNullOrEmpty
    }

    It 'reads exactly the fields the scanner writes to .records.json' {
        $catalog = Resolve-Framework @(Get-FrameworkCatalog (Join-Path $Root 'frameworks')) 'CMMC'
        $snapshot = Read-Snapshot (Join-Path $Root 'tests/fixtures/compliant.json')
        $thresholds = Get-ScanThreshold -ExamplePath (Join-Path $Root 'ComplianceScan.example.psd1') -Catalog $catalog
        $evaluation = Invoke-ComplianceEvaluation -Snapshot $snapshot -Thresholds $thresholds -Catalog $catalog -Level 'L2'
        $record = @(ConvertTo-ScanRecord $evaluation $snapshot $catalog)[0]
        $records = ($Tables | Where-Object Name -eq 'Records').Text
        $m = [regex]::Match($records, 'Table\.ExpandRecordColumn\(Rows, "Rows", \{([^}]*)\}\)')
        $m.Success | Should -BeTrue
        $read = @([regex]::Matches($m.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        $read | Should -Be @($record.Keys)
    }

    It 'gives every field it reads a column of the same name' {
        $records = $Tables | Where-Object Name -eq 'Records'
        $m = [regex]::Match($records.Text, 'Table\.ExpandRecordColumn\(Rows, "Rows", \{([^}]*)\}\)')
        foreach ($f in [regex]::Matches($m.Groups[1].Value, '"([^"]+)"')) {
            $records.Columns | Should -Contain $f.Groups[1].Value
        }
    }

    It 'counts every state the scanner can report' {
        $scans = $Tables | Where-Object Name -eq 'Scans'
        foreach ($state in 'Fail', 'Error', 'Accepted', 'Skipped', 'Manual', 'Pass', 'NotApplicable') {
            $scans.Text | Should -Match "x = ""$state"""
        }
        $records = $Tables | Where-Object Name -eq 'Records'
        foreach ($state in 'Fail', 'Error', 'Accepted', 'Skipped', 'Manual', 'Pass', 'NotApplicable') {
            $records.Text | Should -Match """$state"", ""[A-Z-]"""
        }
    }
}

Describe 'Power BI privacy' {
    It 'holds no local paths, accounts or email addresses' {
        $files = Get-CommittedProjectFile
        if ($null -eq $files) { Set-ItResult -Skipped -Because 'git is not available to list the files it would commit'; return }
        $files.Count | Should -BeGreaterThan 40
        $hits = @(Select-String -LiteralPath $files -Pattern @(
            '[A-Za-z]:\\', '\\Users\\', '/Users/', '/home/', '[\w.+-]+@[\w-]+\.[\w.]+') |
            ForEach-Object { "$($_.Path):$($_.LineNumber)" })
        $hits | Should -BeNullOrEmpty
    }

    It 'ships the example share as the report folder, not a real one' {
        $expr = [IO.File]::ReadAllText((Join-Path $Model 'expressions.tmdl'))
        $expr | Should -Match 'expression ReportFolder = "\\\\fileserver\\scans" meta'
    }

    It 'commits no Power BI cache, local settings or saved report' {
        $files = Get-CommittedProjectFile
        if ($null -eq $files) { Set-ItResult -Skipped -Because 'git is not available to list the files it would commit'; return }
        @($files | Where-Object { (Split-Path $_ -Leaf) -in 'cache.abf', 'localSettings.json' -or [IO.Path]::GetExtension($_) -in '.pbix', '.pbit' }) |
            Should -BeNullOrEmpty
    }

    It 'keeps them out of git' {
        $ignore = [IO.File]::ReadAllLines((Join-Path $Root '.gitignore'))
        foreach ($p in '**/.pbi/localSettings.json', '**/.pbi/cache.abf', '*.pbix', '*.pbit') {
            $ignore | Should -Contain $p
        }
    }
}
