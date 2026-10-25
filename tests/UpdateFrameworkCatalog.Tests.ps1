# Pester tests for tools/Update-FrameworkCatalog.ps1. No network: the generator
# reads the made-up sources in fixtures/generator with -SourcePath and -Offline,
# and downloads are mocked.
#
# Run through ..\Test-ComplianceScan.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:Generator = Join-Path $Root 'tools/Update-FrameworkCatalog.ps1'
    $script:FixtureSources = Join-Path $PSScriptRoot 'fixtures/generator/sources'
    $script:FixtureMappings = Join-Path $PSScriptRoot 'fixtures/generator/mappings'
    $script:DisaFixture = Join-Path $PSScriptRoot 'fixtures/stig-sample-xccdf.xml'
    . $Generator

    function Get-TestFolder {
        # A new, empty folder under TestDrive.
        $p = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $p
        $p
    }

    function Copy-FixtureMapping {
        # A copy of the fixture mappings, with text replacements applied to one file.
        param([string]$File, [hashtable]$Replace = @{})
        $dir = Get-TestFolder
        Copy-Item -Path (Join-Path $FixtureMappings '*') -Destination $dir
        if ($File) {
            $path = Join-Path $dir $File
            $text = [IO.File]::ReadAllText($path)
            foreach ($k in $Replace.Keys) {
                if (-not $text.Contains($k)) { throw "The fixture $File has no '$k' to replace." }
                $text = $text.Replace($k, $Replace[$k])
            }
            [IO.File]::WriteAllText($path, $text)
        }
        $dir
    }

    function Invoke-Generator {
        # Runs the generator on the fixtures into a new folder. Returns the folder,
        # the result objects and the warnings.
        param([string[]]$Framework, [string]$Mappings = $FixtureMappings, [string[]]$StigPath, [switch]$DryRun)
        $out = Get-TestFolder
        $arguments = @{
            MappingPath = $Mappings; SourcePath = $FixtureSources; Offline = $true
            OutputPath = $out; CachePath = (Join-Path $out 'cache')
        }
        if ($Framework) { $arguments.Framework = $Framework }
        if ($StigPath) { $arguments.StigPath = $StigPath }
        if ($DryRun) { $arguments.WhatIf = $true }
        $warnings = $null
        $results = @(& $Generator @arguments -WarningVariable warnings -WarningAction SilentlyContinue)
        [pscustomobject]@{ Folder = $out; Results = $results; Warnings = @($warnings | ForEach-Object { "$_" }) }
    }

    # The generator's functions are simple functions, without -WarningVariable;
    # their warnings are taken from stream 3 instead.
    function Select-Warning { param([object[]]$Output) @($Output | Where-Object { $_ -is [Management.Automation.WarningRecord] } | ForEach-Object { "$_" }) }
    function Select-Value { param([object[]]$Output) @($Output | Where-Object { $_ -isnot [Management.Automation.WarningRecord] })[0] }

    function Read-Catalog {
        param([string]$Folder, [string]$File)
        Import-PowerShellDataFile -LiteralPath (Join-Path $Folder "$File.psd1")
    }

    function Get-Requirement {
        param($Catalog, [string]$Id)
        $r = @($Catalog.Requirements | Where-Object { $_.Id -eq $Id })
        if ($r.Count -ne 1) { throw "Expected one requirement $Id; found $($r.Count)." }
        $r[0]
    }
}

Describe 'Data files' {
    It 'keeps the key order written in the file, nested tables included' {
        $p = Join-Path (Get-TestFolder) 'order.psd1'
        [IO.File]::WriteAllText($p, "@{ Zulu = 1; Alpha = @{ Yankee = 'y'; Bravo = 'b' }; Mike = @(1, 2) }")
        $d = Read-DataFile $p
        @($d.Keys) | Should -Be @('Zulu', 'Alpha', 'Mike')
        @($d.Alpha.Keys) | Should -Be @('Yankee', 'Bravo')
        @($d.Mike) | Should -Be @(1, 2)
    }

    It 'reads $true, $false, $null, negative numbers and one-item arrays' {
        $p = Join-Path (Get-TestFolder) 'values.psd1'
        [IO.File]::WriteAllText($p, "@{ T = `$true; F = `$false; N = `$null; Neg = -1; One = @('a'); Many = @(`n    'a'`n    'b'`n) }")
        $d = Read-DataFile $p
        $d.T | Should -BeTrue
        $d.F | Should -BeFalse
        $d.N | Should -BeNullOrEmpty
        $d.Neg | Should -Be -1
        , $d.One | Should -BeOfType [object[]]
        $d.One.Count | Should -Be 1
        @($d.Many) | Should -Be @('a', 'b')
    }

    It 'refuses <Name>' -TestCases @(
        @{ Name = 'a command'; Text = '@{ A = (Get-Date) }'; Message = '*literals, arrays and hashtables only*' }
        @{ Name = 'a variable'; Text = '@{ A = $env:PATH }'; Message = "*can't use variables*" }
        @{ Name = 'a pipeline'; Text = '@{ A = 1 | Write-Output }'; Message = '*values only*' }
        @{ Name = 'two statements'; Text = "@{ A = 1 }`n@{ B = 2 }"; Message = '*one hashtable*' }
        @{ Name = 'text that does not parse'; Text = '@{ A = '; Message = '*does not parse*' }
    ) {
        param($Text, $Message)
        $p = Join-Path (Get-TestFolder) 'bad.psd1'
        [IO.File]::WriteAllText($p, $Text)
        { Read-DataFile $p } | Should -Throw $Message
    }

    It 'writes short tables on one line and long or nested ones a key a line' {
        $short = [ordered]@{ Source = 'SecPol'; Name = 'LockoutBadCount'; Op = 'eq'; Value = 3 }
        ConvertTo-DataText $short | Should -BeExactly "@{ Source = 'SecPol'; Name = 'LockoutBadCount'; Op = 'eq'; Value = 3 }"
        $nested = [ordered]@{ Id = 'X'; Expect = @([ordered]@{ Op = 'eq' }) }
        ConvertTo-DataText $nested | Should -BeExactly "@{`n    Id = 'X'`n    Expect = @(`n        @{ Op = 'eq' }`n    )`n}"
        $long = [ordered]@{ Title = 'x' * 150 }
        ConvertTo-DataText $long | Should -BeExactly "@{`n    Title = '$('x' * 150)'`n}"
    }

    It 'writes empty values, booleans and quotes as the restricted language reads them' {
        ConvertTo-DataText ([ordered]@{}) | Should -BeExactly '@{}'
        ConvertTo-DataText @() | Should -BeExactly '@()'
        ConvertTo-DataText $null | Should -BeExactly '$null'
        ConvertTo-DataText $true | Should -BeExactly '$true'
        ConvertTo-DataText "Don't" | Should -BeExactly "'Don''t'"
        ConvertTo-DataText @('a', 1) | Should -BeExactly "@('a', 1)"
    }

    It 'writes typographic punctuation as ASCII and refuses other non-ASCII text' {
        $text = "a$([char]0x2013)b$([char]0x2019)s $([char]0x201c)q$([char]0x201d)$([char]0xa0)end"
        ConvertTo-DataText $text | Should -BeExactly "'a-b''s `"q`" end'"
        { ConvertTo-DataText "caf$([char]0xe9)" } | Should -Throw '*Not ASCII*'
    }

    It 'writes a catalog the scanner reads back to the same values' {
        $meta = [ordered]@{ Id = 'T'; Levels = @('One'); Complete = $true; Thresholds = [ordered]@{} }
        $reqs = @(
            (New-Requirement 'R-1' 'F' 'One' "It's one" @('AC-GuestDisabled'))
            (New-Requirement 'R-2' 'F' 'One' 'Two' @() @([ordered]@{ Source = 'Registry'; Path = 'HKLM:\X'; Name = 'Y'; Op = 'eq'; Value = 1 }))
            (New-Requirement 'R-3' 'F' 'One' 'Three')
        )
        $p = Join-Path (Get-TestFolder) 'catalog.psd1'
        [IO.File]::WriteAllText($p, (ConvertTo-CatalogText '# A header.' $meta $reqs))
        $c = Import-PowerShellDataFile -LiteralPath $p
        $c.Id | Should -Be 'T'
        $c.Requirements.Count | Should -Be 3
        $c.Requirements[0].Title | Should -Be "It's one"
        $c.Requirements[1].Expect[0].Path | Should -Be 'HKLM:\X'
        $c.Requirements[2].Note | Should -Be $Manual
    }

    It 'leaves a requirement with checks or expectations without a note, and one with neither Manual' {
        $r = New-Requirement 'R' 'F' 'L' 'T' @() @($null)
        $r.Contains('Expect') | Should -BeFalse
        $r.Note | Should -Be $Manual
        (New-Requirement 'R' 'F' 'L' 'T' @('AC-GuestDisabled')).Contains('Note') | Should -BeFalse
    }

    It 'wraps the header comment at 82 columns' {
        $lines = @((Format-HeaderComment (('word ' * 60).Trim())) -split "`n")
        $lines.Count | Should -BeGreaterThan 1
        @($lines | Where-Object { $_.Length -gt 84 -or -not $_.StartsWith('# ') }).Count | Should -Be 0
    }
}

Describe 'Source files' {
    BeforeEach {
        $script:SourceLog = [Collections.Generic.List[object]]::new()
        $script:Cache = Get-TestFolder
        $script:Good = Join-Path $FixtureSources 'Sample-1.2.org.default.xml'
        $script:GoodHash = Get-FileSha256 $Good
        $script:Mirrors = @('https://mirror-one.invalid/a', 'https://mirror-two.invalid/a')
    }

    It 'takes a file from -SourcePath when its hash matches, without downloading' {
        Mock Save-Url { throw 'no download expected' }
        $p = Get-SourceFile -Name 'Sample-1.2.org.default.xml' -Sha256 $GoodHash -Urls $Mirrors -CachePath $Cache -SourcePath $FixtureSources
        $p | Should -Be (Get-Item -LiteralPath $Good).FullName
        Should -Invoke Save-Url -Times 0 -Exactly
        $SourceLog[0].From | Should -Be $p
    }

    It 'skips a local file with other content, then takes the cached copy' {
        $local = Get-TestFolder
        Set-Content -LiteralPath (Join-Path $local 'Sample-1.2.org.default.xml') -Value 'other content'
        Copy-Item -LiteralPath $Good -Destination $Cache
        $out = @(Get-SourceFile -Name 'Sample-1.2.org.default.xml' -Sha256 $GoodHash -Urls $Mirrors -CachePath $Cache -SourcePath $local 3>&1)
        $p = Select-Value $out
        $warnings = @(Select-Warning $out)
        $p | Should -Be (Join-Path $Cache 'Sample-1.2.org.default.xml')
        @($warnings).Count | Should -Be 1
        "$($warnings[0])" | Should -BeLike "*doesn't match the pinned SHA-256*"
    }

    It 'fails over to the next mirror when one is down, and caches the download' {
        Mock Save-Url { if ($Url -like '*mirror-one*') { throw 'host not found' }; Copy-Item -LiteralPath $Good -Destination $Path }
        $out = @(Get-SourceFile -Name 'Sample-1.2.org.default.xml' -Sha256 $GoodHash -Urls $Mirrors -CachePath $Cache 3>&1)
        $p = Select-Value $out
        $warnings = @(Select-Warning $out)
        $p | Should -Be (Join-Path $Cache 'Sample-1.2.org.default.xml')
        Get-FileSha256 $p | Should -Be $GoodHash
        Should -Invoke Save-Url -Times 2 -Exactly
        $SourceLog[0].From | Should -Be $Mirrors[1]
        "$($warnings[0])" | Should -BeLike '*mirror-one*host not found*'
        @(Get-ChildItem -LiteralPath $Cache -Filter '*.download').Count | Should -Be 0
    }

    It 'refuses a mirror that hands back other content' {
        Mock Save-Url { if ($Url -like '*mirror-one*') { Set-Content -LiteralPath $Path -Value 'tampered' } else { Copy-Item -LiteralPath $Good -Destination $Path } }
        $out = @(Get-SourceFile -Name 'Sample-1.2.org.default.xml' -Sha256 $GoodHash -Urls $Mirrors -CachePath $Cache 3>&1)
        $p = Select-Value $out
        $warnings = @(Select-Warning $out)
        Get-FileSha256 $p | Should -Be $GoodHash
        "$($warnings[0])" | Should -BeLike '*mirror-one*other content*'
    }

    It 'takes a PowerStig file from the module package when every mirror fails' {
        $package = 'https://package.invalid/Sample/1.2'
        $staging = Get-TestFolder
        $null = New-Item -ItemType Directory -Path (Join-Path $staging 'PowerStig/StigData/Processed')
        Copy-Item -LiteralPath $Good -Destination (Join-Path $staging 'PowerStig/StigData/Processed')
        $zip = Join-Path (Get-TestFolder) 'package.zip'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($staging, $zip)
        Mock Save-Url { if ($Url -eq $package) { Copy-Item -LiteralPath $zip -Destination $Path } else { throw 'mirror down' } }
        $p = Get-SourceFile -Name 'Sample-1.2.org.default.xml' -Sha256 $GoodHash -Urls $Mirrors -CachePath $Cache -Package $package 3>$null
        Get-FileSha256 $p | Should -Be $GoodHash
        $SourceLog[0].From | Should -Be $package
    }

    It 'names every source it tried when none has the file' {
        Mock Save-Url { throw 'offline' }
        { Get-SourceFile -Name 'Sample-1.2.org.default.xml' -Sha256 $GoodHash -Urls $Mirrors -CachePath $Cache 3>$null } |
            Should -Throw '*No source had Sample-1.2.org.default.xml*mirror-one*mirror-two*-SourcePath*'
    }

    It 'downloads nothing with -Offline' {
        Mock Save-Url { throw 'no download expected' }
        { Get-SourceFile -Name 'Sample-1.2.org.default.xml' -Sha256 $GoodHash -Urls $Mirrors -CachePath $Cache -Offline } | Should -Throw '*-Offline*'
        Should -Invoke Save-Url -Times 0 -Exactly
    }
}

Describe 'Organization-defined values' {
    It 'reads <Test>' -TestCases @(
        @{ Test = "'V-1' -le '900' -and 'V-1' -ne '0'"; Want = [ordered]@{ Op = 'between'; Min = 1; Max = 900 } }
        @{ Test = "'V-1' -le '900' -and 'V-1' -gt '0'"; Want = [ordered]@{ Op = 'between'; Min = 1; Max = 900 } }
        @{ Test = "'V-1' -ge '24'"; Want = [ordered]@{ Op = 'ge'; Value = 24 } }
        @{ Test = "'V-1' -le '3'"; Want = [ordered]@{ Op = 'between'; Min = 0; Max = 3 } }
        @{ Test = "'V-1' -ge '15' -or 'V-1' -eq '0'"; Want = [ordered]@{ Op = 'ge'; Value = 15; Also = @(0, -1) } }
        @{ Test = "'V-1' -match '1|2|ShouldBeAbsent'"; Want = [ordered]@{ Op = 'in'; Values = @(1, 2); AbsentOk = $true } }
        @{ Test = "'V-1' -ne 'Guest'"; Want = [ordered]@{ Op = 'ne'; Value = 'Guest' } }
        @{ Test = 'ValueData is set to 0x00000384 (900) or greater'; Want = [ordered]@{ Op = 'ge'; Value = 900 } }
        @{ Test = "''V-1'' -le '900' -and ''V-1'' -ne '0'"; Want = [ordered]@{ Op = 'between'; Min = 1; Max = 900 } }
    ) {
        param($Test, $Want)
        $e = ConvertFrom-OrgTest $Test ([ordered]@{ Source = 'SecPol'; Name = 'X' })
        @($e.Keys) | Should -Be (@('Source', 'Name') + @($Want.Keys))
        foreach ($k in $Want.Keys) { $e[$k] | Should -Be $Want[$k] }
    }

    It 'returns nothing for a test it does not know, rather than guessing' {
        ConvertFrom-OrgTest "'V-1' -lt '5'" ([ordered]@{}) | Should -BeNullOrEmpty
        ConvertFrom-OrgTest "'V-1' -le '900' extra" ([ordered]@{}) | Should -BeNullOrEmpty
    }
}

Describe 'NIST catalogs from OSCAL' {
    BeforeAll {
        $script:Run = Invoke-Generator -Framework 'NIST-800-171r3', 'NIST-800-53r5', 'NIST-CSF-2.0'
    }

    It 'writes each catalog and reports it' {
        @($Run.Results | ForEach-Object { $_.Id }) | Should -Be @('NIST-800-171r3', 'NIST-800-53r5', 'NIST-CSF-2.0')
        @($Run.Results | Where-Object { -not $_.Changed }).Count | Should -Be 0
        $Run.Warnings.Count | Should -Be 0
    }

    It 'leaves withdrawn 800-171 requirements out and maps families and checks' {
        $c = Read-Catalog $Run.Folder 'nist-800-171r3'
        @($c.Requirements | ForEach-Object { $_.Id }) | Should -Be @('03.01.01', '03.01.02', '03.03.01')
        (Get-Requirement $c '03.01.01').Checks | Should -Be @('AC-GuestDisabled', 'AC-NoPasswordNotRequired')
        (Get-Requirement $c '03.03.01').Family | Should -Be 'AU'
        (Get-Requirement $c '03.01.02').Note | Should -Be $Manual
    }

    It 'takes the Moderate baseline, marks Low, and uses the unpadded labels' {
        $c = Read-Catalog $Run.Folder 'nist-800-53r5'
        @($c.Requirements | ForEach-Object { $_.Id }) | Should -Be @('AC-2', 'AC-2(1)', 'AC-3')
        @($c.Requirements | ForEach-Object { $_.Level }) | Should -Be @('Low', 'Moderate', 'Moderate')
        (Get-Requirement $c 'AC-2(1)').Title | Should -Be 'Account Management | Automated System Account Management'
        (Get-Requirement $c 'AC-2(1)').Checks | Should -Be @('AC-GuestDisabled')
        $c.Name | Should -Be 'NIST SP 800-53 Rev 5 (5.2.0) Low/Moderate baselines'
    }

    It 'counts a one-control Low baseline (regression: a one-item list unwrapped)' {
        $text = [IO.File]::ReadAllText((Join-Path $Run.Folder 'nist-800-53r5.psd1'))
        $text | Should -Match 'Moderate baseline, 1 of which are also in Low'
    }

    It 'takes CSF subcategory titles from the statement and leaves withdrawn ones out' {
        $c = Read-Catalog $Run.Folder 'nist-csf-2.0'
        @($c.Requirements | ForEach-Object { $_.Id }) | Should -Be @('PR.AA-01', 'PR.AA-03')
        (Get-Requirement $c 'PR.AA-03').Title | Should -Be 'Users are authenticated.'
        (Get-Requirement $c 'PR.AA-03').Family | Should -Be 'PR.AA'
    }

    It 'stops when a mapping names an ID the source does not have' {
        $maps = Copy-FixtureMapping 'nist-800-171r3.psd1' @{ "'03.01.01' = " = "'03.99.99' = @('AC-GuestDisabled')`n        '03.01.01' = " }
        { Invoke-Generator -Framework 'NIST-800-171r3' -Mappings $maps } | Should -Throw '*03.99.99*'
    }
}

Describe 'STIG catalog from PowerStig' {
    BeforeAll {
        $script:Run = Invoke-Generator -Framework 'DISA-STIG-Sample'
        $script:Stig = Read-Catalog $Run.Folder 'disa-stig-sample'
    }

    It "follows PowerStig's release when there is no DISA zip" {
        $Stig.Name | Should -Be 'DISA Westmark Sample STIG V1R2'
        $Stig.StigId | Should -Be 'Sample_Westmark_STIG'
        $Stig.Requirements.Count | Should -Be 16
        $Run.Results[0].Note | Should -BeLike '*PowerStig Sample-1.2'
        $Run.Warnings.Count | Should -Be 0
    }

    It 'writes the mapped thresholds and AppliesTo' {
        [IO.File]::ReadAllText((Join-Path $Run.Folder 'disa-stig-sample.psd1')) | Should -Match "(?m)^    Thresholds = @\{ LockoutThresholdMax = 3; MinPasswordLength = 14 \}$"
        $Stig.AppliesTo.MinBuild | Should -Be 22000
    }

    It 'maps <Id> (<Kind>)' -TestCases @(
        @{ Id = 'V-900007'; Kind = 'account policy, organization-defined'; Title = 'Account lockout threshold: 1 to 3'; Expect = [ordered]@{ Source = 'SecPol'; Name = 'LockoutBadCount'; Op = 'between'; Min = 1; Max = 3 } }
        @{ Id = 'V-900011'; Kind = 'audit policy'; Title = 'Audit Credential Validation: Failure'; Expect = [ordered]@{ Source = 'Audit'; Subcategory = 'Credential Validation'; Setting = 'Failure' } }
        @{ Id = 'V-900001'; Kind = 'registry DWORD'; Title = 'EnableLUA (System) = 1'; Expect = [ordered]@{ Source = 'Registry'; Name = 'EnableLUA'; Op = 'eq'; Value = 1 } }
        @{ Id = 'V-900002.a'; Kind = 'registry DWORD in hex, a split rule'; Title = 'PromptOnSecureDesktop (System) = 0x00000001'; Expect = [ordered]@{ Name = 'PromptOnSecureDesktop'; Op = 'eq'; Value = 1 } }
        @{ Id = 'V-900002.b'; Kind = 'registry string'; Title = 'Label (FVE) = Westmark'; Expect = [ordered]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'; Op = 'eq'; Value = 'Westmark' } }
        @{ Id = 'V-900003'; Kind = 'registry, organization-defined'; Title = 'MaxIdleTime (Terminal Services) between 1 and 900000'; Expect = [ordered]@{ Op = 'between'; Min = 1; Max = 900000 } }
        @{ Id = 'V-900008'; Kind = 'security option'; Title = 'Accounts: Guest account status: Disabled'; Expect = [ordered]@{ Source = 'SecPol'; Name = 'EnableGuestAccount'; Op = 'eq'; Value = 0 } }
        @{ Id = 'V-900012'; Kind = 'service'; Title = 'Service seclogon is Disabled'; Expect = [ordered]@{ Source = 'Service'; Name = 'seclogon'; StartType = 'Disabled' } }
        @{ Id = 'V-900009'; Kind = 'user right'; Title = 'Deny access to this computer from the network: includes Guests, Local account'; Expect = [ordered]@{ Op = 'includes'; Identities = @('Guests', 'Local account') } }
        @{ Id = 'V-900010'; Kind = 'user right, one of a list of values'; Title = 'Debug programs: Administrators, Local account only'; Expect = [ordered]@{ Op = 'only'; Identities = @('Administrators', 'Local account') } }
        @{ Id = 'V-900015'; Kind = 'user right, with alternatives'; Title = 'Back up files and directories: includes Administrators, Backup Operators or Local account'; Expect = [ordered]@{ Op = 'includes'; Identities = @('Administrators', 'Backup Operators|Local account') } }
        @{ Id = 'V-900013'; Kind = 'Windows feature'; Title = 'Feature SMB1Protocol is not installed'; Expect = [ordered]@{ Source = 'Feature'; Name = 'SMB1Protocol'; State = 'Disabled' } }
    ) {
        param($Id, $Title, $Expect)
        $r = Get-Requirement $Stig $Id
        $r.Title | Should -BeExactly $Title
        $r.Expect.Count | Should -Be 1
        foreach ($k in $Expect.Keys) { $r.Expect[0][$k] | Should -Be $Expect[$k] -Because "$Id Expect.$k" }
        $r.Contains('Note') | Should -BeFalse
    }

    It 'allows an unset value where the STIG says the default is compliant' {
        $r = Get-Requirement $Stig 'V-900016'
        $r.Expect[0].AbsentOk | Should -BeTrue
        $r.Expect[0].Value | Should -Be 0
        (Get-Requirement $Stig 'V-900001').Expect[0].Contains('AbsentOk') | Should -BeFalse
    }

    It 'gives a manual rule its named check when the discussion matches' {
        $r = Get-Requirement $Stig 'V-900005'
        $r.Checks | Should -Be @('SC-FirewallEnabled')
        $r.Title | Should -Be 'A firewall provides a line of defense against attack.'
    }

    It 'leaves unmatched manual rules and multi-string values to STIG Viewer' {
        foreach ($id in 'V-900014', 'V-900006') {
            $r = Get-Requirement $Stig $id
            $r.Contains('Expect') | Should -BeFalse
            $r.Note | Should -Be $NotAutomated
        }
    }

    It 'takes levels from the severities' {
        (Get-Requirement $Stig 'V-900010').Level | Should -Be 'CAT I'
        (Get-Requirement $Stig 'V-900014').Level | Should -Be 'CAT III'
    }

    It 'does not apply overrides without a DISA release' {
        (Get-Requirement $Stig 'V-900002.b').Title | Should -Be 'Label (FVE) = Westmark'
    }

    It 'stops on a security policy the mappings do not name' {
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{ "'Accounts: Guest account status' = 'EnableGuestAccount'" = '' }
        { Invoke-Generator -Framework 'DISA-STIG-Sample' -Mappings $maps } | Should -Throw "*V-900008*'Accounts: Guest account status'*"
    }

    It 'stops on named checks for a rule the STIG does not have' {
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{ 'NamedByText = $true' = "Named = @{ 'V-999999' = @{ Checks = @('SC-FirewallEnabled') } }" }
        { Invoke-Generator -Framework 'DISA-STIG-Sample' -Mappings $maps } | Should -Throw '*V-999999*'
    }

    It 'leaves AppliesTo out when the mappings give none' {
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{ '            AppliesTo = @{ ProductTypes = @(1); MinBuild = 22000 }' = '' }
        $run = Invoke-Generator -Framework 'DISA-STIG-Sample' -Mappings $maps
        (Read-Catalog $run.Folder 'disa-stig-sample').Contains('AppliesTo') | Should -BeFalse
    }

    It 'stops when PolicyFallback meets a split rule that is not a policy value and its local setting' {
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{ "            AppliesTo = @{ ProductTypes = @(1); MinBuild = 22000 }" = "            AppliesTo = @{ ProductTypes = @(1); MinBuild = 22000 }`n            PolicyFallback = `$true" }
        { Invoke-Generator -Framework 'DISA-STIG-Sample' -Mappings $maps } | Should -Throw '*PolicyFallback: V-900002 *'
    }

    It 'refuses a framework it does not build' {
        { Invoke-Generator -Framework 'CMMC' } | Should -Throw "*doesn't build CMMC*"
    }
}

Describe 'Joining a policy value with its local setting' {
    BeforeAll {
        $script:Policy = 'HKLM:\SOFTWARE\Policies\Westmark\Firewall'
        $script:Local = 'HKLM:\SYSTEM\CurrentControlSet\Services\Westmark\Firewall'
        function Get-RulePart {
            param([string]$Id, [string]$Path, [string]$Name = 'Enabled')
            New-Requirement $Id 'Config' 'CAT II' "$Name = 1" @() @([ordered]@{ Source = 'Registry'; Path = $Path; Name = $Name; Op = 'eq'; Value = 1 })
        }
    }

    It 'makes one requirement that reads the policy value, then the local setting' {
        $out = Join-PolicyFallback @((Get-RulePart 'V-1.a' $Policy), (Get-RulePart 'V-1.b' $Local), (Get-RulePart 'V-2' $Policy 'Other'))
        @($out | ForEach-Object { $_.Id }) | Should -Be @('V-1', 'V-2')
        $e = $out[0].Expect[0]
        @($e.Keys) | Should -Be @('Source', 'Path', 'FallbackPath', 'Name', 'Op', 'Value')
        $e.Path | Should -Be $Policy
        $e.FallbackPath | Should -Be $Local
        $out[1].Expect[0].Contains('FallbackPath') | Should -BeFalse
    }

    It 'refuses parts that <Case>' -ForEach @(
        @{ Case = 'name different values'; Parts = { @((Get-RulePart 'V-1.a' $Policy), (Get-RulePart 'V-1.b' $Local 'Other')) } }
        @{ Case = 'have no policy value first'; Parts = { @((Get-RulePart 'V-1.a' $Local), (Get-RulePart 'V-1.b' $Policy)) } }
        @{ Case = 'have no local setting'; Parts = { @(, (Get-RulePart 'V-1.a' $Policy)) } }
        @{ Case = 'come in three'; Parts = { @((Get-RulePart 'V-1.a' $Policy), (Get-RulePart 'V-1.b' $Local), (Get-RulePart 'V-1.c' $Local)) } }
    ) {
        { Join-PolicyFallback (& $Parts) } | Should -Throw '*PolicyFallback: V-1 *'
    }
}

Describe 'Values a person must review' {
    BeforeAll {
        $script:Pol = 'HKLM:\SOFTWARE\Policies\Westmark'
        function Get-RegRule {
            param([string]$Id, $Expect)
            $e = [ordered]@{ Source = 'Registry'; Path = $Pol; Name = 'X' }
            foreach ($k in $Expect.Keys) { $e[$k] = $Expect[$k] }
            New-Requirement $Id 'Config' 'CAT II' 'X' @() @($e)
        }
    }

    It 'names <Case>' -ForEach @(
        @{ Case = 'a blank expected value (regression: AllowTelemetry on Server 2025)'; Expect = @{ Op = 'eq'; Value = '' }; Raw = "Value Name: AllowTelemetry`nType: REG_DWORD`nValue0x00000000 (0), 0x00000001 (1)"; Want = 'V-1: no expected value' }
        @{ Case = 'a check that lists several values'; Expect = @{ Op = 'eq'; Value = 0 }; Raw = "Value: 0x00000000 (0) - No peering`n0x00000001 (1) - LAN`nA value of 0x00000003 (3) is a finding."; Want = 'V-1: the check lists several values' }
        @{ Case = 'a check waived when another rule is met'; Expect = @{ Op = 'eq'; Value = 0 }; Raw = 'If WN25-00-000380 is configured, this is not applicable. Value: 0x00000000 (0)'; Want = 'V-1: the check is waived when another rule is met' }
    ) {
        @(Get-UnreviewedValue @(Get-RegRule 'V-1' $Expect) @{ 'V-1' = $Raw } @(@{})) | Should -Be @($Want)
    }

    It 'passes <Case>' -ForEach @(
        @{ Case = 'one value'; Expect = @{ Op = 'eq'; Value = 1 }; Raw = 'Value: 0x00000001 (1)' }
        @{ Case = 'several values already read as a list'; Expect = @{ Op = 'in'; Values = @(0, 1) }; Raw = 'Value: 0x00000000 (0), 0x00000001 (1)' }
        @{ Case = 'a waiver with no other rule named'; Expect = @{ Op = 'eq'; Value = 1 }; Raw = 'If the system writes events to an audit server, this is NA. Value: 0x00000001 (1)' }
    ) {
        @(Get-UnreviewedValue @(Get-RegRule 'V-1' $Expect) @{ 'V-1' = $Raw } @(@{})).Count | Should -Be 0
    }

    It 'takes a correction that sets Expect or NotApplicableIf, and only that, as reviewed' {
        $rule = Get-RegRule 'V-1' @{ Op = 'eq'; Value = 0 }
        $raw = @{ 'V-1' = 'If WN25-00-000380 is configured, this is NA. Value: 0x00000000 (0), 0x00000001 (1)' }
        @(Get-UnreviewedValue @($rule) $raw @(@{ 'V-1' = @{ Expect = @(); NotApplicableIf = @('V-2') } })).Count | Should -Be 0
        @(Get-UnreviewedValue @($rule) $raw @(@{}, @{ 'V-1' = @{ Expect = @() } })) | Should -Be @('V-1: the check is waived when another rule is met')
        @(Get-UnreviewedValue @($rule) $raw @(@{ 'V-1' = @{ DomainOnly = $true } })).Count | Should -Be 2
    }
}

Describe 'Corrections' {
    BeforeAll {
        $script:Fix = "            NamedByText = `$true`n            Corrections = @{`n" +
            "                'V-900001' = @{ Reason = 'Two values.'; Title = 'EnableLUA (System) in 1/2'; Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\X'; Name = 'EnableLUA'; Op = 'in'; Values = @(1, 2) }) }`n" +
            "                'V-900016' = @{ Reason = 'NA when SMBv1 is removed.'; NotApplicableIf = @('V-900013', 'V-900001') }`n" +
            "                'V-900002.a' = @{ Reason = 'Standalone only.'; StandaloneOnly = `$true }`n" +
            "            }"
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{ "            NamedByText = `$true" = $Fix }
        $script:Run = Invoke-Generator -Framework 'DISA-STIG-Sample' -Mappings $maps
        $script:Stig = Read-Catalog $Run.Folder 'disa-stig-sample'
    }

    It "applies on PowerStig's release, without a DISA release" {
        $r = Get-Requirement $Stig 'V-900001'
        $r.Title | Should -Be 'EnableLUA (System) in 1/2'
        @($r.Expect[0].Values) | Should -Be @(1, 2)
        (Get-Requirement $Stig 'V-900002.a').Expect[0].StandaloneOnly | Should -BeTrue
    }

    It 'copies the final expectations of the rules a waiver names' {
        $w = (Get-Requirement $Stig 'V-900016').Expect[0].NotApplicableIf
        @($w.Rules) | Should -Be @('V-900013', 'V-900001')
        $w.Expect[0].Source | Should -Be 'Feature'
        $w.Expect[0].Name | Should -Be 'SMB1Protocol'
        @($w.Expect[1].Values) | Should -Be @(1, 2)
        (Get-Requirement $Stig 'V-900013').Expect[0].Contains('NotApplicableIf') | Should -BeFalse
    }

    It 'refuses a waiver <Case>' -ForEach @(
        @{ Case = 'on a rule without expectations'; Line = "'V-900005' = @{ NotApplicableIf = @('V-900013') }"; Want = '*waives V-900005*no expectations*' }
        @{ Case = 'naming a rule without expectations'; Line = "'V-900001' = @{ NotApplicableIf = @('V-900014') }"; Want = '*V-900014 has no expectations*' }
    ) {
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{ "            NamedByText = `$true" = "            NamedByText = `$true`n            Corrections = @{ $Line }" }
        { Invoke-Generator -Framework 'DISA-STIG-Sample' -Mappings $maps } | Should -Throw $Want
    }
}

Describe 'STIG catalog following a DISA release' {
    BeforeAll {
        $script:Run = Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture
        $script:Stig = Read-Catalog $Run.Folder 'disa-stig-sample'
        # The same release without the catalog's override.
        $plainMaps = Copy-FixtureMapping 'disa-stig.psd1' @{
            "            Overrides = @{`n                'V-900002.b' = @{`n                    Reason = 'The DISA release moved the BitLocker part to its own rule.'`n                    MoveTo = 'V-900004'`n                }`n            }`n" = ''
        }
        $script:PlainRun = Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings $plainMaps
        $script:Plain = Read-Catalog $PlainRun.Folder 'disa-stig-sample'
    }

    It "takes DISA's version, release and rule list" {
        $Stig.Name | Should -Be 'DISA Westmark Sample STIG V1R3'
        @($Plain.Requirements | ForEach-Object { $_.Id }) | Should -Be @('V-900005', 'V-900001', 'V-900002.a', 'V-900002.b', 'V-900003', 'V-900004')
        $PlainRun.Results[0].Note | Should -BeLike '*DISA V1R3, PowerStig Sample-1.2: 1 new rule(s) Manual, 11 retired rule(s) dropped (V-900007, *'
    }

    It 'takes levels from DISA, by the base Vuln ID for split rules' {
        (Get-Requirement $Plain 'V-900002.a').Level | Should -Be 'CAT I'
        (Get-Requirement $Plain 'V-900002.b').Level | Should -Be 'CAT I'
    }

    It "adds a rule new in the release as Manual, titled from DISA's rule title" {
        $r = Get-Requirement $Plain 'V-900004'
        $r.Title | Should -Be 'A rule the catalog does not have.'
        $r.Level | Should -Be 'CAT II'
        $r.Note | Should -BeLike 'New in Sample Westmark STIG V1R3 and not automated yet*'
        $r.Contains('Expect') | Should -BeFalse
    }

    It "keeps PowerStig's automation for rules DISA still has" {
        (Get-Requirement $Plain 'V-900001').Expect[0].Name | Should -Be 'EnableLUA'
        (Get-Requirement $Plain 'V-900005').Checks | Should -Be @('SC-FirewallEnabled')
    }

    It 'warns about automated rules whose check DISA reworded' {
        $PlainRun.Results[0].Reworded | Should -Be @('V-900002.b', 'V-900003')
        @($PlainRun.Warnings | Where-Object { $_ -like '*reworded*V-900002.b, V-900003' }).Count | Should -Be 1
    }

    It 'moves a split part to the Vuln ID DISA gave it, with its level, and stops warning about it' {
        @($Stig.Requirements | ForEach-Object { $_.Id }) | Should -Be @('V-900005', 'V-900001', 'V-900002.a', 'V-900004', 'V-900003')
        $r = Get-Requirement $Stig 'V-900004'
        $r.Title | Should -Be 'Label (FVE) = Westmark'
        $r.Level | Should -Be 'CAT II'
        $r.Expect[0].Value | Should -Be 'Westmark'
        $Run.Results[0].Reworded | Should -Be @('V-900003')
        $Run.Results[0].Note | Should -BeLike '*0 new rule(s) Manual*'
    }

    It 'replaces the fields an override names' {
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{ "                    MoveTo = 'V-900004'" = "                    MoveTo = 'V-900004'`n                }`n                'V-900003' = @{`n                    Title = 'Idle limit'`n                    Expect = @(@{ Source = 'Registry'; Path = 'HKLM:\X'; Name = 'MaxIdleTime'; Op = 'between'; Min = 1; Max = 600000 })" }
        $run = Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings $maps
        $r = Get-Requirement (Read-Catalog $run.Folder 'disa-stig-sample') 'V-900003'
        $r.Title | Should -Be 'Idle limit'
        $r.Expect[0].Max | Should -Be 600000
        $run.Results[0].Reworded.Count | Should -Be 0
    }

    It 'marks every expectation of a DomainOnly override, and refuses one on a rule without expectations' {
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{ "                    MoveTo = 'V-900004'" = "                    MoveTo = 'V-900004'`n                }`n                'V-900002.a' = @{`n                    Reason = 'Not applicable off a domain.'`n                    DomainOnly = `$true" }
        $run = Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings $maps
        $r = Get-Requirement (Read-Catalog $run.Folder 'disa-stig-sample') 'V-900002.a'
        $r.Expect[0].DomainOnly | Should -BeTrue
        (Get-Requirement (Read-Catalog $run.Folder 'disa-stig-sample') 'V-900001').Expect[0].Contains('DomainOnly') | Should -BeFalse
        $manual = Copy-FixtureMapping 'disa-stig.psd1' @{ "                    MoveTo = 'V-900004'" = "                    MoveTo = 'V-900004'`n                }`n                'V-900005' = @{`n                    DomainOnly = `$true" }
        { Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings $manual } | Should -Throw '*V-900005 DomainOnly*no expectations*'
    }

    It 'follows the DISA benchmark the catalog names, not only PowerStig''s ID' {
        $other = Copy-FixtureMapping 'disa-stig.psd1' @{ "            NamedByText = `$true" = "            DisaBenchmark = 'Another_Westmark_STIG'`n            NamedByText = `$true" }
        $run = Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings $other
        (Read-Catalog $run.Folder 'disa-stig-sample').Name | Should -Be 'DISA Westmark Sample STIG V1R2'
        $same = Copy-FixtureMapping 'disa-stig.psd1' @{ "            NamedByText = `$true" = "            DisaBenchmark = 'Sample_Westmark_STIG'`n            NamedByText = `$true" }
        $run = Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings $same
        (Read-Catalog $run.Folder 'disa-stig-sample').Name | Should -Be 'DISA Westmark Sample STIG V1R3'
    }

    It "leaves out the rules DISA's STIG IDs mark as for the other server role" {
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{
            "            NamedByText = `$true" = "            NotForRole = '^WM-00-00000[34]`$'`n            NamedByText = `$true"
            "                    MoveTo = 'V-900004'" = "                    MoveTo = 'V-900005'"
        }
        $run = Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings $maps
        $ids = @((Read-Catalog $run.Folder 'disa-stig-sample').Requirements | ForEach-Object { $_.Id })
        $ids | Should -Not -Contain 'V-900003'
        $ids | Should -Not -Contain 'V-900004'
        $run.Results[0].Note | Should -BeLike '*1 rule(s) now for the other role only (V-900003)'
    }

    It 'stops on an override for a rule the release does not have' {
        $maps = Copy-FixtureMapping 'disa-stig.psd1' @{ "'V-900002.b' = @{" = "'V-900006' = @{" }
        { Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings $maps } | Should -Throw '*overrides V-900006*'
    }

    It 'stops warning about reworded rules reviewed against this release, and only this release' {
        $reviewed = @{ "            NamedByText = `$true" = "            NamedByText = `$true`n            Reviewed = @{ Release = 'V1R3'; Rules = @('V-900003') }" }
        $run = Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings (Copy-FixtureMapping 'disa-stig.psd1' $reviewed)
        $run.Results[0].Reworded.Count | Should -Be 0
        $run.Warnings.Count | Should -Be 0
        $stale = @{ "            NamedByText = `$true" = "            NamedByText = `$true`n            Reviewed = @{ Release = 'V1R2'; Rules = @('V-900003') }" }
        $run = Invoke-Generator -Framework 'DISA-STIG-Sample' -StigPath $DisaFixture -Mappings (Copy-FixtureMapping 'disa-stig.psd1' $stale)
        $run.Results[0].Reworded | Should -Be @('V-900003')
    }
}

Describe 'Generated output' {
    BeforeAll {
        $script:Run = Invoke-Generator
    }

    It 'builds every catalog in the mappings by default' {
        @($Run.Results | ForEach-Object { $_.File }) | Should -Be @('nist-800-171r3.psd1', 'nist-800-53r5.psd1', 'nist-csf-2.0.psd1', 'disa-stig-sample.psd1')
    }

    It 'writes <_> as ASCII with LF line ends and no BOM' -ForEach @('nist-800-171r3', 'nist-800-53r5', 'nist-csf-2.0', 'disa-stig-sample') {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $Run.Folder "$_.psd1"))
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
        $bytes -contains 13 | Should -BeFalse
        $bytes[-1] | Should -Be 10
    }

    It 'writes catalogs the scanner loads and evaluates' {
        # In a separate process, so the scanner's functions stay out of this one.
        $out = Get-TestFolder
        Get-ChildItem -LiteralPath $Run.Folder -Filter '*.psd1' | Copy-Item -Destination $out
        $job = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -Command {
            param($ScriptPath, $Folder, $Fixture, $Example)
            $ErrorActionPreference = 'Stop'
            . $ScriptPath
            foreach ($c in @(Get-FrameworkCatalog $Folder)) {
                $t = Get-ScanThreshold -ExamplePath $Example -Catalog $c
                $e = Invoke-ComplianceEvaluation -Snapshot (Read-Snapshot $Fixture) -Thresholds $t -Catalog $c -Level ''
                "$($c.Id)=$(@($e.Requirements).Count)/$(@($c.Requirements).Count)"
            }
        } -args (Join-Path $Root 'Invoke-EndpointComplianceScan.ps1'), $out, (Join-Path $PSScriptRoot 'fixtures/compliant.json'), (Join-Path $Root 'ComplianceScan.example.psd1')
        $LASTEXITCODE | Should -Be 0
        @($job) | Should -Be @('DISA-STIG-Sample=16/16', 'NIST-800-171r3=3/3', 'NIST-800-53r5=3/3', 'NIST-CSF-2.0=2/2')
    }

    It 'reports an unchanged catalog as unchanged and leaves it alone' {
        $path = Join-Path $Run.Folder 'nist-csf-2.0.psd1'
        $before = (Get-Item -LiteralPath $path).LastWriteTimeUtc
        $again = @(& $Generator -Framework 'NIST-CSF-2.0' -MappingPath $FixtureMappings -SourcePath $FixtureSources -Offline -OutputPath $Run.Folder -CachePath (Join-Path $Run.Folder 'cache'))
        $again[0].Changed | Should -BeFalse
        (Get-Item -LiteralPath $path).LastWriteTimeUtc | Should -Be $before
    }

    It 'writes nothing with -WhatIf' {
        $run = Invoke-Generator -Framework 'NIST-CSF-2.0' -DryRun
        $run.Results[0].Changed | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $run.Folder 'nist-csf-2.0.psd1') | Should -BeFalse
    }
}

Describe "The project's mappings" {
    BeforeAll {
        $script:Mappings = Join-Path $Root 'tools/mappings'
        $script:SourceData = Read-DataFile (Join-Path $Mappings 'sources.psd1')
        $script:StigData = Read-DataFile (Join-Path $Mappings 'disa-stig.psd1')
        $scannerAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'Invoke-EndpointComplianceScan.ps1'), [ref]$null, [ref]$null)
        # Check names, from the scanner's check table, without running the scanner.
        $table = $scannerAst.Find({ param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Get-CheckTable' }, $true)
        $script:CheckNames = @([regex]::Matches($table.Extent.Text, "(?m)^\s*'([A-Z]{2}-[A-Za-z0-9]+)'\s*=") | ForEach-Object { $_.Groups[1].Value })
    }

    It 'finds the check names in the scanner' {
        $CheckNames.Count | Should -BeGreaterThan 30
        $CheckNames | Should -Contain 'SC-FirewallEnabled'
    }

    It 'read as data: <_>' -ForEach @('sources.psd1', 'disa-stig.psd1', 'nist-800-171r3.psd1', 'nist-800-53r5.psd1', 'nist-csf-2.0.psd1') {
        { Read-DataFile (Join-Path $Mappings $_) } | Should -Not -Throw
    }

    It 'name only checks the scanner has' {
        $named = [Collections.Generic.List[string]]::new()
        foreach ($f in 'nist-800-171r3.psd1', 'nist-800-53r5.psd1', 'nist-csf-2.0.psd1') {
            foreach ($v in (Read-DataFile (Join-Path $Mappings $f)).Checks.Values) { foreach ($n in $v) { $named.Add($n) } }
        }
        foreach ($n in $StigData.NamedByText) { foreach ($c in $n.Checks) { $named.Add($c) } }
        foreach ($cat in $StigData.Catalogs) {
            if ($cat.Contains('Named')) { foreach ($v in $cat.Named.Values) { foreach ($c in $v.Checks) { $named.Add($c) } } }
        }
        $named.Count | Should -BeGreaterThan 50
        @($named | Where-Object { $CheckNames -notcontains $_ } | Select-Object -Unique) | Should -BeNullOrEmpty
    }

    It 'pin both PowerStig files of every STIG catalog' {
        $pinned = @($SourceData.PowerStig.Files | ForEach-Object { $_.Name })
        foreach ($cat in $StigData.Catalogs) {
            $pinned | Should -Contain "$($cat.PowerStig).xml"
            $pinned | Should -Contain "$($cat.PowerStig).org.default.xml"
        }
    }

    It 'pin every source file by a SHA-256' {
        $files = @($SourceData.Oscal.Files) + @($SourceData.PowerStig.Files) + @($SourceData.Disa)
        $files.Count | Should -BeGreaterThan 15
        @($files | Where-Object { $_.Sha256 -notmatch '^[0-9a-f]{64}$' }).Count | Should -Be 0
    }

    It 'give every source more than one place to come from' {
        @($SourceData.Oscal.Mirrors).Count | Should -BeGreaterThan 1
        @($SourceData.PowerStig.Mirrors).Count + [int][bool]$SourceData.PowerStig.Package | Should -BeGreaterThan 1
    }

    It 'give every override and correction a reason' {
        foreach ($cat in $StigData.Catalogs) {
            foreach ($kind in 'Overrides', 'Corrections') {
                if (-not $cat.Contains($kind)) { continue }
                foreach ($id in $cat[$kind].Keys) { $cat[$kind][$id].Reason | Should -Not -BeNullOrEmpty -Because "$($cat.Id) $kind $id" }
            }
        }
    }
}
