# Pester tests for Invoke-EndpointComplianceScan.ps1. No network, no elevation,
# no Windows needed: every check is fed a fixture snapshot, never the machine.
#
# Run through ..\Test-ComplianceScan.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeDiscovery {
    # Test cases are built from the script's own registry targets and catalogs.
    $discoveryRoot = Split-Path $PSScriptRoot -Parent
    . (Join-Path $discoveryRoot 'Invoke-EndpointComplianceScan.ps1')
    $script:FrameworkCases = @(Get-FrameworkCatalog (Join-Path $discoveryRoot 'frameworks') | ForEach-Object { @{ Id = $_.Id } })
}

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:ScriptPath = Join-Path $Root 'Invoke-EndpointComplianceScan.ps1'
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures/compliant.json'
    . $ScriptPath

    $script:Catalogs = @(Get-FrameworkCatalog (Join-Path $Root 'frameworks'))
    $script:Catalog = Resolve-Framework $Catalogs 'CMMC'
    $script:ExamplePath = Join-Path $Root 'ComplianceScan.example.psd1'

    function Get-Fixture { Read-Snapshot $FixturePath }
    function Get-Threshold { param($For = $Catalog) Get-ScanThreshold -ExamplePath $ExamplePath -Catalog $For }
    function Get-Framework { param([string]$Id) Resolve-Framework $Catalogs $Id }

    function Write-RegFact {
        # Sets a registry fact; $null makes the value absent.
        param($Snapshot, [string]$Key, $Value)
        $f = $Snapshot.Registry.$Key
        if ($null -eq $f) { throw "Fixture has no registry entry '$Key'." }
        $f.Present = $null -ne $Value
        $f.Value = $Value
    }

    function Get-CheckState {
        param($Snapshot, [string]$Check, $Thresholds = (Get-Threshold))
        $table = Get-CheckTable
        Invoke-Check -Name $Check -Definition $table[$Check] -Snapshot $Snapshot -Thresholds $Thresholds
    }

    function Invoke-Evaluation {
        param($Snapshot, $Thresholds = (Get-Threshold), [string]$Level = 'L2', $For = $Catalog)
        Invoke-ComplianceEvaluation -Snapshot $Snapshot -Thresholds $Thresholds -Catalog $For -Level $Level
    }

    function Write-Fact {
        # Adds or replaces one property on a snapshot section read from JSON.
        param($Section, [string]$Name, $Value)
        if ($Section.PSObject.Properties[$Name]) { $Section.$Name = $Value }
        else { $Section | Add-Member -NotePropertyName $Name -NotePropertyValue $Value }
    }

    function Get-SatisfyingValue {
        # A value that meets one expectation's Op.
        param($Expect)
        switch ($Expect.Op) {
            'eq' { return $Expect.Value }
            'ne' { return "not-$($Expect.Value)" }
            'ge' { return $Expect.Value }
            'between' { return $Expect.Max }
            'in' { return @($Expect.Values)[0] }
            'notempty' { return 'Authorized use only.' }
        }
        throw "No satisfying value for Op '$($Expect.Op)'."
    }

    function Get-IdentityEntry {
        # A user-rights entry for one catalog identity, as the collector records it.
        param([string]$Identity)
        $sid = "$($IdentitySid[$Identity])".Replace('*', '1000000011-1000000012-1000000013')
        $name = if ($Identity.Contains('\')) { $Identity } else { "WESTMARK\$Identity" }
        [pscustomobject]@{ Sid = $sid; Name = $name }
    }

    function Get-CompliantSnapshot {
        # The fixture plus a fact that meets every expectation in one catalog.
        param($For)
        $s = Get-Fixture
        $rightsSet = @{}
        foreach ($r in @($For.Requirements | Where-Object { $_.Contains('Expect') })) {
            foreach ($e in @($r.Expect)) {
                switch ($e.Source) {
                    'Registry' {
                        Write-Fact $s.Registry "$($e.Path)\$($e.Name)" ([pscustomobject]@{ Present = $true; Value = (Get-SatisfyingValue $e); Denied = $false })
                    }
                    'SecPol' { Write-Fact $s.SecurityPolicy $e.Name (Get-SatisfyingValue $e) }
                    'Audit' {
                        $guid = $AuditSubcategoryGuid[$e.Subcategory]
                        $now = 0
                        if ($s.AuditPolicy.PSObject.Properties[$guid]) { $now = [int]$s.AuditPolicy.$guid }
                        Write-Fact $s.AuditPolicy $guid ($now -bor $AuditBits[$e.Setting])
                    }
                    'UserRight' {
                        # The first expectation on a right replaces the fixture's holders; later ones add to them.
                        $held = @()
                        if ($rightsSet.ContainsKey($e.Name)) { $held = @($s.UserRights.($e.Name)) }
                        foreach ($i in @($e.Identities)) {
                            $first = @("$i" -split '\|')[0]
                            if (@($held | Where-Object { Test-IdentityMatch $_ @($first) }).Count -eq 0) { $held += Get-IdentityEntry $first }
                        }
                        Write-Fact $s.UserRights $e.Name @($held)
                        $rightsSet[$e.Name] = $true
                    }
                    'Service' { Write-Fact $s.Services $e.Name ([pscustomobject]@{ Present = $true; StartType = $e.StartType; Status = 'Stopped' }) }
                    'Feature' { Write-Fact $s.Features $e.Name ([pscustomobject]@{ Present = $true; State = $e.State }) }
                    'Local' {
                        # A PAW allows local logon to Administrators and designated groups only.
                        if ($e.Name -eq 'LocalLogonHolders') { Write-Fact $s.UserRights 'SeInteractiveLogonRight' @(Get-IdentityEntry 'Administrators') }
                    }
                }
            }
        }
        return $s
    }

    function Test-ExpectOn {
        # Runs one expectation against the fixture after $Mutate.
        param($Expect, [scriptblock]$Mutate = {})
        $s = Get-Fixture
        & $Mutate $s
        Invoke-Expectation -Expect $Expect -Snapshot $s
    }

    $script:Sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $script:TsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $script:Lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $script:Explorer = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
}

Describe 'Every framework catalog: <Id>' -ForEach $script:FrameworkCases {
    BeforeAll {
        $script:Fw = Get-Framework $Id
        $script:Known = @((Get-CheckTable).Keys)
        $script:Ops = @{ eq = 'Value'; ne = 'Value'; ge = 'Value'; between = 'Min', 'Max'; in = 'Values'; notempty = @() }
    }

    It 'has the metadata the scanner reads' {
        foreach ($k in 'Id', 'Name', 'Source', 'Levels', 'Complete', 'Thresholds', 'Requirements') {
            $Fw.Contains($k) | Should -BeTrue -Because "key $k"
        }
        $Fw.Complete | Should -BeOfType [bool]
        @($Fw.Levels).Count | Should -BeGreaterThan 0
        @($Fw.Requirements).Count | Should -BeGreaterThan 0
        $Fw.Source | Should -Match '^https://'
    }

    It 'lists each requirement once' {
        $ids = @($Fw.Requirements | ForEach-Object { $_.Id })
        @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'gives each requirement a family, a known level and a title' {
        foreach ($r in $Fw.Requirements) {
            "$($r.Family)" | Should -Not -BeNullOrEmpty -Because "requirement $($r.Id)"
            @($Fw.Levels) | Should -Contain $r.Level -Because "requirement $($r.Id)"
            "$($r.Title)" | Should -Not -BeNullOrEmpty -Because "requirement $($r.Id)"
        }
    }

    It 'names only checks that exist' {
        foreach ($r in $Fw.Requirements) {
            foreach ($c in @($r.Checks)) { $Known | Should -Contain $c -Because "requirement $($r.Id)" }
        }
    }

    It 'writes every expectation in a shape the scanner reads' {
        foreach ($r in @($Fw.Requirements | Where-Object { $_.Contains('Expect') })) {
            $because = "requirement $($r.Id)"
            @($r.Expect).Count | Should -BeGreaterThan 0 -Because $because
            foreach ($e in @($r.Expect)) {
                $ExpectSection.Keys | Should -Contain $e.Source -Because $because
                switch ($e.Source) {
                    'Registry' {
                        $e.Path | Should -Match '^HK(LM|CU):\\' -Because $because
                        "$($e.Name)" | Should -Not -BeNullOrEmpty -Because $because
                    }
                    'SecPol' { "$($e.Name)" | Should -Not -BeNullOrEmpty -Because $because }
                    'Audit' {
                        $AuditSubcategoryGuid.Keys | Should -Contain $e.Subcategory -Because $because
                        $AuditBits.Keys | Should -Contain $e.Setting -Because $because
                    }
                    'Service' { $e.StartType | Should -BeIn 'Disabled', 'Manual', 'Automatic' -Because $because }
                    'Feature' { $e.State | Should -Be 'Disabled' -Because $because }
                    'Directory' { @($DirectoryTest.Keys) | Should -Contain $e.Name -Because $because }
                    'Local' { @($LocalTest.Keys) | Should -Contain $e.Name -Because $because }
                    'UserRight' {
                        $e.Name | Should -Match '^Se\w+(Privilege|Right)$' -Because $because
                        $e.Op | Should -BeIn 'only', 'includes' -Because $because
                        $e.Contains('Identities') | Should -BeTrue -Because $because
                        if ($e.Op -eq 'includes') { @($e.Identities).Count | Should -BeGreaterThan 0 -Because $because }
                        foreach ($i in @($e.Identities | ForEach-Object { "$_" -split '\|' })) {
                            $i | Should -Not -BeNullOrEmpty -Because $because
                            # An identity without a well-known SID is matched by its full account name.
                            if (-not $IdentitySid.ContainsKey($i)) { $i | Should -Match '\\' -Because "$because, identity '$i'" }
                        }
                    }
                }
                if ($e.Source -in 'Registry', 'SecPol') {
                    $Ops.Keys | Should -Contain $e.Op -Because $because
                    foreach ($field in @($Ops[$e.Op])) { $e.Contains($field) | Should -BeTrue -Because "$because needs $field for $($e.Op)" }
                }
            }
        }
    }

    It 'gives every requirement without evidence a note on where to look' {
        foreach ($r in @($Fw.Requirements | Where-Object { @($_.Checks).Count -eq 0 -and -not $_.Contains('Expect') })) {
            "$($r.Note)" | Should -Not -BeNullOrEmpty -Because "requirement $($r.Id) has no checks"
        }
    }

    It 'names the Windows it was written for in a shape the scanner reads, if it names one' {
        # The operating system STIGs name their Windows; the Firewall STIG applies to any.
        if ($Fw.Id -like 'DISA-STIG-*' -and $Fw.Id -ne 'DISA-STIG-Firewall') { $Fw.Contains('AppliesTo') | Should -BeTrue }
        if ($Fw.Contains('AppliesTo')) {
            $keys = @($Fw.AppliesTo.Keys)
            $keys.Count | Should -BeGreaterThan 0
            foreach ($k in $keys) { $k | Should -BeIn 'ProductTypes', 'Builds', 'MinBuild' }
            $a = $Fw.AppliesTo
            if ($a.Contains('ProductTypes')) { foreach ($t in @($a.ProductTypes)) { $t | Should -BeIn 1, 2, 3 } }
            if ($a.Contains('Builds')) { foreach ($b in @($a.Builds)) { $b | Should -BeOfType [int] } }
            if ($a.Contains('MinBuild')) { $a.MinBuild | Should -BeOfType [int] }
        }
    }

    It 'sets only thresholds the example file knows' {
        $known = (Import-PowerShellDataFile -LiteralPath $ExamplePath).Keys
        foreach ($k in $Fw.Thresholds.Keys) { $known | Should -Contain $k }
    }

    It 'passes, or leaves to manual review, every requirement on a snapshot that meets it' {
        $e = Invoke-Evaluation (Get-CompliantSnapshot $Fw) -Thresholds (Get-Threshold $Fw) -Level $null -For $Fw
        @($e.Requirements).Count | Should -Be @($Fw.Requirements).Count
        $bad = @($e.Requirements | Where-Object { $_.State -notin 'Pass', 'Manual', 'NotApplicable' } |
            ForEach-Object { "$($_.Reference)=$($_.State): $($_.Findings)" })
        $bad | Should -BeNullOrEmpty
        Get-ScanExitCode $e.Requirements | Should -Be 0
    }
}

Describe 'Framework catalogs' {
    It 'has the published number of requirements in <Id>' -ForEach @(
        @{ Id = 'CMMC'; Count = 110 }
        @{ Id = 'NIST-800-171r3'; Count = 97 }
        @{ Id = 'NIST-800-53r5'; Count = 287 }
        @{ Id = 'NIST-CSF-2.0'; Count = 106 }
        @{ Id = 'DISA-STIG-Win11'; Count = 276 }
        @{ Id = 'DISA-STIG-WS2019-MS'; Count = 247 }
        @{ Id = 'DISA-STIG-WS2019-DC'; Count = 277 }
        @{ Id = 'DISA-STIG-WS2022-MS'; Count = 242 }
        @{ Id = 'DISA-STIG-WS2022-DC'; Count = 271 }
        @{ Id = 'DISA-STIG-WS2025-MS'; Count = 258 }
        @{ Id = 'DISA-STIG-WS2025-DC'; Count = 288 }
        @{ Id = 'DISA-STIG-Firewall'; Count = 21 }
        @{ Id = 'DISA-STIG-AD-Domain'; Count = 36 }
        @{ Id = 'DISA-STIG-AD-Forest'; Count = 7 }
        @{ Id = 'DISA-STIG-PAW'; Count = 24 }
    ) {
        @((Get-Framework $Id).Requirements).Count | Should -Be $Count
        (Get-Framework $Id).Complete | Should -BeTrue
    }

    It 'marks the partial catalogs as partial' {
        foreach ($id in 'CIS-v8.1', 'PCI-DSS-4.0.1') { (Get-Framework $id).Complete | Should -BeFalse -Because $id }
    }

    It 'lists every HIPAA Security Rule standard and implementation specification' {
        $hipaa = Get-Framework 'HIPAA'
        $hipaa.Complete | Should -BeTrue
        $ids = @($hipaa.Requirements.Id)
        $ids.Count | Should -Be 65
        @($ids | Select-Object -Unique).Count | Should -Be 65
        @($ids | Where-Object { $_ -like '164.308*' }).Count | Should -Be 30
        @($ids | Where-Object { $_ -like '164.310*' }).Count | Should -Be 12
        @($ids | Where-Object { $_ -like '164.312*' }).Count | Should -Be 12
        @($ids | Where-Object { $_ -like '164.314*' }).Count | Should -Be 6
        @($ids | Where-Object { $_ -like '164.316*' }).Count | Should -Be 5
        foreach ($r in $hipaa.Requirements) { $r.Title | Should -Match '\((standard|required|addressable)\)$' -Because $r.Id }
    }

    It 'marks only the retired Server 2019 STIGs as retired' {
        foreach ($c in $Catalogs) {
            $retired = $c.Contains('Retired')
            $retired | Should -Be ($c.Id -like 'DISA-STIG-WS2019-*') -Because $c.Id
            if ($retired) { "$($c.Retired)" | Should -Match 'V3R8' }
        }
    }

    It 'uses every check in at least one framework' {
        $used = @($Catalogs | ForEach-Object { $_.Requirements } | ForEach-Object { @($_.Checks) }) | Select-Object -Unique
        foreach ($c in (Get-CheckTable).Keys) { $used | Should -Contain $c }
    }

    It 'checks local accounts on no domain controller STIG, where there are none' {
        foreach ($c in @($Catalogs | Where-Object { $_.Contains('AppliesTo') -and @($_.AppliesTo.ProductTypes) -contains 2 })) {
            $table = Get-CheckTable
            $used = @($c.Requirements | ForEach-Object { @($_.Checks) } | Where-Object { $_ })
            foreach ($n in $used) { @($table[$n].Needs) | Should -Not -Contain 'LocalAccounts' -Because "$($c.Id) uses $n" }
        }
    }

    It 'knows every audit subcategory any catalog or the example names' {
        $names = @((Import-PowerShellDataFile -LiteralPath $ExamplePath).AuditSubcategories | ForEach-Object { $_.Name })
        foreach ($n in $names) { $AuditSubcategoryGuid.Keys | Should -Contain $n }
    }

    It 'collects every registry value, service and feature any catalog expects, waivers included' {
        $t = Get-CollectionTarget -Catalogs $Catalogs -Thresholds (Get-Threshold)
        $waivers = 0
        foreach ($c in $Catalogs) {
            $expects = @($c.Requirements | Where-Object { $_.Contains('Expect') } | ForEach-Object { $_.Expect })
            $nested = @($expects | Where-Object { $_.Contains('NotApplicableIf') } | ForEach-Object { $_.NotApplicableIf.Expect })
            $waivers += $nested.Count
            foreach ($e in @($expects + $nested)) {
                switch ($e.Source) {
                    'Registry' {
                        $t.Registry.Contains("$($e.Path)\$($e.Name)") | Should -BeTrue
                        if ($e.Contains('FallbackPath')) { $t.Registry.Contains("$($e.FallbackPath)\$($e.Name)") | Should -BeTrue }
                    }
                    'Service' { $t.Services | Should -Contain $e.Name }
                    'Feature' { $t.Features | Should -Contain $e.Name }
                }
            }
        }
        foreach ($k in Get-RegistryTarget) { $t.Registry.Contains($k) | Should -BeTrue }
        $waivers | Should -BeGreaterThan 0
    }

    It 'expects a value in every registry expectation (regression: a blank AllowTelemetry on Server 2025)' {
        foreach ($c in $Catalogs) {
            foreach ($e in @($c.Requirements | Where-Object { $_.Contains('Expect') } | ForEach-Object { $_.Expect } | Where-Object { $_.Source -eq 'Registry' -and $_.Contains('Value') })) {
                "$($e.Value)" | Should -Not -BeNullOrEmpty -Because "$($c.Id) $($e.Name)"
            }
        }
    }

    It 'waives only with rules of the same catalog, and copies their expectations' {
        foreach ($c in $Catalogs) {
            foreach ($r in @($c.Requirements | Where-Object { $_.Contains('Expect') })) {
                foreach ($e in @($r.Expect | Where-Object { $_.Contains('NotApplicableIf') })) {
                    $copied = @($e.NotApplicableIf.Expect)
                    $named = @(foreach ($id in @($e.NotApplicableIf.Rules)) {
                            $other = @($c.Requirements | Where-Object { $_.Id -eq $id })
                            $other.Count | Should -Be 1 -Because "$($c.Id) $($r.Id) names $id"
                            @($other[0].Expect)
                        })
                    $copied.Count | Should -Be $named.Count -Because "$($c.Id) $($r.Id)"
                }
            }
        }
    }

    It 'keeps a backslash in a registry value name apart from the path' {
        $t = Get-CollectionTarget -Catalogs $Catalogs -Thresholds (Get-Threshold)
        $hardened = @($t.Registry.Values | Where-Object { $_.Name -like '\\*' })
        $hardened.Count | Should -BeGreaterThan 0
        foreach ($h in $hardened) { $h.Path | Should -Match 'HardenedPaths$' }
    }

    It 'reads catalogs as data only' {
        $path = Join-Path $TestDrive 'evil.psd1'
        Set-Content -LiteralPath $path -Value "@{ Id = (Get-Date) }"
        { Import-CatalogFile $path } | Should -Throw
    }
}

Describe 'CMMC catalog' {
    It 'has the right number of requirements in each family' {
        $expected = @{ AC = 22; AT = 3; AU = 9; CM = 9; IA = 11; IR = 3; MA = 6; MP = 9; PS = 2; PE = 6; RA = 3; CA = 4; SC = 16; SI = 7 }
        foreach ($fam in $expected.Keys) {
            @($Catalog.Requirements | Where-Object Family -eq $fam).Count | Should -Be $expected[$fam] -Because "family $fam"
        }
    }

    It 'numbers each family under its own 800-171 section' {
        $section = @{ AC = '3.1'; AT = '3.2'; AU = '3.3'; CM = '3.4'; IA = '3.5'; IR = '3.6'; MA = '3.7'; MP = '3.8'; PS = '3.9'; PE = '3.10'; RA = '3.11'; CA = '3.12'; SC = '3.13'; SI = '3.14' }
        foreach ($r in $Catalog.Requirements) {
            $r.Id | Should -Match ('^' + [regex]::Escape($section[$r.Family]) + '\.\d+$')
        }
    }

    It 'flags exactly the 17 Level 1 requirements' {
        $l1 = @($Catalog.Requirements | Where-Object Level -eq 'L1' | ForEach-Object { $_.Id }) | Sort-Object
        $want = @('3.1.1', '3.1.2', '3.1.20', '3.1.22', '3.5.1', '3.5.2', '3.8.3', '3.10.1', '3.10.3',
            '3.10.4', '3.10.5', '3.13.1', '3.13.5', '3.14.1', '3.14.2', '3.14.4', '3.14.5') | Sort-Object
        $l1 | Should -Be $want
    }

    It 'uses every check for at least one requirement' {
        $used = @($Catalog.Requirements | ForEach-Object { @($_.Checks) }) | Select-Object -Unique
        foreach ($c in (Get-CheckTable).Keys) { $used | Should -Contain $c }
    }
}

Describe 'Choosing a framework and level' {
    It 'finds a framework by Id or file name, ignoring case' {
        (Resolve-Framework $Catalogs 'disa-stig-win11').Id | Should -Be 'DISA-STIG-Win11'
        (Resolve-Framework $Catalogs 'nist-800-53r5').Id | Should -Be 'NIST-800-53r5'
        (Resolve-Framework $Catalogs 'hipaa-security-rule').Id | Should -Be 'HIPAA'
    }

    It 'lists the frameworks when none is chosen or the name is unknown' {
        { Resolve-Framework $Catalogs '' } | Should -Throw '*Choose a framework*CMMC*'
        { Resolve-Framework $Catalogs 'SOC2' } | Should -Throw "*Unknown framework 'SOC2'*PCI-DSS-4.0.1*"
    }

    It 'defaults to the highest level and accepts <Given> as <Want>' -ForEach @(
        @{ Id = 'CMMC'; Given = ''; Want = 'L2' }
        @{ Id = 'CMMC'; Given = '1'; Want = 'L1' }
        @{ Id = 'CMMC'; Given = 'l1'; Want = 'L1' }
        @{ Id = 'DISA-STIG-Win11'; Given = 'cat i'; Want = 'CAT I' }
        @{ Id = 'DISA-STIG-Win11'; Given = ''; Want = 'CAT III' }
        @{ Id = 'NIST-800-53r5'; Given = 'Low'; Want = 'Low' }
    ) {
        Resolve-FrameworkLevel (Get-Framework $Id) $Given | Should -Be $Want
    }

    It 'refuses a level the framework does not have' {
        { Resolve-FrameworkLevel (Get-Framework 'NIST-800-53r5') 'High' } | Should -Throw '*Low, Moderate*'
        { Resolve-FrameworkLevel $Catalog '3' } | Should -Throw '*L1, L2*'
    }

    It 'includes the levels before the chosen one' {
        $stig = Get-Framework 'DISA-STIG-Win11'
        $s = Get-CompliantSnapshot $stig
        $cat1 = @($stig.Requirements | Where-Object Level -eq 'CAT I').Count
        $cat2 = @($stig.Requirements | Where-Object Level -eq 'CAT II').Count
        @((Invoke-Evaluation $s -Level 'CAT I' -For $stig).Requirements).Count | Should -Be $cat1
        @((Invoke-Evaluation $s -Level 'CAT II' -For $stig).Requirements).Count | Should -Be ($cat1 + $cat2)
        $nist = Get-Framework 'NIST-800-53r5'
        $low = @($nist.Requirements | Where-Object Level -eq 'Low').Count
        @((Invoke-Evaluation (Get-Fixture) -Level 'Low' -For $nist).Requirements).Count | Should -Be $low
    }

    It 'shows other frameworks by their own Id, not as a CMMC practice' {
        $e = Invoke-Evaluation (Get-Fixture) -Level 'Rev3' -For (Get-Framework 'NIST-800-171r3')
        ($e.Requirements | Where-Object Requirement -eq '03.01.08').Reference | Should -Be '03.01.08'
    }
}

Describe 'Compliant snapshot' {
    BeforeAll {
        $script:Eval = Invoke-Evaluation (Get-Fixture)
    }

    It 'passes every check' {
        $notPass = @($Eval.Checks | Where-Object State -ne 'Pass' | ForEach-Object { "$($_.Check)=$($_.State): $($_.Evidence)" })
        $notPass | Should -BeNullOrEmpty
        @($Eval.Checks).Count | Should -Be @((Get-CheckTable).Keys).Count
    }

    It 'reports every requirement as Pass or Manual' {
        @($Eval.Requirements).Count | Should -Be 110
        @($Eval.Requirements | Where-Object { $_.State -notin 'Pass', 'Manual' }) | Should -BeNullOrEmpty
    }

    It 'exits 0' {
        Get-ScanExitCode $Eval.Requirements | Should -Be 0
    }

    It 'limits a Level 1 scan to the 17 Level 1 requirements' {
        $l1 = Invoke-Evaluation (Get-Fixture) -Level 'L1'
        @($l1.Requirements).Count | Should -Be 17
    }

    It 'builds CMMC practice IDs from family, level and requirement' {
        ($Eval.Requirements | Where-Object Requirement -eq '3.1.1').Reference | Should -Be 'AC.L1-3.1.1'
        ($Eval.Requirements | Where-Object Requirement -eq '3.1.8').Reference | Should -Be 'AC.L2-3.1.8'
    }

    It 'lists only the evidence that did not pass under Findings' {
        $s = Get-Fixture
        Write-RegFact $s "$Sys\EnableLUA" 0
        $r = (Invoke-Evaluation $s).Requirements | Where-Object Requirement -eq '3.1.7'
        $r.State | Should -Be 'Fail'
        $r.Findings | Should -Match '^AC-UacEnabled: '
        $r.Findings | Should -Not -Match 'AC-UacSecureDesktop'
    }
}

Describe 'Expectations' {
    It '<Op> <Case> gives <Want>' -ForEach @(
        @{ Op = 'eq'; Case = 'matching'; Value = 1; Expect = @{ Op = 'eq'; Value = 1 }; Want = $true }
        @{ Op = 'eq'; Case = 'different'; Value = 0; Expect = @{ Op = 'eq'; Value = 1 }; Want = $false }
        @{ Op = 'eq'; Case = 'text with other case and spacing'; Value = 'RequireMutualAuthentication=1,RequireIntegrity=1'; Expect = @{ Op = 'eq'; Value = 'RequireMutualAuthentication=1, requireintegrity=1' }; Want = $true }
        @{ Op = 'eq'; Case = 'a DWORD read back as a negative Int32'; Value = [int]-1; Expect = @{ Op = 'eq'; Value = 4294967295 }; Want = $true }
        @{ Op = 'ne'; Case = 'renamed'; Value = 'WestAdmin'; Expect = @{ Op = 'ne'; Value = 'Administrator' }; Want = $true }
        @{ Op = 'ne'; Case = 'not renamed'; Value = 'administrator'; Expect = @{ Op = 'ne'; Value = 'Administrator' }; Want = $false }
        @{ Op = 'ge'; Case = 'equal'; Value = 15; Expect = @{ Op = 'ge'; Value = 15 }; Want = $true }
        @{ Op = 'ge'; Case = 'below'; Value = 14; Expect = @{ Op = 'ge'; Value = 15 }; Want = $false }
        @{ Op = 'ge'; Case = 'not a number'; Value = 'x'; Expect = @{ Op = 'ge'; Value = 15 }; Want = $false }
        @{ Op = 'ge'; Case = 'an allowed extra value'; Value = -1; Expect = @{ Op = 'ge'; Value = 15; Also = @(0, -1) }; Want = $true }
        @{ Op = 'between'; Case = 'inside'; Value = 3; Expect = @{ Op = 'between'; Min = 1; Max = 3 }; Want = $true }
        @{ Op = 'between'; Case = 'zero'; Value = 0; Expect = @{ Op = 'between'; Min = 1; Max = 3 }; Want = $false }
        @{ Op = 'between'; Case = 'above'; Value = 4; Expect = @{ Op = 'between'; Min = 1; Max = 3 }; Want = $false }
        @{ Op = 'in'; Case = 'listed'; Value = 2; Expect = @{ Op = 'in'; Values = @(1, 2) }; Want = $true }
        @{ Op = 'in'; Case = 'not listed'; Value = 3; Expect = @{ Op = 'in'; Values = @(1, 2) }; Want = $false }
        @{ Op = 'notempty'; Case = 'text'; Value = 'Notice'; Expect = @{ Op = 'notempty' }; Want = $true }
        @{ Op = 'notempty'; Case = 'blank'; Value = '  '; Expect = @{ Op = 'notempty' }; Want = $false }
    ) {
        Test-ExpectValue $Value $Expect | Should -Be $Want
    }

    It 'fails a registry value that is not set' {
        $r = Test-ExpectOn @{ Source = 'Registry'; Path = $Sys; Name = 'EnableLUA'; Op = 'eq'; Value = 1 } { param($s) Write-RegFact $s "$Sys\EnableLUA" $null }
        $r.State | Should -Be 'Fail'
        $r.Evidence | Should -Match 'not set'
    }

    It 'passes an unset registry value only when AbsentOk says so' {
        $e = @{ Source = 'Registry'; Path = $Sys; Name = 'EnableLUA'; Op = 'in'; Values = @(1); AbsentOk = $true }
        (Test-ExpectOn $e { param($s) Write-RegFact $s "$Sys\EnableLUA" $null }).State | Should -Be 'Pass'
    }

    It 'reads the local setting only when no policy value is set: <Case>' -ForEach @(
        @{ Case = 'policy value passes'; Policy = 1; Local = 0; Want = 'Pass'; Evidence = '^EnableFirewall = 1$' }
        @{ Case = 'policy value fails, whatever the local setting'; Policy = 0; Local = 1; Want = 'Fail'; Evidence = '^EnableFirewall = 0;' }
        @{ Case = 'local setting passes'; Policy = $null; Local = 1; Want = 'Pass'; Evidence = '^EnableFirewall \(local setting, no policy value\) = 1$' }
        @{ Case = 'local setting fails'; Policy = $null; Local = 0; Want = 'Fail'; Evidence = 'local setting' }
        @{ Case = 'neither set fails'; Policy = $null; Local = $null; Want = 'Fail'; Evidence = 'not set by policy or locally' }
    ) {
        $gp = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
        $fw = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'
        $e = @{ Source = 'Registry'; Path = $gp; FallbackPath = $fw; Name = 'EnableFirewall'; Op = 'eq'; Value = 1 }
        $r = Test-ExpectOn $e {
            param($s)
            Write-Fact $s.Registry "$gp\EnableFirewall" ([pscustomobject]@{ Present = $null -ne $Policy; Value = $Policy; Denied = $false })
            Write-Fact $s.Registry "$fw\EnableFirewall" ([pscustomobject]@{ Present = $null -ne $Local; Value = $Local; Denied = $false })
        }
        $r.State | Should -Be $Want
        $r.Evidence | Should -Match $Evidence
    }

    It 'skips a fallback whose local setting was not readable' {
        $gp = 'HKLM:\SOFTWARE\Policies\Westmark'
        $fw = 'HKLM:\SYSTEM\Westmark'
        $e = @{ Source = 'Registry'; Path = $gp; FallbackPath = $fw; Name = 'X'; Op = 'eq'; Value = 1 }
        $r = Test-ExpectOn $e {
            param($s)
            Write-Fact $s.Registry "$gp\X" ([pscustomobject]@{ Present = $false; Value = $null; Denied = $false })
            Write-Fact $s.Registry "$fw\X" ([pscustomobject]@{ Present = $false; Value = $null; Denied = $true })
        }
        $r.State | Should -Be 'Skipped'
    }

    It 'judges a DomainOnly expectation on <Case>' -ForEach @(
        @{ Case = 'a domain member normally'; InDomain = $true; Value = 0; Want = 'Fail' }
        @{ Case = 'a standalone system as not applicable'; InDomain = $false; Value = 0; Want = 'NotApplicable' }
    ) {
        $e = @{ Source = 'Registry'; Path = $Sys; Name = 'EnableLUA'; Op = 'eq'; Value = 1; DomainOnly = $true }
        $r = Test-ExpectOn $e { param($s) Write-RegFact $s "$Sys\EnableLUA" $Value; $s.Meta.PartOfDomain = $InDomain }
        $r.State | Should -Be $Want
    }

    It 'judges a StandaloneOnly expectation on <Case>' -ForEach @(
        @{ Case = 'a standalone system normally'; InDomain = $false; Want = 'Fail' }
        @{ Case = 'a domain member as not applicable'; InDomain = $true; Want = 'NotApplicable' }
    ) {
        $e = @{ Source = 'Registry'; Path = $Sys; Name = 'EnableLUA'; Op = 'eq'; Value = 1; StandaloneOnly = $true }
        $r = Test-ExpectOn $e { param($s) Write-RegFact $s "$Sys\EnableLUA" 0; $s.Meta.PartOfDomain = $InDomain }
        $r.State | Should -Be $Want
    }

    It 'judges an expectation the STIG waives when <Case>' -ForEach @(
        @{ Case = 'every named rule is met'; Smb1 = 'Disabled'; Start = 4; Want = 'NotApplicable'; Evidence = '^V-2 and V-3 are met' }
        @{ Case = 'one named rule is not met'; Smb1 = 'Disabled'; Start = 2; Want = 'Fail'; Evidence = 'not set' }
        @{ Case = 'no named rule is met'; Smb1 = 'Enabled'; Start = 2; Want = 'Fail'; Evidence = 'not set' }
    ) {
        $mrx = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
        $waiver = @{ Rules = @('V-2', 'V-3'); Expect = @(
                @{ Source = 'Feature'; Name = 'SMB1Protocol'; State = 'Disabled' }
                @{ Source = 'Registry'; Path = $mrx; Name = 'Start'; Op = 'eq'; Value = 4 }
            ) }
        $e = @{ Source = 'Registry'; Path = $Sys; Name = 'EnableLUA'; Op = 'eq'; Value = 1; NotApplicableIf = $waiver }
        $r = Test-ExpectOn $e {
            param($s)
            Write-RegFact $s "$Sys\EnableLUA" $null
            Write-Fact $s.Features 'SMB1Protocol' ([pscustomobject]@{ Present = $true; State = $Smb1 })
            Write-Fact $s.Registry "$mrx\Start" ([pscustomobject]@{ Present = $true; Value = $Start; Denied = $false })
        }
        $r.State | Should -Be $Want
        $r.Evidence | Should -Match $Evidence
    }

    It 'judges a waived expectation normally when the waiver cannot be judged' {
        $e = @{ Source = 'Registry'; Path = $Sys; Name = 'EnableLUA'; Op = 'eq'; Value = 1
            NotApplicableIf = @{ Rules = @('V-2'); Expect = @(@{ Source = 'Feature'; Name = 'SMB1Protocol'; State = 'Disabled' }) } }
        $r = Test-ExpectOn $e {
            param($s)
            Write-RegFact $s "$Sys\EnableLUA" 0
            $s.Collection.Features.Status = 'Skipped'; $s.Collection.Features.Reason = 'Needs an elevated session.'
        }
        $r.State | Should -Be 'Fail'
    }

    It 'errors a DomainOnly expectation when the snapshot has no domain membership' {
        $e = @{ Source = 'Registry'; Path = $Sys; Name = 'EnableLUA'; Op = 'eq'; Value = 1; DomainOnly = $true }
        (Test-ExpectOn $e { param($s) $s.Meta.PSObject.Properties.Remove('PartOfDomain') }).State | Should -Be 'Error'
    }

    It 'errors a registry value missing from the snapshot' {
        (Test-ExpectOn @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Nowhere'; Name = 'X'; Op = 'eq'; Value = 1 }).State | Should -Be 'Error'
    }

    It 'skips a registry value that was not readable' {
        $r = Test-ExpectOn @{ Source = 'Registry'; Path = $Sys; Name = 'EnableLUA'; Op = 'eq'; Value = 1 } { param($s) $s.Registry."$Sys\EnableLUA".Denied = $true }
        $r.State | Should -Be 'Skipped'
    }

    It 'fails a security policy value that is not defined' {
        (Test-ExpectOn @{ Source = 'SecPol'; Name = 'NoSuchPolicy'; Op = 'eq'; Value = 1 }).State | Should -Be 'Fail'
    }

    It 'fails an audit subcategory without the required setting' {
        $r = Test-ExpectOn @{ Source = 'Audit'; Subcategory = 'Logon'; Setting = 'Failure' } { param($s) $s.AuditPolicy.'{0CCE9215-69AE-11D9-BED3-505054503030}' = 1 }
        $r.State | Should -Be 'Fail'
    }

    It 'errors an audit subcategory it does not know' {
        (Test-ExpectOn @{ Source = 'Audit'; Subcategory = 'Logon Typo'; Setting = 'Success' }).State | Should -Be 'Error'
    }

    It 'passes a service that must be disabled when it is not installed, and fails it when it runs' {
        $e = @{ Source = 'Service'; Name = 'SNMP'; StartType = 'Disabled' }
        (Test-ExpectOn $e).State | Should -Be 'Pass'
        (Test-ExpectOn $e { param($s) $s.Services.SNMP.Present = $true; $s.Services.SNMP.StartType = 'Automatic' }).State | Should -Be 'Fail'
    }

    It 'errors a service that was not collected' {
        (Test-ExpectOn @{ Source = 'Service'; Name = 'seclogon'; StartType = 'Disabled' }).State | Should -Be 'Error'
    }

    It 'judges an optional feature: <Case>' -ForEach @(
        @{ Case = 'enabled fails'; Fact = @{ Present = $true; State = 'Enabled' }; Want = 'Fail' }
        @{ Case = 'disabled passes'; Fact = @{ Present = $true; State = 'Disabled' }; Want = 'Pass' }
        @{ Case = 'payload removed passes'; Fact = @{ Present = $true; State = 'DisabledWithPayloadRemoved' }; Want = 'Pass' }
        @{ Case = 'absent from this build passes'; Fact = @{ Present = $false; State = '' }; Want = 'Pass' }
        @{ Case = 'enabled after a restart fails'; Fact = @{ Present = $true; State = 'EnablePending' }; Want = 'Fail' }
        @{ Case = 'disabled after a restart fails'; Fact = @{ Present = $true; State = 'DisablePending' }; Want = 'Fail' }
        @{ Case = 'installed Server feature fails'; Fact = @{ Present = $true; State = 'Installed' }; Want = 'Fail' }
        @{ Case = 'Server feature installed after a restart fails'; Fact = @{ Present = $true; State = 'InstallPending' }; Want = 'Fail' }
        @{ Case = 'Server feature removed after a restart fails'; Fact = @{ Present = $true; State = 'UninstallPending' }; Want = 'Fail' }
        @{ Case = 'available Server feature passes'; Fact = @{ Present = $true; State = 'Available' }; Want = 'Pass' }
        @{ Case = 'removed Server feature passes'; Fact = @{ Present = $true; State = 'Removed' }; Want = 'Pass' }
    ) {
        $s = Get-Fixture
        Write-Fact $s.Features 'SMB1Protocol' ([pscustomobject]$Fact)
        $r = Invoke-Expectation -Expect @{ Source = 'Feature'; Name = 'SMB1Protocol'; State = 'Disabled' } -Snapshot $s
        $r.State | Should -Be $Want
    }

    It 'errors a feature expectation that wants a state other than Disabled' {
        (Test-ExpectOn @{ Source = 'Feature'; Name = 'SMB1Protocol'; State = 'Enabled' } {
            param($s) Write-Fact $s.Features 'SMB1Protocol' ([pscustomobject]@{ Present = $true; State = 'Enabled' })
        }).State | Should -Be 'Error'
    }

    It 'skips an optional feature when the features collector needed elevation' {
        $r = Test-ExpectOn @{ Source = 'Feature'; Name = 'SMB1Protocol'; State = 'Disabled' } {
            param($s) $s.Collection.Features.Status = 'Skipped'; $s.Collection.Features.Reason = 'Needs an elevated session.'
        }
        $r.State | Should -Be 'Skipped'
    }

    It 'errors an expectation with an unknown <What>' -ForEach @(
        @{ What = 'operator'; Expect = @{ Source = 'SecPol'; Name = 'PasswordComplexity'; Op = 'gt'; Value = 0 } }
        @{ What = 'source'; Expect = @{ Source = 'Wmi'; Name = 'X' } }
    ) {
        (Test-ExpectOn $Expect).State | Should -Be 'Error'
    }

    It 'rolls expectations and checks up to the worst state' {
        $fw = @{
            Id = 'T'; Name = 'T'; Levels = @('One'); Complete = $true; Thresholds = @{}
            Requirements = @(@{ Id = '1'; Family = 'X'; Level = 'One'; Title = 't'; Checks = @('AC-UacEnabled')
                    Expect = @(@{ Source = 'SecPol'; Name = 'PasswordComplexity'; Op = 'eq'; Value = 0 }) })
        }
        $r = (Invoke-Evaluation (Get-Fixture) -Level 'One' -For $fw).Requirements[0]
        $r.State | Should -Be 'Fail'
        $r.Checks | Should -Be 'AC-UacEnabled=Pass; SecPol:PasswordComplexity=Fail'
    }
}

Describe 'Server 2025 domain controller STIG (regression: false failures in a lab scan)' {
    BeforeAll {
        $script:Dc = Get-Framework 'DISA-STIG-WS2025-DC'
        function Get-DcState {
            param([scriptblock]$Mutate, [string[]]$Id)
            $s = Get-CompliantSnapshot $Dc
            & $Mutate $s
            $e = Invoke-Evaluation $s -Thresholds (Get-Threshold $Dc) -Level $null -For $Dc
            foreach ($i in $Id) { ($e.Requirements | Where-Object Requirement -eq $i).State }
        }
        $script:Smb = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        $script:Mrx = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start'
        $script:Telemetry = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        $script:DoMode = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        $script:Consent = "$Sys\ConsentPromptBehaviorAdmin"
    }

    It 'leaves the SMB1 settings not applicable when SMB1 is removed' {
        Get-DcState {
            param($s)
            Write-RegFact $s $Smb $null; Write-RegFact $s $Mrx $null
            Write-Fact $s.Features 'FS-SMB1' ([pscustomobject]@{ Present = $true; State = 'Removed' })
        } 'V-278023', 'V-278024', 'V-278025' | Should -Be @('Pass', 'NotApplicable', 'NotApplicable')
    }

    It 'leaves SMB1 removal not applicable when both SMB1 settings are met, and fails all three when none is' {
        Get-DcState {
            param($s) Write-Fact $s.Features 'FS-SMB1' ([pscustomobject]@{ Present = $true; State = 'Installed' })
        } 'V-278023', 'V-278024', 'V-278025' | Should -Be @('NotApplicable', 'Pass', 'Pass')
        Get-DcState {
            param($s)
            Write-RegFact $s $Smb $null; Write-RegFact $s $Mrx 2
            Write-Fact $s.Features 'FS-SMB1' ([pscustomobject]@{ Present = $true; State = 'Installed' })
        } 'V-278023', 'V-278024', 'V-278025' | Should -Be @('Fail', 'Fail', 'Fail')
    }

    It 'judges <Name> = <Value> as <Want>' -ForEach @(
        @{ Name = 'AllowTelemetry'; Id = 'V-278103'; Value = 1; Want = 'Pass' }
        @{ Name = 'AllowTelemetry'; Id = 'V-278103'; Value = 3; Want = 'Fail' }
        @{ Name = 'AllowTelemetry'; Id = 'V-278103'; Value = $null; Want = 'Fail' }
        @{ Name = 'DODownloadMode'; Id = 'V-278104'; Value = 99; Want = 'Pass' }
        @{ Name = 'DODownloadMode'; Id = 'V-278104'; Value = 3; Want = 'Fail' }
        @{ Name = 'ConsentPromptBehaviorAdmin'; Id = 'V-278234'; Value = 1; Want = 'Pass' }
        @{ Name = 'ConsentPromptBehaviorAdmin'; Id = 'V-278234'; Value = 5; Want = 'Fail' }
    ) {
        $key = @{ AllowTelemetry = $Telemetry; DODownloadMode = $DoMode; ConsentPromptBehaviorAdmin = $Consent }[$Name]
        Get-DcState { param($s) Write-RegFact $s $key $Value } $Id | Should -Be $Want
    }
}

Describe 'Active Directory STIGs' {
    BeforeAll {
        $script:AdDomain = Get-Framework 'DISA-STIG-AD-Domain'
        $script:AdForest = Get-Framework 'DISA-STIG-AD-Forest'
        $script:DomainSid = 'S-1-5-21-1000000011-1000000012-1000000013'

        function Get-TestUser {
            param([string]$Name, [int]$Rid, [bool]$NotDelegated = $false, [bool]$Protected = $false, [bool]$Enabled = $true)
            [pscustomobject]@{ Name = $Name; Sid = "$DomainSid-$Rid"; Enabled = $Enabled; NotDelegated = $NotDelegated; Protected = $Protected }
        }

        function Add-DirectoryMember {
            # Adds a user (or a principal with only Name and Sid) to groups, as the collector records it.
            param($Snapshot, $User, [string[]]$Group)
            foreach ($g in $Group) {
                $entry = $Snapshot.Directory.Groups.$g
                $entry.Members = @($entry.Members) + [pscustomobject]@{ Name = $User.Name; Sid = $User.Sid }
                if ($User.PSObject.Properties['Enabled']) { $entry.Users = @($entry.Users) + $User }
            }
        }

        function Get-AdState {
            # The states of the named requirements, from both AD catalogs, after $Mutate.
            param([scriptblock]$Mutate, [string[]]$Id)
            $s = Get-CompliantSnapshot $AdDomain
            & $Mutate $s
            $all = @{}
            foreach ($fw in $AdDomain, $AdForest) {
                foreach ($r in (Invoke-Evaluation $s -Thresholds (Get-Threshold $fw) -Level $null -For $fw).Requirements) { $all[$r.Requirement] = $r }
            }
            foreach ($i in $Id) { $all[$i].State }
        }

        function Get-AdFinding {
            param([scriptblock]$Mutate, [string]$Id)
            $s = Get-CompliantSnapshot $AdDomain
            & $Mutate $s
            $fw = if ($AdForest.Requirements.Id -contains $Id) { $AdForest } else { $AdDomain }
            "$(((Invoke-Evaluation $s -Thresholds (Get-Threshold $fw) -Level $null -For $fw).Requirements | Where-Object Requirement -eq $Id).Findings)"
        }
    }

    It 'flags every finding planted in a lab domain (regression: lab domain controller)' {
        $planted = {
            param($s)
            $builtIn = Get-TestUser 'Administrator' 500
            $admin = Get-TestUser 'wm-admin2' 1105
            Add-DirectoryMember $s $builtIn 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'
            Add-DirectoryMember $s $admin 'Domain Admins', 'Enterprise Admins', 'Schema Admins'
            Add-DirectoryMember $s (Get-TestUser 'wm-gpo' 1106) 'Group Policy Creator Owners'
            Add-DirectoryMember $s ([pscustomobject]@{ Name = 'Everyone'; Sid = 'S-1-1-0' }) 'Pre-Windows 2000 Compatible Access'
            $s.Directory.UnconstrainedDelegation = @('WM-SRV07')
        }
        $ids = 'V-243466', 'V-243467', 'V-243470', 'V-243477', 'V-243478', 'V-243486', 'V-243487', 'V-243502'
        Get-AdState $planted $ids | Should -Be @('Fail', 'Fail', 'Fail', 'Fail', 'Fail', 'Fail', 'Manual', 'Fail')
        Get-AdFinding $planted 'V-243477' | Should -Match 'Administrator, wm-admin2'
        Get-AdFinding $planted 'V-243478' | Should -Match 'WM-SRV07'
        Get-AdFinding $planted 'V-243486' | Should -Match 'Everyone'
        Get-AdFinding $planted 'V-243502' | Should -Match 'Administrator, wm-admin2'
    }

    It 'passes the domain and forest STIG rules a compliant domain meets, and leaves the rest to review' {
        $ids = 'V-243466', 'V-243467', 'V-243470', 'V-243471', 'V-243476', 'V-243477', 'V-243478', 'V-243479', 'V-243480',
            'V-243484', 'V-243485', 'V-243486', 'V-243487', 'V-243497', 'V-243500', 'V-243502', 'V-243503', 'V-243504', 'V-269098'
        Get-AdState {} $ids | Should -Be @('Manual', 'Manual', 'Pass', 'Pass', 'Pass', 'Pass', 'Pass', 'Pass', 'Pass',
            'NotApplicable', 'NotApplicable', 'Pass', 'Pass', 'NotApplicable', 'Pass', 'Pass', 'Pass', 'Manual', 'NotApplicable')
    }

    It 'judges administrator separation by enabled accounts only' {
        Get-AdState { param($s) Add-DirectoryMember $s (Get-TestUser 'wm-old' 1110 -Enabled $false) 'Domain Admins', 'Enterprise Admins' } 'V-243466' | Should -Be 'Manual'
        Get-AdState { param($s) Add-DirectoryMember $s (Get-TestUser 'wm-bk' 1111 $true $true) 'Domain Admins', 'Backup Operators' } 'V-243467' | Should -Be 'Fail'
        Get-AdState { param($s) foreach ($g in 'Domain Admins', 'Enterprise Admins') { $s.Directory.Groups.$g.Members = @(); $s.Directory.Groups.$g.Users = @() } } 'V-243466', 'V-243467' |
            Should -Be @('Pass', 'Pass')
    }

    It 'names a well-known SID the directory stores by SID alone (regression: lab scan showed S-1-1-0)' {
        $bySid = {
            param($s)
            Add-DirectoryMember $s ([pscustomobject]@{ Name = 'S-1-1-0'; Sid = 'S-1-1-0' }) 'Pre-Windows 2000 Compatible Access'
            Add-DirectoryMember $s ([pscustomobject]@{ Name = ''; Sid = 'S-1-5-7' }) 'Pre-Windows 2000 Compatible Access'
        }
        Get-AdState $bySid 'V-243486' | Should -Be 'Fail'
        $finding = Get-AdFinding $bySid 'V-243486'
        $finding | Should -Match 'includes Everyone and Anonymous Logon\.'
        $finding | Should -Not -Match 'S-1-'
        # A named member keeps its own name, and an unknown SID stays as it is.
        Get-AdFinding { param($s) Add-DirectoryMember $s ([pscustomobject]@{ Name = 'Jeder'; Sid = 'S-1-1-0' }) 'Pre-Windows 2000 Compatible Access' } 'V-243486' |
            Should -Match 'includes Jeder\.'
        $s = Get-CompliantSnapshot $AdDomain
        Add-DirectoryMember $s ([pscustomobject]@{ Name = "$DomainSid-2001"; Sid = "$DomainSid-2001" }) 'Group Policy Creator Owners'
        @(Get-DirectoryMember $s.Directory 'Group Policy Creator Owners').Name | Should -Be @("$DomainSid-2001")
    }

    It 'allows one administrative account outside Protected Users, not two' {
        Get-AdState { param($s) Add-DirectoryMember $s (Get-TestUser 'Administrator' 500 $true) 'Domain Admins' } 'V-243477' | Should -Be 'Pass'
        Get-AdState {
            param($s)
            Add-DirectoryMember $s (Get-TestUser 'Administrator' 500 $true) 'Domain Admins'
            Add-DirectoryMember $s (Get-TestUser 'wm-ops' 1112 $true) 'Account Operators'
        } 'V-243477' | Should -Be 'Fail'
        Get-AdState { param($s) $s.Directory.DomainMode = 5 } 'V-243477' | Should -Be 'NotApplicable'
    }

    It 'judges <Case> as <Want>' -ForEach @(
        @{ Case = 'smart card hash rolling off'; Id = 'V-243476'; Want = 'Fail'; Mutate = { param($s) $s.Directory.ExpirePasswordsOnSmartCardOnlyAccounts = $false } }
        @{ Case = 'smart card hash rolling below level 2016'; Id = 'V-243476'; Want = 'Manual'; Mutate = { param($s) $s.Directory.DomainMode = 6 } }
        @{ Case = 'domain functional level 2012 R2'; Id = 'V-243480'; Want = 'Fail'; Mutate = { param($s) $s.Directory.DomainMode = 6 } }
        @{ Case = 'a DSRM password over a year old'; Id = 'V-243479'; Want = 'Fail'; Mutate = { param($s) $s.Directory.DsrmLastSet = '2024-01-01T00:00:00Z' } }
        @{ Case = 'no DSRM change event'; Id = 'V-243479'; Want = 'Manual'; Mutate = { param($s) $s.Directory.DsrmLastSet = $null } }
        @{ Case = 'a computer without a LAPS password'; Id = 'V-243471'; Want = 'Manual'; Mutate = { param($s) $s.Directory.Laps.Missing = @('WM-PC12') } }
        @{ Case = 'no LAPS schema'; Id = 'V-243471'; Want = 'Manual'; Mutate = { param($s) $s.Directory.Laps.Schema = 'None' } }
        @{ Case = 'a privileged account that can be delegated'; Id = 'V-243470'; Want = 'Fail'; Mutate = { param($s) Add-DirectoryMember $s (Get-TestUser 'wm-print' 1113 $false $true) 'Print Operators' } }
        @{ Case = 'Anonymous Logon in Pre-Windows 2000 Compatible Access'; Id = 'V-243486'; Want = 'Fail'; Mutate = { param($s) Add-DirectoryMember $s ([pscustomobject]@{ Name = 'ANONYMOUS LOGON'; Sid = 'S-1-5-7' }) 'Pre-Windows 2000 Compatible Access' } }
        @{ Case = 'a member of Incoming Forest Trust Builders'; Id = 'V-243487'; Want = 'Manual'; Mutate = { param($s) Add-DirectoryMember $s (Get-TestUser 'wm-trust' 1114) 'Incoming Forest Trust Builders' } }
        @{ Case = 'one domain controller'; Id = 'V-243500'; Want = 'Manual'; Mutate = { param($s) $s.Directory.DomainControllers = 1 } }
        @{ Case = 'a site link replicating every two days'; Id = 'V-243497'; Want = 'Fail'; Mutate = { param($s) $s.Directory.Sites = 2; $s.Directory.SiteLinks[0].ReplInterval = 2880 } }
        @{ Case = 'a site link with a schedule'; Id = 'V-243497'; Want = 'Manual'; Mutate = { param($s) $s.Directory.Sites = 2; $s.Directory.SiteLinks[0].HasSchedule = $true } }
        @{ Case = 'two sites replicating every three hours'; Id = 'V-243497'; Want = 'Pass'; Mutate = { param($s) $s.Directory.Sites = 2 } }
        @{ Case = 'Schema Admins in a child domain'; Id = 'V-243502'; Want = 'NotApplicable'; Mutate = { param($s) $s.Directory.IsForestRoot = $false; Add-DirectoryMember $s (Get-TestUser 'wm-schema' 1115) 'Schema Admins' } }
        @{ Case = 'anonymous forest access in dSHeuristics'; Id = 'V-243503'; Want = 'Fail'; Mutate = { param($s) $s.Directory.DsHeuristics = '0000002' } }
        @{ Case = 'dSHeuristics with other flags'; Id = 'V-243503'; Want = 'Pass'; Mutate = { param($s) $s.Directory.DsHeuristics = '0000001001' } }
        @{ Case = 'the forest root PDC emulator on the domain hierarchy'; Id = 'V-243504'; Want = 'Fail'; Mutate = { param($s) $s.Directory.TimeSource.Type = 'NT5DS' } }
        @{ Case = 'a domain controller that is not the PDC emulator'; Id = 'V-243504'; Want = 'NotApplicable'; Mutate = { param($s) $s.Directory.IsPdcEmulator = $false; $s.Directory.TimeSource.Type = 'NT5DS' } }
    ) {
        Get-AdState $Mutate $Id | Should -Be $Want
    }

    It 'judges trust <Case> as SID filtering <Sid>, selective authentication <Selective>' -ForEach @(
        @{ Case = 'external, quarantined'; Direction = 3; Attributes = 0x4; Sid = 'Pass'; Selective = 'NotApplicable' }
        @{ Case = 'external, not quarantined'; Direction = 2; Attributes = 0; Sid = 'Fail'; Selective = 'NotApplicable' }
        @{ Case = 'external, incoming only'; Direction = 1; Attributes = 0; Sid = 'NotApplicable'; Selective = 'NotApplicable' }
        @{ Case = 'within the forest'; Direction = 3; Attributes = 0x20; Sid = 'NotApplicable'; Selective = 'NotApplicable' }
        @{ Case = 'forest, selective'; Direction = 3; Attributes = 0x18; Sid = 'Pass'; Selective = 'Pass' }
        @{ Case = 'forest, not selective'; Direction = 2; Attributes = 0x8; Sid = 'Pass'; Selective = 'Fail' }
        @{ Case = 'forest, SID history enabled'; Direction = 3; Attributes = 0x58; Sid = 'Fail'; Selective = 'Pass' }
    ) {
        $trust = [pscustomobject]@{ Name = 'partner.example'; Direction = $Direction; Attributes = $Attributes }
        Get-AdState { param($s) $s.Directory.Trusts = @($trust) } 'V-243484', 'V-243485' | Should -Be @($Sid, $Selective)
    }

    It 'judges certificate template <Case> as <Want>' -ForEach @(
        @{ Case = 'smart card logon without approval'; Want = 'Fail'; Template = @{ ManagerApproval = $false; SuppliesSubject = $false; Ekus = @('1.3.6.1.4.1.311.20.2.2') } }
        @{ Case = 'any purpose without approval'; Want = 'Fail'; Template = @{ ManagerApproval = $false; SuppliesSubject = $false; Ekus = @('2.5.29.37.0') } }
        @{ Case = 'no EKU without approval'; Want = 'Fail'; Template = @{ ManagerApproval = $false; SuppliesSubject = $false; Ekus = @() } }
        @{ Case = 'client auth with a supplied subject'; Want = 'Fail'; Template = @{ ManagerApproval = $false; SuppliesSubject = $true; Ekus = @('1.3.6.1.5.5.7.3.2') } }
        @{ Case = 'client auth with a subject from the directory'; Want = 'Pass'; Template = @{ ManagerApproval = $false; SuppliesSubject = $false; Ekus = @('1.3.6.1.5.5.7.3.2') } }
        @{ Case = 'server auth with a supplied subject'; Want = 'Pass'; Template = @{ ManagerApproval = $false; SuppliesSubject = $true; Ekus = @('1.3.6.1.5.5.7.3.1') } }
        @{ Case = 'smart card logon with approval'; Want = 'Pass'; Template = @{ ManagerApproval = $true; SuppliesSubject = $true; Ekus = @('1.3.6.1.4.1.311.20.2.2') } }
    ) {
        $t = [pscustomobject]($Template + @{ Name = 'WestmarkUser' })
        Get-AdState { param($s) $s.Directory.CertificateServices.Present = $true; $s.Directory.CertificateServices.Templates = @($t) } 'V-269098' | Should -Be $Want
    }

    It 'leaves directory rules not applicable off a domain controller, never passed' {
        $s = Get-CompliantSnapshot $AdDomain
        $s.Collection.Directory.Status = 'NotApplicable'
        $s.Collection.Directory.Reason = 'Active Directory is read on a domain controller.'
        $s.Directory = $null
        $e = Invoke-Evaluation $s -Thresholds (Get-Threshold $AdDomain) -Level $null -For $AdDomain
        $directory = @($e.Requirements | Where-Object { $_.Requirement -ne 'V-269097' -and $AdDomain.Requirements.Where({ $_.Contains('Expect') }).Id -contains $_.Requirement })
        $directory.Count | Should -Be 15
        @($directory | Where-Object State -ne 'NotApplicable') | Should -BeNullOrEmpty
        Get-ScanExitCode $e.Requirements | Should -Be 0
    }

    It 'errors directory rules when the directory collector failed' {
        $s = Get-CompliantSnapshot $AdDomain
        $s.Collection.Directory.Status = 'Error'
        $s.Collection.Directory.Reason = 'The server is not operational.'
        $s.Directory = $null
        $e = Invoke-Evaluation $s -Thresholds (Get-Threshold $AdDomain) -Level $null -For $AdDomain
        ($e.Requirements | Where-Object Requirement -eq 'V-243478').State | Should -Be 'Error'
        Get-ScanExitCode $e.Requirements | Should -Be 2
    }

    It 'errors an expectation that names a directory test the scanner does not have' {
        (Test-ExpectOn @{ Source = 'Directory'; Name = 'NoSuchTest' }).State | Should -Be 'Error'
    }

    It 'errors when a group the tests read is missing from the snapshot' {
        $s = Get-CompliantSnapshot $AdDomain
        $s.Directory.Groups.PSObject.Properties.Remove('Schema Admins')
        $e = Invoke-Evaluation $s -Thresholds (Get-Threshold $AdForest) -Level $null -For $AdForest
        ($e.Requirements | Where-Object Requirement -eq 'V-243502').State | Should -Be 'Error'
    }
}

Describe 'PAW STIG' {
    BeforeAll {
        $script:Paw = Get-Framework 'DISA-STIG-PAW'
        function Get-PawResult {
            # The named requirement's result, from the PAW catalog, after $Mutate.
            param([scriptblock]$Mutate, [string]$Id)
            $s = Get-CompliantSnapshot $Paw
            & $Mutate $s
            $e = Invoke-Evaluation $s -Thresholds (Get-Threshold $Paw) -Level $null -For $Paw
            $e.Requirements | Where-Object Requirement -eq $Id
        }
        function Write-GroupMember {
            param($Snapshot, [string]$Group, [string[]]$Name)
            $Snapshot.LocalAccounts.Groups.$Group.Members = @($Name | ForEach-Object { [pscustomobject]@{ Name = $_; Sid = "S-1-5-21-1000000001-1000000002-1000000003-$(1100 + $Name.IndexOf($_))" } })
        }
        function Write-LogonRight {
            param($Snapshot, [object[]]$Entry)
            $Snapshot.UserRights.SeInteractiveLogonRight = @($Entry | ForEach-Object { [pscustomobject]@{ Sid = $_[0]; Name = $_[1] } })
        }
    }

    It 'passes a PAW that meets every automated rule, and leaves the version and Administrators to review' {
        foreach ($id in 'V-243450', 'V-243451', 'V-243452', 'V-243455', 'V-243457', 'V-243463', 'V-243464') {
            (Get-PawResult {} $id).State | Should -Be 'Pass' -Because $id
        }
        foreach ($id in 'V-243447', 'V-243462') { (Get-PawResult {} $id).State | Should -Be 'Manual' -Because $id }
        (Get-PawResult {} 'V-243447').Evidence | Should -Match 'Windows 11 Pro, version 10\.0\.26100'
        (Get-PawResult {} 'V-243462').Evidence | Should -Match 'WESTMARK\\Domain Admins'
    }

    It 'judges <Property> = <Value> as <Want>' -ForEach @(
        @{ Property = 'CodeIntegrityPolicyEnforcementStatus'; Id = 'V-243450'; Value = 1; Want = 'Fail'; Text = 'Audit' }
        @{ Property = 'CodeIntegrityPolicyEnforcementStatus'; Id = 'V-243450'; Value = 0; Want = 'Fail'; Text = 'Not configured' }
        @{ Property = 'UsermodeCodeIntegrityPolicyEnforcementStatus'; Id = 'V-243451'; Value = 1; Want = 'Fail'; Text = 'Audit' }
        @{ Property = 'UsermodeCodeIntegrityPolicyEnforcementStatus'; Id = 'V-243451'; Value = 2; Want = 'Pass'; Text = 'Enforced' }
    ) {
        $r = Get-PawResult { param($s) $s.DeviceGuard.$Property = $Value } $Id
        $r.State | Should -Be $Want
        $r.Evidence | Should -Match $Text
    }

    It 'fails a member of a local privileged group, and leaves Hyper-V Administrators to review' {
        $r = Get-PawResult { param($s) Write-GroupMember $s 'Remote Desktop Users' 'WESTMARK\helpdesk' } 'V-243463'
        $r.State | Should -Be 'Fail'
        $r.Evidence | Should -Match 'Remote Desktop Users: WESTMARK\\helpdesk'
        (Get-PawResult { param($s) Write-GroupMember $s 'Hyper-V Administrators' 'WESTMARK-PC01\tech01' } 'V-243463').State | Should -Be 'Manual'
        (Get-PawResult { param($s) Write-GroupMember $s 'Hyper-V Administrators' 'A'; Write-GroupMember $s 'Power Users' 'B' } 'V-243463').State | Should -Be 'Fail'
    }

    It 'fails Allow log on locally held by <Name>' -ForEach @(
        @{ Sid = 'S-1-5-32-545'; Name = 'BUILTIN\Users' }
        @{ Sid = 'S-1-1-0'; Name = 'Everyone' }
        @{ Sid = 'S-1-5-11'; Name = 'NT AUTHORITY\Authenticated Users' }
        @{ Sid = 'S-1-5-21-1000000011-1000000012-1000000013-513'; Name = 'WESTMARK\Domain Users' }
    ) {
        $entry = @(, @('S-1-5-32-544', 'BUILTIN\Administrators')) + @(, @($Sid, $Name))
        foreach ($id in 'V-243452', 'V-243455') {
            $r = Get-PawResult { param($s) Write-LogonRight $s $entry } $id
            $r.State | Should -Be 'Fail' -Because $id
            $r.Evidence | Should -Match ([regex]::Escape($Name))
        }
    }

    It 'leaves a designated management group with Allow log on locally to review' {
        $entry = @(, @('S-1-5-32-544', 'BUILTIN\Administrators')) + @(, @('S-1-5-21-1000000011-1000000012-1000000013-2101', 'WESTMARK\Tier0-Admins'))
        $r = Get-PawResult { param($s) Write-LogonRight $s $entry } 'V-243455'
        $r.State | Should -Be 'Manual'
        $r.Evidence | Should -Match 'Tier0-Admins'
    }

    It 'fails the smart card and restricted admin settings when unset' {
        (Get-PawResult { param($s) Write-RegFact $s "$Sys\scforceoption" $null } 'V-243457').State | Should -Be 'Fail'
        (Get-PawResult { param($s) Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\RestrictedRemoteAdministration' 0 } 'V-243464').State | Should -Be 'Fail'
        (Get-PawResult {} 'V-243464').Note | Should -Match 'DisableRestrictedAdmin'
    }

    It 'skips the code integrity rules, never passes them, when Device Guard is not reported' {
        $r = Get-PawResult {
            param($s)
            $s.Collection.DeviceGuard.Status = 'Skipped'
            $s.Collection.DeviceGuard.Reason = 'This Windows does not report Device Guard (Win32_DeviceGuard).'
            $s.DeviceGuard = $null
        } 'V-243450'
        $r.State | Should -Be 'Skipped'
    }

    It 'errors the local group rule on a snapshot without local group membership' {
        (Get-PawResult { param($s) $s.LocalAccounts.PSObject.Properties.Remove('Groups') } 'V-243463').State | Should -Be 'Error'
    }

    It 'errors an expectation that names an endpoint test the scanner does not have' {
        (Test-ExpectOn @{ Source = 'Local'; Name = 'NoSuchTest' }).State | Should -Be 'Error'
    }
}

Describe 'Optional feature sources' {
    BeforeAll {
        # Linux has neither cmdlet; give Mock something to replace there.
        $script:AddedStub = @()
        if (-not (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
            function global:Get-WindowsOptionalFeature { [CmdletBinding()] param([switch]$Online) throw "Not mocked (Online=$Online)." }
            $script:AddedStub += 'Get-WindowsOptionalFeature'
        }
        if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
            function global:Get-CimInstance { [CmdletBinding()] param($ClassName) throw "Not mocked ($ClassName)." }
            $script:AddedStub += 'Get-CimInstance'
        }
    }
    AfterAll {
        foreach ($name in $script:AddedStub) { Remove-Item "Function:\$name" }
    }

    It 'reads DISM when it works' {
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ FeatureName = 'SMB1Protocol'; State = 'EnablePending' } } -ParameterFilter { $Online }
        Mock Get-CimInstance { throw 'CIM should not be read when DISM works.' }
        $f = Get-OptionalFeatureState
        $f['SMB1Protocol'] | Should -Be 'EnablePending'
        Should -Invoke Get-CimInstance -Times 0 -Exactly
    }

    It 'falls back to Win32_OptionalFeature when DISM fails (regression: "Class not registered" under PowerShell 7)' {
        Mock Get-WindowsOptionalFeature { throw 'Class not registered' }
        Mock Get-CimInstance {
            [pscustomobject]@{ Name = 'SMB1Protocol'; InstallState = 2 }
            [pscustomobject]@{ Name = 'TelnetClient'; InstallState = 1 }
            [pscustomobject]@{ Name = 'TFTP'; InstallState = 3 }
            [pscustomobject]@{ Name = 'Odd'; InstallState = 4 }
        } -ParameterFilter { $ClassName -eq 'Win32_OptionalFeature' }
        $f = Get-OptionalFeatureState
        $f['SMB1Protocol'] | Should -Be 'Disabled'
        $f['TelnetClient'] | Should -Be 'Enabled'
        $f['TFTP'] | Should -Be 'DisabledWithPayloadRemoved'
        $f['Odd'] | Should -Be 'Unknown'
        $FeatureOnStates | Should -Contain $f['TelnetClient']
        $FeatureOnStates | Should -Not -Contain $f['TFTP']
    }
}

Describe 'User rights' {
    BeforeAll {
        function Write-Holder {
            # Replaces who holds a right in the snapshot; no identities removes it.
            param($Snapshot, [string]$Right, [object[]]$Entry)
            if (@($Entry).Count -eq 0) { $Snapshot.UserRights.PSObject.Properties.Remove($Right); return }
            Write-Fact $Snapshot.UserRights $Right @($Entry)
        }
        function Test-Right {
            param($Expect, [object[]]$Entry, [bool]$InDomain = $true)
            $s = Get-Fixture
            Write-Holder $s $Expect.Name $Entry
            $s.Meta.PartOfDomain = $InDomain
            Invoke-Expectation -Expect (@{ Source = 'UserRight' } + $Expect) -Snapshot $s
        }
        $script:Admins = Get-IdentityEntry 'Administrators'
        $script:AuthUsers = Get-IdentityEntry 'Authenticated Users'
        $script:Guests = Get-IdentityEntry 'Guests'
        $script:LocalAccount = Get-IdentityEntry 'Local account'
        $script:DomainAdmins = Get-IdentityEntry 'Domain Admins'
        $script:EnterpriseAdmins = Get-IdentityEntry 'Enterprise Admins'
    }

    It 'passes only when everyone holding the right is allowed' {
        $e = @{ Name = 'SeNetworkLogonRight'; Op = 'only'; Identities = @('Administrators', 'Authenticated Users') }
        (Test-Right $e @($Admins, $AuthUsers)).State | Should -Be 'Pass'
        (Test-Right $e @($Admins)).State | Should -Be 'Pass'
        $r = Test-Right $e @($Admins, $Guests)
        $r.State | Should -Be 'Fail'
        $r.Evidence | Should -Match 'WESTMARK\\Guests'
        $r.Evidence | Should -Match 'allowed: only Administrators, Authenticated Users'
    }

    It 'passes a right no one may hold only when no one holds it' {
        $e = @{ Name = 'SeTcbPrivilege'; Op = 'only'; Identities = @() }
        $r = Test-Right $e @()
        $r.State | Should -Be 'Pass'
        $r.Evidence | Should -Match 'assigned to no one'
        (Test-Right $e @($Admins)).State | Should -Be 'Fail'
    }

    It 'matches well-known identities by SID, whatever the display language' {
        $e = @{ Name = 'SeDebugPrivilege'; Op = 'only'; Identities = @('Administrators') }
        (Test-Right $e @([pscustomobject]@{ Sid = 'S-1-5-32-544'; Name = 'VORDEFINIERT\Administratoren' })).State | Should -Be 'Pass'
        (Test-Right $e @([pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-1001'; Name = 'WESTMARK\Administrators' })).State | Should -Be 'Fail'
    }

    It 'matches an identity without a well-known SID by account name' {
        $e = @{ Name = 'SeImpersonatePrivilege'; Op = 'only'; Identities = @('Administrators', 'RESTRICTED SERVICES\PrintSpoolerService') }
        $spooler = [pscustomobject]@{ Sid = 'S-1-5-99-1-2-3'; Name = 'RESTRICTED SERVICES\PrintSpoolerService' }
        (Test-Right $e @($Admins, $spooler)).State | Should -Be 'Pass'
    }

    It 'fails, never passes, a holder whose SID no longer resolves' {
        $e = @{ Name = 'SeBackupPrivilege'; Op = 'only'; Identities = @('Administrators') }
        $r = Test-Right $e @($Admins, [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-4444'; Name = '' })
        $r.State | Should -Be 'Fail'
        $r.Evidence | Should -Match 'S-1-5-21-1-2-3-4444'
    }

    It 'fails includes when a required identity is missing' {
        $e = @{ Name = 'SeDenyNetworkLogonRight'; Op = 'includes'; Identities = @('Guests', 'Local account') }
        (Test-Right $e @($Guests, $LocalAccount, $Admins)).State | Should -Be 'Pass'
        $r = Test-Right $e @($Guests)
        $r.State | Should -Be 'Fail'
        $r.Evidence | Should -Match 'missing: Local account'
        (Test-Right $e @()).State | Should -Be 'Fail'
    }

    It 'accepts either identity of an alternative' {
        $e = @{ Name = 'SeDenyNetworkLogonRight'; Op = 'includes'; Identities = @('Local account and member of Administrators group|Local account') }
        (Test-Right $e @($LocalAccount)).State | Should -Be 'Pass'
        (Test-Right $e @(Get-IdentityEntry 'Local account and member of Administrators group')).State | Should -Be 'Pass'
        $r = Test-Right $e @($Guests)
        $r.State | Should -Be 'Fail'
        $r.Evidence | Should -Match 'Local account and member of Administrators group or Local account'
    }

    It 'requires domain groups on a domain member and waives them elsewhere' {
        $e = @{ Name = 'SeDenyNetworkLogonRight'; Op = 'includes'; Identities = @('Enterprise Admins', 'Domain Admins', 'Guests') }
        (Test-Right $e @($Guests) -InDomain $true).State | Should -Be 'Fail'
        (Test-Right $e @($Guests, $DomainAdmins, $EnterpriseAdmins) -InDomain $true).State | Should -Be 'Pass'
        $r = Test-Right $e @($Guests) -InDomain $false
        $r.State | Should -Be 'Pass'
        $r.Evidence | Should -Match 'not required outside a domain'
    }

    It 'errors includes when the snapshot does not say whether the machine is in a domain' {
        $s = Get-Fixture
        $s.Meta.PSObject.Properties.Remove('PartOfDomain')
        $r = Invoke-Expectation -Expect @{ Source = 'UserRight'; Name = 'SeDenyNetworkLogonRight'; Op = 'includes'; Identities = @('Guests') } -Snapshot $s
        $r.State | Should -Be 'Error'
    }

    It 'errors an unknown operator' {
        (Test-Right @{ Name = 'SeDebugPrivilege'; Op = 'exactly'; Identities = @('Administrators') } @($Admins)).State | Should -Be 'Error'
    }

    It 'skips, never passes, user rights a non-elevated run could not collect' {
        $s = Get-Fixture
        $s.Collection.UserRights.Status = 'Skipped'
        $s.Collection.UserRights.Reason = 'Needs an elevated session.'
        $s.UserRights = $null
        $r = Invoke-Expectation -Expect @{ Source = 'UserRight'; Name = 'SeTcbPrivilege'; Op = 'only'; Identities = @() } -Snapshot $s
        $r.State | Should -Be 'Skipped'
    }
}

Describe 'Registry text' {
    It 'drops trailing NULs and turns embedded ones into line breaks' {
        # Regression (0.4.1): NULs from the registry reached the reports.
        ConvertTo-RegistryText "Westmark notice$([char]0)$([char]0)" | Should -BeExactly 'Westmark notice'
        ConvertTo-RegistryText "line one$([char]0)line two$([char]0)" | Should -BeExactly "line one`nline two"
        ConvertTo-RegistryText @("one$([char]0)", 'two') | Should -BeExactly "one`ntwo"
        ConvertTo-RegistryText 'plain' | Should -BeExactly 'plain'
    }
}

Describe 'Platform' {
    It 'warns nothing when the catalog fits the snapshot or names no platform' {
        Get-PlatformMismatch (Get-Framework 'DISA-STIG-Win11') (Get-Fixture) | Should -BeNullOrEmpty
        Get-PlatformMismatch $Catalog (Get-Fixture) | Should -BeNullOrEmpty
    }

    It 'warns when a Server STIG meets client Windows' {
        $w = Get-PlatformMismatch (Get-Framework 'DISA-STIG-WS2022-MS') (Get-Fixture)
        $w | Should -Match 'DISA-STIG-WS2022-MS'
        $w | Should -Match 'build 20348'
        $w | Should -Match 'is client Windows, build 26100'
    }

    It 'warns when the member server STIG meets a domain controller of the right build' {
        $s = Get-Fixture
        $s.Meta.ProductType = 2
        $s.Meta.OSVersion = '10.0.20348'
        Get-PlatformMismatch (Get-Framework 'DISA-STIG-WS2022-DC') $s | Should -BeNullOrEmpty
        Get-PlatformMismatch (Get-Framework 'DISA-STIG-WS2022-MS') $s | Should -Match 'is a domain controller'
    }

    It 'warns when the build is older than the catalog allows' {
        $s = Get-Fixture
        $s.Meta.OSVersion = '10.0.19045'
        Get-PlatformMismatch (Get-Framework 'DISA-STIG-Win11') $s | Should -Match 'build 22000 or later'
    }

    It 'warns when the snapshot does not say which Windows it came from' {
        $s = Get-Fixture
        $s.Meta.OSVersion = ''
        Get-PlatformMismatch (Get-Framework 'DISA-STIG-Win11') $s | Should -Match 'does not say|doesn''t say'
    }

    It 'carries the warning in the evaluation' {
        (Invoke-Evaluation (Get-Fixture) -Level $null -For (Get-Framework 'DISA-STIG-WS2025-DC')).PlatformWarning | Should -Match 'DISA-STIG-WS2025-DC'
    }

    It 'reports local-account checks as NotApplicable on a domain controller' {
        $s = Get-Fixture
        $s.Collection.LocalAccounts.Status = 'NotApplicable'
        $s.Collection.LocalAccounts.Reason = 'A domain controller has no local accounts; review domain accounts in Active Directory.'
        $s.LocalAccounts = $null
        foreach ($c in 'AC-GuestDisabled', 'AC-NoPasswordNotRequired', 'AC-LocalAdminCount') {
            $r = Get-CheckState $s $c
            $r.State | Should -Be 'NotApplicable' -Because $c
            $r.Evidence | Should -Match 'domain controller'
        }
        Get-ScanExitCode (Invoke-Evaluation $s).Requirements | Should -Be 0
    }
}

Describe 'Each check fails on a bad setting' {
    It '<Check> fails when <Case>' -ForEach @(
        @{ Check = 'AC-GuestDisabled'; Case = 'Guest is enabled'; Mutate = { param($s) ($s.LocalAccounts.Users | Where-Object Name -eq 'Guest').Enabled = $true } }
        @{ Check = 'AC-NoPasswordNotRequired'; Case = 'an enabled account needs no password'; Mutate = { param($s) ($s.LocalAccounts.Users | Where-Object Name -eq 'DefaultAccount').Enabled = $true } }
        @{ Check = 'AC-UacEnabled'; Case = 'EnableLUA is 0'; Mutate = { param($s) Write-RegFact $s "$Sys\EnableLUA" 0 } }
        @{ Check = 'AC-UacSecureDesktop'; Case = 'PromptOnSecureDesktop is 0'; Mutate = { param($s) Write-RegFact $s "$Sys\PromptOnSecureDesktop" 0 } }
        @{ Check = 'AC-UacPromptBehavior'; Case = 'admins elevate without a prompt'; Mutate = { param($s) Write-RegFact $s "$Sys\ConsentPromptBehaviorAdmin" 0 } }
        @{ Check = 'AC-UacPromptBehavior'; Case = 'the user prompt value is unknown'; Mutate = { param($s) Write-RegFact $s "$Sys\ConsentPromptBehaviorUser" 2 } }
        @{ Check = 'AC-LocalAdminCount'; Case = 'there are three admins'; Mutate = { param($s) $s.LocalAccounts.Administrators += 'WESTMARK-PC01\extra' } }
        @{ Check = 'AC-AccountLockout'; Case = 'the threshold is 0'; Mutate = { param($s) $s.SecurityPolicy.LockoutBadCount = 0 } }
        @{ Check = 'AC-AccountLockout'; Case = 'the threshold is 50'; Mutate = { param($s) $s.SecurityPolicy.LockoutBadCount = 50 } }
        @{ Check = 'AC-AccountLockout'; Case = 'the duration is 5 minutes'; Mutate = { param($s) $s.SecurityPolicy.LockoutDuration = 5 } }
        @{ Check = 'AC-LogonBanner'; Case = 'the caption is missing'; Mutate = { param($s) Write-RegFact $s "$Sys\LegalNoticeCaption" $null } }
        @{ Check = 'AC-LogonBanner'; Case = 'the text is blank'; Mutate = { param($s) Write-RegFact $s "$Sys\LegalNoticeText" '  ' } }
        @{ Check = 'AC-InactivityLock'; Case = 'no limit is set'; Mutate = { param($s) Write-RegFact $s "$Sys\InactivityTimeoutSecs" $null } }
        @{ Check = 'AC-InactivityLock'; Case = 'the limit is 30 minutes'; Mutate = { param($s) Write-RegFact $s "$Sys\InactivityTimeoutSecs" 1800 } }
        @{ Check = 'AC-RdpProtected'; Case = 'RDP is on without NLA'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication' 0 } }
        @{ Check = 'AC-RdpProtected'; Case = 'policy turns NLA off'; Mutate = { param($s) Write-RegFact $s "$TsPol\UserAuthentication" 0 } }
        @{ Check = 'AC-RdpIdleTimeout'; Case = 'RDP has no idle limit'; Mutate = { param($s) Write-RegFact $s "$TsPol\MaxIdleTime" $null } }
        @{ Check = 'AC-RdpIdleTimeout'; Case = 'the idle limit is an hour'; Mutate = { param($s) Write-RegFact $s "$TsPol\MaxIdleTime" 3600000 } }
        @{ Check = 'AU-AuditPolicy'; Case = 'Logon audits success only'; Mutate = { param($s) $s.AuditPolicy.'{0CCE9215-69AE-11D9-BED3-505054503030}' = 1 } }
        @{ Check = 'AU-AuditPolicy'; Case = 'a subcategory is missing from the export'; Mutate = { param($s) $s.AuditPolicy.PSObject.Properties.Remove('{0CCE922B-69AE-11D9-BED3-505054503030}') } }
        @{ Check = 'AU-SensitivePrivilegeUse'; Case = 'it is not audited'; Mutate = { param($s) $s.AuditPolicy.'{0CCE9228-69AE-11D9-BED3-505054503030}' = 0 } }
        @{ Check = 'AU-SecurityLogSize'; Case = 'the log is the 20 MB default'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize' $null } }
        @{ Check = 'AU-TimeSync'; Case = 'the sync type is NoSync'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type' 'NoSync' } }
        @{ Check = 'AU-TimeSync'; Case = 'Windows Time is disabled'; Mutate = { param($s) $s.Services.W32Time.StartType = 'Disabled' } }
        @{ Check = 'CM-Smb1Disabled'; Case = 'the SMBv1 client driver is on'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start' 2 } }
        @{ Check = 'CM-Smb1Disabled'; Case = 'the SMBv1 server is on'; Mutate = { param($s) $s.Smb.ServerEnabled = $true } }
        @{ Check = 'CM-Smb1Disabled'; Case = 'the registry turns the SMBv1 server on'; Mutate = { param($s) $s.Smb.ServerEnabled = $null; Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1' 1 } }
        @{ Check = 'CM-NonessentialServices'; Case = 'Remote Registry is Manual'; Mutate = { param($s) $s.Services.RemoteRegistry.StartType = 'Manual' } }
        @{ Check = 'CM-AlwaysInstallElevated'; Case = 'the machine policy is 1'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' 1 } }
        @{ Check = 'CM-AutoplayDisabled'; Case = 'NoDriveTypeAutoRun is the Windows default'; Mutate = { param($s) Write-RegFact $s "$Explorer\NoDriveTypeAutoRun" $null } }
        @{ Check = 'CM-AutoplayDisabled'; Case = 'NoAutorun is not set'; Mutate = { param($s) Write-RegFact $s "$Explorer\NoAutorun" $null } }
        @{ Check = 'CM-AutoplayDisabled'; Case = 'AutoPlay for non-volume devices is on'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume' 0 } }
        @{ Check = 'IA-BlankPasswordConsoleOnly'; Case = 'blank passwords work over the network'; Mutate = { param($s) Write-RegFact $s "$Lsa\LimitBlankPasswordUse" 0 } }
        @{ Check = 'IA-PasswordComplexity'; Case = 'the minimum length is 8'; Mutate = { param($s) $s.SecurityPolicy.MinimumPasswordLength = 8 } }
        @{ Check = 'IA-PasswordComplexity'; Case = 'complexity is off'; Mutate = { param($s) $s.SecurityPolicy.PasswordComplexity = 0 } }
        @{ Check = 'IA-PasswordHistory'; Case = 'history is 5'; Mutate = { param($s) $s.SecurityPolicy.PasswordHistorySize = 5 } }
        @{ Check = 'IA-StoredPasswordProtection'; Case = 'LM hashes are stored'; Mutate = { param($s) Write-RegFact $s "$Lsa\NoLMHash" 0 } }
        @{ Check = 'IA-StoredPasswordProtection'; Case = 'reversible encryption is on'; Mutate = { param($s) $s.SecurityPolicy.ClearTextPassword = 1 } }
        @{ Check = 'IA-NtlmV2Only'; Case = 'the level is the Windows default 3'; Mutate = { param($s) Write-RegFact $s "$Lsa\LmCompatibilityLevel" $null } }
        @{ Check = 'MP-RemovableStorage'; Case = 'no removable storage policy is set'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\Deny_Write' $null } }
        @{ Check = 'SC-FirewallEnabled'; Case = 'the Public profile is off'; Mutate = { param($s) ($s.Firewall | Where-Object Name -eq 'Public').Enabled = 'False' } }
        @{ Check = 'SC-FirewallEnabled'; Case = 'Private allows inbound'; Mutate = { param($s) ($s.Firewall | Where-Object Name -eq 'Private').DefaultInboundAction = 'Allow' } }
        @{ Check = 'SC-LegacyTlsDisabled'; Case = 'TLS 1.0 server is unset'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled' $null } }
        @{ Check = 'SC-LegacyTlsDisabled'; Case = 'TLS 1.1 client is on'; Mutate = { param($s) Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\Enabled' 1 } }
        @{ Check = 'SC-FipsMode'; Case = 'FIPS mode is off'; Mutate = { param($s) Write-RegFact $s "$Lsa\FipsAlgorithmPolicy\Enabled" 0 } }
        @{ Check = 'SC-BitLocker'; Case = 'protection is off'; Mutate = { param($s) $s.BitLocker.ProtectionStatus = 'Off' } }
        @{ Check = 'SC-BitLocker'; Case = 'BitLocker is not installed (Windows Server without the feature)'; Mutate = { param($s) $s.BitLocker.ProtectionStatus = 'NotInstalled' } }
        @{ Check = 'SI-UpdateRecency'; Case = 'the newest update is 80 days old'; Mutate = { param($s) $s.Hotfix.LatestInstalledOn = '2026-08-01T00:00:00Z' } }
        @{ Check = 'SI-UpdateRecency'; Case = 'no update has an install date'; Mutate = { param($s) $s.Hotfix.LatestInstalledOn = $null } }
        @{ Check = 'SI-AntivirusActive'; Case = 'Defender real-time is off and nothing else is registered'; Mutate = { param($s) $s.Defender.RealTimeProtectionEnabled = $false } }
        @{ Check = 'SI-SignatureAge'; Case = 'signatures are 19 days old'; Mutate = { param($s) $s.Defender.AntivirusSignatureLastUpdated = '2026-10-01T00:00:00Z' } }
        @{ Check = 'SI-ScanRecency'; Case = 'the last scan was 16 days ago'; Mutate = { param($s) $s.Defender.QuickScanEndTime = '2026-10-01T00:00:00Z' } }
    ) {
        $s = Get-Fixture
        & $Mutate $s
        $r = Get-CheckState $s $Check
        $r.State | Should -Be 'Fail' -Because $r.Evidence
    }
}

Describe 'BitLocker not installed' {
    It 'says BitLocker is not installed, rather than reporting a protection status' {
        $s = Get-Fixture
        $s.BitLocker.ProtectionStatus = 'NotInstalled'
        $r = Get-CheckState $s 'SC-BitLocker'
        $r.State | Should -Be 'Fail'
        $r.Evidence | Should -BeLike "*BitLocker isn't installed*C:*"
    }

    It 'recognises an unregistered CIM namespace by its error code, not its message' {
        $missing = [pscustomobject]@{ Exception = [pscustomobject]@{ NativeErrorCode = 'InvalidNamespace'; Message = 'Espace de noms non valide' } }
        $denied = [pscustomobject]@{ Exception = [pscustomobject]@{ NativeErrorCode = 'AccessDenied'; Message = 'Invalid namespace' } }
        $plain = [pscustomobject]@{ Exception = [InvalidOperationException]::new('Invalid namespace') }
        Test-CimInvalidNamespace $missing | Should -BeTrue
        Test-CimInvalidNamespace $denied | Should -BeFalse
        Test-CimInvalidNamespace $plain | Should -BeFalse
    }

    It 'recognises it by the error ID, or wrapped in another exception' {
        $byId = [pscustomobject]@{ FullyQualifiedErrorId = 'HRESULT 0x8004100e,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand'; Exception = [InvalidOperationException]::new('x') }
        $wrapped = [pscustomobject]@{ FullyQualifiedErrorId = 'ActionPreferenceStop'; Exception = [pscustomobject]@{ InnerException = [pscustomobject]@{ NativeErrorCode = 'InvalidNamespace' } } }
        $other = [pscustomobject]@{ FullyQualifiedErrorId = 'HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand'; Exception = [InvalidOperationException]::new('x') }
        Test-CimInvalidNamespace $byId | Should -BeTrue
        Test-CimInvalidNamespace $wrapped | Should -BeTrue
        Test-CimInvalidNamespace $other | Should -BeFalse
    }
}

Describe 'States other than Pass and Fail' {
    It 'treats RDP idle limits as not applicable when RDP is off' {
        $s = Get-Fixture
        Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections' 1
        (Get-CheckState $s 'AC-RdpIdleTimeout').State | Should -Be 'NotApplicable'
        (Get-CheckState $s 'AC-RdpProtected').State | Should -Be 'Pass'
    }

    It 'rolls a requirement whose only check is not applicable up to NotApplicable, not Pass' {
        $s = Get-Fixture
        Write-RegFact $s "$TsPol\fDenyTSConnections" 1
        $e = Invoke-Evaluation $s
        ($e.Requirements | Where-Object Requirement -eq '3.1.11').State | Should -Be 'NotApplicable'
    }

    It 'accepts a lockout that lasts until an administrator unlocks it' {
        $s = Get-Fixture
        $s.SecurityPolicy.LockoutDuration = -1
        (Get-CheckState $s 'AC-AccountLockout').State | Should -Be 'Pass'
    }

    It 'passes the UAC prompt defaults under the example and fails them under the STIG' {
        $s = Get-Fixture
        Write-RegFact $s "$Sys\ConsentPromptBehaviorAdmin" $null
        Write-RegFact $s "$Sys\ConsentPromptBehaviorUser" $null
        (Get-CheckState $s 'AC-UacPromptBehavior').State | Should -Be 'Pass'
        (Get-CheckState $s 'AC-UacPromptBehavior' (Get-Threshold (Get-Framework 'DISA-STIG-Win11'))).State | Should -Be 'Fail'
    }

    It 'uses the documented Windows default for an unset value and says so' {
        $s = Get-Fixture
        Write-RegFact $s "$Sys\EnableLUA" $null
        $r = Get-CheckState $s 'AC-UacEnabled'
        $r.State | Should -Be 'Pass'
        $r.Evidence | Should -Match 'Windows default'
    }

    It 'credits third-party antivirus reported to Security Center' {
        $s = Get-Fixture
        $s.Defender.RealTimeProtectionEnabled = $false
        $s.SecurityCenter = @([pscustomobject]@{ DisplayName = 'Contoso Antivirus'; ProductState = 0x41000 })
        (Get-CheckState $s 'SI-AntivirusActive').State | Should -Be 'Pass'
        (Get-CheckState $s 'SI-SignatureAge').State | Should -Be 'Pass'
        (Get-CheckState $s 'SI-ScanRecency').State | Should -Be 'Manual'
    }

    It 'fails third-party antivirus that reports stale signatures' {
        $s = Get-Fixture
        $s.Defender.RealTimeProtectionEnabled = $false
        $s.SecurityCenter = @([pscustomobject]@{ DisplayName = 'Contoso Antivirus'; ProductState = 0x41010 })
        (Get-CheckState $s 'SI-SignatureAge').State | Should -Be 'Fail'
    }

    It 'checks antivirus from Security Center alone when Defender is not collected' {
        $s = Get-Fixture
        $s.Collection.Defender.Status = 'Error'
        $s.Collection.Defender.Reason = 'service not running'
        $s.Defender = $null
        $s.SecurityCenter = @([pscustomobject]@{ DisplayName = 'Contoso Antivirus'; ProductState = 0x41000 })
        (Get-CheckState $s 'SI-AntivirusActive').State | Should -Be 'Pass'
    }

    It 'reports FIPS mode as Manual when the profile turns it off' {
        $t = Get-Threshold
        $t.RequireFipsMode = $false
        $s = Get-Fixture
        Write-RegFact $s "$Lsa\FipsAlgorithmPolicy\Enabled" 0
        (Get-CheckState $s 'SC-FipsMode' $t).State | Should -Be 'Manual'
    }

    It 'reports removable media as Manual when the profile turns it off' {
        $t = Get-Threshold
        $t.RequireRemovableMediaPolicy = $false
        (Get-CheckState (Get-Fixture) 'MP-RemovableStorage' $t).State | Should -Be 'Manual'
    }

    It 'skips SMBv1 when the server state is unknown' {
        $s = Get-Fixture
        $s.Smb.ServerEnabled = $null
        Write-RegFact $s 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1' $null
        (Get-CheckState $s 'CM-Smb1Disabled').State | Should -Be 'Skipped'
    }

    It 'skips the Security log size when its key is not readable' {
        $s = Get-Fixture
        Write-RegFact $s 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize' $null
        $f = $s.Registry.'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize'
        $f.Present = $false
        $f.Denied = $true
        (Get-CheckState $s 'AU-SecurityLogSize').State | Should -Be 'Skipped'
    }
}

Describe 'No silent passes' {
    It 'skips, never passes, the checks a non-elevated run cannot collect' {
        $s = Get-Fixture
        foreach ($sec in 'SecurityPolicy', 'AuditPolicy', 'BitLocker') {
            $s.Collection.$sec.Status = 'Skipped'
            $s.Collection.$sec.Reason = 'Needs an elevated session.'
            $s.$sec = $null
        }
        $e = Invoke-Evaluation $s
        $skipped = @($e.Checks | Where-Object State -eq 'Skipped' | ForEach-Object { $_.Check }) | Sort-Object
        $skipped | Should -Be (@('AC-AccountLockout', 'AU-AuditPolicy', 'AU-SensitivePrivilegeUse', 'IA-PasswordComplexity',
                'IA-PasswordHistory', 'IA-StoredPasswordProtection', 'SC-BitLocker') | Sort-Object)
        ($e.Requirements | Where-Object Requirement -eq '3.1.8').State | Should -Be 'Skipped'
        ($e.Requirements | Where-Object Requirement -eq '3.1.7').State | Should -Be 'Skipped'
        Get-ScanExitCode $e.Requirements | Should -Be 0
    }

    It 'errors every check that reads a section whose collector failed' {
        $s = Get-Fixture
        $s.Collection.Registry.Status = 'Error'
        $s.Collection.Registry.Reason = 'test'
        $e = Invoke-Evaluation $s
        ($e.Checks | Where-Object Check -eq 'AC-UacEnabled').State | Should -Be 'Error'
        Get-ScanExitCode $e.Requirements | Should -Be 2
    }

    It 'errors a check whose section has no collection record' {
        $s = Get-Fixture
        $s.Collection.PSObject.Properties.Remove('Firewall')
        (Get-CheckState $s 'SC-FirewallEnabled').State | Should -Be 'Error'
    }

    It 'errors a check when registry value <Key> is missing from the snapshot' -ForEach @(
        Get-RegistryTarget | ForEach-Object { @{ Key = $_ } }
    ) {
        $s = Get-Fixture
        $s.Registry.PSObject.Properties.Remove($Key)
        $e = Invoke-Evaluation $s
        $errors = @($e.Checks | Where-Object { $_.State -eq 'Error' -and $_.Evidence -like "*$Key*" })
        $errors.Count | Should -BeGreaterThan 0 -Because 'a missing fact must surface as an Error'
        @($e.Checks | Where-Object State -eq 'Pass').Count | Should -BeLessThan @($e.Checks).Count
    }

    It 'holds every registry value the named checks read, and no other, in the fixture' {
        $fixtureKeys = @((Get-Fixture).Registry.PSObject.Properties.Name) | Sort-Object
        $fixtureKeys | Should -Be (@(Get-RegistryTarget) | Sort-Object)
    }

    It 'errors a check that names an unknown audit setting' {
        $t = Get-Threshold
        $t.AuditSubcategories = @(@{ Name = 'Logon'; Setting = 'Sometimes' })
        (Get-CheckState (Get-Fixture) 'AU-AuditPolicy' $t).State | Should -Be 'Error'
    }

    It 'errors a check that names an unknown audit subcategory' {
        $t = Get-Threshold
        $t.AuditSubcategories = @(@{ Name = 'Logons'; Setting = 'Success' })
        (Get-CheckState (Get-Fixture) 'AU-AuditPolicy' $t).State | Should -Be 'Error'
    }

    It 'errors a check that needs a missing service record' {
        $s = Get-Fixture
        $s.Services.PSObject.Properties.Remove('SNMP')
        (Get-CheckState $s 'CM-NonessentialServices').State | Should -Be 'Error'
    }

    It 'errors rather than passes when no local accounts were returned' {
        $s = Get-Fixture
        $s.LocalAccounts.Users = @()
        (Get-CheckState $s 'AC-NoPasswordNotRequired').State | Should -Be 'Error'
    }

    It 'refuses a catalog entry that names an unknown check' {
        $bad = @{ Id = 'T'; Levels = @('L1'); Requirements = @(@{ Id = '3.1.1'; Family = 'AC'; Level = 'L1'; Title = 't'; Checks = @('AC-Nope') }) }
        { Invoke-ComplianceEvaluation -Snapshot (Get-Fixture) -Thresholds (Get-Threshold) -Catalog $bad } | Should -Throw '*unknown check*'
    }

    It 'refuses a catalog entry whose level is not in Levels' {
        $bad = @{ Id = 'T'; Levels = @('L1'); Requirements = @(@{ Id = '3.1.1'; Family = 'AC'; Level = 'L9'; Title = 't'; Checks = @() }) }
        { Invoke-ComplianceEvaluation -Snapshot (Get-Fixture) -Thresholds (Get-Threshold) -Catalog $bad } | Should -Throw "*level 'L9'*"
    }

    It 'refuses a snapshot with another schema version' {
        $path = Join-Path $TestDrive 'old.json'
        $s = Get-Fixture
        $s.SchemaVersion = 99
        $s | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        { Read-Snapshot $path } | Should -Throw '*schema version*'
    }

    It 'reads a schema 5 snapshot, which has no AsSystem, as a scan run by a user' {
        $path = Join-Path $TestDrive 'schema5.json'
        $s = Get-Fixture
        $s.SchemaVersion = 5
        $s.Meta.PSObject.Properties.Remove('AsSystem')
        $s | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        $e = @{ Source = 'Registry'; Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Op = 'ne'; Value = 1; AbsentOk = $true }
        (Test-Expectation (Read-Snapshot $path) $e).State | Should -Be 'Pass'
    }
}

Describe 'Per-user settings in a scan run as SYSTEM' {
    BeforeAll {
        $script:UserExpect = @{ Source = 'Registry'; Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Op = 'ne'; Value = 1; AbsentOk = $true }
        $script:MachineExpect = @{ Source = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Op = 'ne'; Value = 1; AbsentOk = $true }
    }

    It 'judges an HKCU setting as usual in a scan run by a user' {
        (Test-Expectation (Get-Fixture) $UserExpect).State | Should -Be 'Pass'
    }

    It 'skips an HKCU setting, saying why, when the scan ran as SYSTEM' {
        $s = Get-Fixture
        $s.Meta.AsSystem = $true
        $r = Test-Expectation $s $UserExpect
        $r.State | Should -Be 'Skipped'
        $r.Evidence | Should -BeLike '*per-user*ran as SYSTEM*'
    }

    It 'skips it even when the SYSTEM value would fail, so no false finding is reported' {
        $s = Get-Fixture
        $s.Meta.AsSystem = $true
        Write-RegFact $s 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' 1
        (Test-Expectation $s $UserExpect).State | Should -Be 'Skipped'
    }

    It 'still judges HKLM settings when the scan ran as SYSTEM' {
        $s = Get-Fixture
        $s.Meta.AsSystem = $true
        (Test-Expectation $s $MachineExpect).State | Should -Be 'Pass'
    }

    It 'covers every HKCU expectation in the STIG catalogs' {
        $s = Get-Fixture
        $s.Meta.AsSystem = $true
        $user = @(foreach ($c in $Catalogs) { foreach ($r in @($c.Requirements)) { if ($r.Contains('Expect')) { @($r.Expect) | Where-Object { $_.Contains('Path') -and "$($_.Path)" -like 'HKCU:*' } } } })
        $user.Count | Should -BeGreaterThan 0
        foreach ($e in $user) { (Test-Expectation $s $e).State | Should -Be 'Skipped' -Because "$($e.Path)\$($e.Name)" }
    }
}

Describe 'Accepted deviations' {
    BeforeAll {
        $script:DevFw = @{
            Id = 'SAMPLE-DEV'; Name = 'Sample deviations'; Source = 'https://example.invalid'
            Levels = @('One'); Complete = $true; Thresholds = @{}
            Requirements = @(
                @{ Id = 'R-1'; Family = 'X'; Level = 'One'; Title = 'Audit right'; Checks = @()
                    Expect = @(@{ Source = 'UserRight'; Name = 'SeAuditPrivilege'; Op = 'only'; Identities = @('Local Service', 'Network Service') }) }
                @{ Id = 'R-2.a'; Family = 'X'; Level = 'One'; Title = 'UAC part'; Checks = @('AC-UacEnabled') }
                @{ Id = 'R-3'; Family = 'X'; Level = 'One'; Title = 'BitLocker'; Checks = @('SC-BitLocker') }
                @{ Id = 'R-4'; Family = 'X'; Level = 'One'; Title = 'UAC'; Checks = @('AC-UacEnabled') }
                @{ Id = 'R-5'; Family = 'X'; Level = 'One'; Title = 'UAC and BitLocker'; Checks = @('AC-UacEnabled', 'SC-BitLocker') }
            )
        }
        $script:Spooler = [pscustomobject]@{ Sid = 'S-1-5-99-1000000021-1000000022-1000000023-1000000024-1000000025'; Name = 'RESTRICTED SERVICES\PrintSpoolerService' }
        $script:SpoolerRule = @{ Rule = 'R-1'; Identity = 'RESTRICTED SERVICES\PrintSpoolerService'; Reason = 'Server default; accepted by the ISSM.' }
        function Get-DevSnapshot {
            # The print spooler holds SeAuditPrivilege beside the two allowed
            # services, plus any $Extra holders; UAC is off.
            param([object[]]$Extra = @())
            $s = Get-Fixture
            Write-Fact $s.UserRights 'SeAuditPrivilege' @(@((Get-IdentityEntry 'Local Service'), (Get-IdentityEntry 'Network Service'), $Spooler) + $Extra)
            Write-RegFact $s "$Sys\EnableLUA" 0
            $s
        }
        function Get-DevEvaluation {
            param([object[]]$Deviation, $Snapshot = (Get-DevSnapshot), $For = $DevFw)
            $t = Get-Threshold
            $t.Deviations = @($Deviation)
            Invoke-Evaluation $Snapshot -Thresholds $t -Level 'One' -For $For
        }
        function Get-DevResult {
            param([object[]]$Deviation, $Snapshot = (Get-DevSnapshot), [string]$Id = 'R-1')
            @((Get-DevEvaluation $Deviation $Snapshot).Requirements | Where-Object Requirement -eq $Id)[0]
        }
    }

    It 'fails the rule when no deviation is listed' {
        (Get-DevResult @()).State | Should -Be 'Fail'
        (Get-DevEvaluation @()).Requirements.State | Should -Not -Contain 'Accepted'
    }

    It 'accepts a user right held by the exact account the deviation names, keeping the evidence and the reason' {
        $r = Get-DevResult @($SpoolerRule)
        $r.State | Should -Be 'Accepted'
        $r.Checks | Should -Match '=Accepted'
        $r.Findings | Should -Match 'PrintSpoolerService'
        $r.Note | Should -Match 'Accepted deviation: Server default; accepted by the ISSM\.'
    }

    It 'matches the account by SID too' {
        (Get-DevResult @(@{ Rule = 'R-1'; Identity = $Spooler.Sid; Reason = 'r' })).State | Should -Be 'Accepted'
    }

    It 'still fails when another account also holds the right' {
        $r = Get-DevResult @($SpoolerRule) (Get-DevSnapshot @(Get-IdentityEntry 'Guests'))
        $r.State | Should -Be 'Fail'
        $r.Note | Should -Match "accepts only RESTRICTED SERVICES\\PrintSpoolerService, which doesn't cover every finding"
    }

    It 'never matches a look-alike account: the name must be exact' {
        (Get-DevResult @(@{ Rule = 'R-1'; Identity = 'PrintSpoolerService'; Reason = 'r' })).State | Should -Be 'Fail'
        (Get-DevResult @(@{ Rule = 'R-1'; Identity = 'OTHER\PrintSpoolerService'; Reason = 'r' })).State | Should -Be 'Fail'
    }

    It 'does not let an Identity deviation accept a rule that is not a user right' {
        $r = Get-DevResult @(@{ Rule = 'R-4'; Identity = 'RESTRICTED SERVICES\PrintSpoolerService'; Reason = 'r' }) -Id 'R-4'
        $r.State | Should -Be 'Fail'
        $r.Note | Should -Match "doesn't cover every finding \(AC-UacEnabled\)"
    }

    It 'accepts any Fail of the rule when the deviation names no account' {
        (Get-DevResult @(@{ Rule = 'R-4'; Reason = 'UAC is off on this kiosk by design.' }) -Id 'R-4').State | Should -Be 'Accepted'
    }

    It 'covers the parts of a split rule' {
        (Get-DevResult @(@{ Rule = 'R-2'; Reason = 'r' }) -Id 'R-2.a').State | Should -Be 'Accepted'
    }

    It 'leaves a shared check''s result alone for the requirements the deviation does not name' {
        $e = Get-DevEvaluation @(@{ Rule = 'R-4'; Reason = 'r' })
        ($e.Requirements | Where-Object Requirement -eq 'R-4').State | Should -Be 'Accepted'
        ($e.Requirements | Where-Object Requirement -eq 'R-2.a').State | Should -Be 'Fail'
        ($e.Checks | Where-Object Check -eq 'AC-UacEnabled').State | Should -Be 'Fail'
    }

    It 'never accepts an Error' {
        $s = Get-DevSnapshot
        $s.Collection.BitLocker.Status = 'Error'
        $s.Collection.BitLocker.Reason = 'Access denied.'
        (Get-DevResult @(@{ Rule = 'R-3'; Reason = 'r' }) $s -Id 'R-3').State | Should -Be 'Error'
        $r = Get-DevResult @(@{ Rule = 'R-5'; Reason = 'r' }) $s -Id 'R-5'
        $r.State | Should -Be 'Error'
        $r.Checks | Should -Be 'AC-UacEnabled=Accepted; SC-BitLocker=Error'
    }

    It 'applies only to the framework it names' {
        (Get-DevResult @(@{ Rule = 'R-4'; Framework = 'SAMPLE-DEV'; Reason = 'r' }) -Id 'R-4').State | Should -Be 'Accepted'
        (Get-DevResult @(@{ Rule = 'R-4'; Framework = 'DISA-STIG-WS2025-DC'; Reason = 'r' }) -Id 'R-4').State | Should -Be 'Fail'
    }

    It 'applies through its Expires day and not after, saying so (the fixture was collected 2026-10-20)' {
        (Get-DevResult @(@{ Rule = 'R-4'; Reason = 'r'; Expires = '2026-10-20' }) -Id 'R-4').State | Should -Be 'Accepted'
        (Get-DevResult @(@{ Rule = 'R-4'; Reason = 'r'; Expires = '2026-10-20' }) -Id 'R-4').Note | Should -Match '\(until 2026-10-20\)'
        $r = Get-DevResult @(@{ Rule = 'R-4'; Reason = 'r'; Expires = '2026-10-19' }) -Id 'R-4'
        $r.State | Should -Be 'Fail'
        $r.Note | Should -Match 'expired on 2026-10-19'
    }

    It 'says when a listed deviation has nothing left to accept' {
        $s = Get-DevSnapshot
        Write-RegFact $s "$Sys\EnableLUA" 1
        $r = Get-DevResult @(@{ Rule = 'R-4'; Reason = 'r' }) $s -Id 'R-4'
        $r.State | Should -Be 'Pass'
        $r.Note | Should -Match 'nothing in it failed'
    }

    It 'refuses a deviation with <Why>' -ForEach @(
        @{ Why = 'no Rule'; Entry = @{ Reason = 'r' }; Message = '*no Rule*' }
        @{ Why = 'no Reason'; Entry = @{ Rule = 'R-1' }; Message = '*no Reason*' }
        @{ Why = 'an unknown key'; Entry = @{ Rule = 'R-1'; Reason = 'r'; Account = 'x' }; Message = "*unknown key 'Account'*" }
        @{ Why = 'a date that is not yyyy-MM-dd'; Entry = @{ Rule = 'R-1'; Reason = 'r'; Expires = '30/06/2027' }; Message = '*use yyyy-MM-dd*' }
        @{ Why = 'an entry that is not a hashtable'; Entry = 'R-1'; Message = '*is a hashtable*' }
    ) {
        { Get-DevEvaluation @($Entry) } | Should -Throw $Message
    }

    It 'reads Deviations from the local settings file' {
        $path = Join-Path $TestDrive 'dev.psd1'
        Set-Content -LiteralPath $path -Value "@{ Deviations = @( @{ Rule = 'R-4'; Reason = 'r' } ) }"
        $t = Get-ScanThreshold -ExamplePath $ExamplePath -OverridePath $path
        $e = Invoke-Evaluation (Get-DevSnapshot) -Thresholds $t -Level 'One' -For $DevFw
        ($e.Requirements | Where-Object Requirement -eq 'R-4').State | Should -Be 'Accepted'
        @((Get-Threshold).Deviations).Count | Should -Be 0 -Because 'the shipped example accepts nothing'
    }

    It 'exits 0 when every Fail is accepted' {
        $e = Get-DevEvaluation @($SpoolerRule, @{ Rule = 'R-2'; Reason = 'r' }, @{ Rule = 'R-4'; Reason = 'r' }, @{ Rule = 'R-5'; Reason = 'r' })
        @($e.Requirements | Where-Object State -eq 'Fail').Count | Should -Be 0
        Get-ScanExitCode $e.Requirements | Should -Be 0
    }

    It 'shows accepted deviations in the HTML report, the JSON summary and the records' {
        $e = Get-DevEvaluation @($SpoolerRule)
        $html = ConvertTo-HtmlReport $e (Get-DevSnapshot) $DevFw
        $html | Should -Match '<b class="Accepted">1</b>Accepted deviation'
        $html | Should -Match 'data-state="Accepted"'
        $html | Should -Match 'value="Accepted" checked'
        $files = Export-ScanReport -Evaluation $e -Snapshot (Get-DevSnapshot) -Thresholds (Get-Threshold) -Catalog $DevFw -Folder (Join-Path $TestDrive 'dev')
        $json = Get-Content -LiteralPath @($files | Where-Object { $_ -like '*-sample-dev.json' })[0] -Raw | ConvertFrom-Json
        $json.Summary.Accepted | Should -Be 1
        $records = Get-Content -LiteralPath @($files | Where-Object { $_ -like '*.records.json' })[0] -Raw | ConvertFrom-Json
        ($records | Where-Object Requirement -eq 'R-1').State | Should -Be 'Accepted'
    }

    It 'keeps an accepted rule Open in a STIG Viewer checklist, with the reason in the comments' {
        $fw = @{
            Id = 'SAMPLE-STIG'; Name = 'Sample STIG'; Source = 'https://example.invalid'; StigId = 'Sample_Westmark_STIG'
            Levels = @('CAT I', 'CAT II', 'CAT III'); Complete = $true; Thresholds = @{}
            Requirements = @(@{ Id = 'V-900001'; Family = 'X'; Level = 'CAT II'; Title = 'UAC'; Checks = @('AC-UacEnabled') })
        }
        $t = Get-Threshold
        $t.Deviations = @(@{ Rule = 'V-900001'; Reason = 'UAC is off on this kiosk by design.' })
        $s = Get-DevSnapshot
        $e = Invoke-Evaluation $s -Thresholds $t -Level 'CAT III' -For $fw
        $c = Get-ChecklistResult $e $s $fw (Read-StigBenchmark (Join-Path $PSScriptRoot 'fixtures/stig-sample-xccdf.xml'))
        $c.Entries['V-900001'].Status | Should -Be 'Open'
        $c.Entries['V-900001'].Comments | Should -Match 'Accepted\. Accepted deviation: UAC is off on this kiosk by design\.'
        $c.Entries['V-900001'].Details | Should -Match 'V-900001 Accepted: AC-UacEnabled: EnableLUA = 0'
    }
}

Describe 'Collector progress' {
    It 'names every collector, in the order the scan runs them' {
        $run = @([regex]::Matches((Get-Content -LiteralPath $ScriptPath -Raw), 'Invoke-Collector \$snap ''(\w+)''') | ForEach-Object { $_.Groups[1].Value })
        $run.Count | Should -BeGreaterThan 0
        $run | Should -Be @($CollectorLabel.Keys)
    }
}

Describe 'Console output' {
    It 'wraps between words, never inside one (regression: the launch line broke "a l" / "arge")' {
        $text = 'Scanning WESTMARK-PC01 for DISA Windows PAW STIG V3R3. This usually takes 2 to 5 minutes, longer on a domain controller with a large directory, and changes nothing on the machine.'
        $lines = Format-WrappedText $text 60 4
        $lines.Count | Should -BeGreaterThan 2
        foreach ($l in $lines) { $l.Length | Should -BeLessOrEqual 60 }
        foreach ($l in $lines[1..($lines.Count - 1)]) { $l | Should -Match '^    \S' }
        (($lines | ForEach-Object { $_.Trim() }) -join ' ') | Should -Be $text
    }

    It 'keeps padded columns aligned on the first line' {
        $lines = Format-WrappedText ('{0,-8} {1,-14} {2}' -f 'Fail', 'V-243457', 'Registry:scforceoption: scforceoption = 0; needs 1.') 50 24
        $lines | Should -Be @(
            'Fail     V-243457       Registry:scforceoption:'
            '                        scforceoption = 0; needs'
            '                        1.'
        )
    }

    It 'leaves text on one line when there is no console width' {
        $lines = Format-WrappedText 'one two three' 0 4
        @($lines).Count | Should -Be 1
        $lines[0] | Should -Be 'one two three'
    }

    It 'puts a word longer than the line on its own line rather than splitting it' {
        $path = 'C:\Reports\compliance-scan-WESTMARK-PC01-20261020T150000Z-disa-stig-paw.records.json'
        $lines = Format-WrappedText "Reports: $path done" 30 2
        $lines | Should -Contain "  $path"
    }

    It 'sets the launch notice apart and warns about elevation only when not elevated' {
        $fw = Get-Framework 'DISA-STIG-PAW'
        $out = @(Write-ScanBanner -Computer 'WESTMARK-PC01' -Catalog $fw -Elevated $true 6>&1 | ForEach-Object { "$_" })
        $out[0] | Should -Be ''
        $out[1] | Should -Be "Endpoint compliance scan $ComplianceScanVersion"
        $out | Should -Contain "  Scanning   WESTMARK-PC01 for $($fw.Name)"
        ($out -join "`n") | Should -Match 'Usually 2 to 5 minutes'
        ($out -join "`n") | Should -Not -Match 'Elevation'
        $out[-1] | Should -Be ''
        $low = @(Write-ScanBanner -Computer 'WESTMARK-PC01' -Catalog $fw -Elevated $false 6>&1 | ForEach-Object { "$_" })
        ($low -join "`n") | Should -Match 'Elevation  Not elevated: checks that need it will be Skipped'
    }

    It 'lists the report files one per line under their folder' {
        $folder = Join-Path $TestDrive 'r'
        $files = @((Join-Path $folder 'a.csv'), (Join-Path $folder 'a.html'))
        $out = @(Write-ReportList $files 6>&1 | ForEach-Object { "$_" })
        $out | Should -Be @("Reports in ${folder}:", '  a.csv', '  a.html')
    }
}

Describe 'Exit codes' {
    It 'gives <Want> for <States>' -ForEach @(
        @{ States = @('Pass', 'Manual'); Want = 0 }
        @{ States = @('Pass', 'Skipped', 'NotApplicable'); Want = 0 }
        @{ States = @('Pass', 'Accepted'); Want = 0 }
        @{ States = @('Accepted', 'Fail'); Want = 1 }
        @{ States = @('Pass', 'Fail'); Want = 1 }
        @{ States = @('Fail', 'Error'); Want = 2 }
        @{ States = @('Error'); Want = 2 }
    ) {
        Get-ScanExitCode @($States | ForEach-Object { [pscustomobject]@{ State = $_ } }) | Should -Be $Want
    }
}

Describe 'Thresholds' {
    It 'lets a profile override a known key' {
        $path = Join-Path $TestDrive 'p.psd1'
        Set-Content -LiteralPath $path -Value '@{ MinPasswordLength = 16 }'
        (Get-ScanThreshold -ExamplePath $ExamplePath -OverridePath $path).MinPasswordLength | Should -Be 16
    }

    It 'applies the framework''s thresholds over the example' {
        $t = Get-Threshold (Get-Framework 'DISA-STIG-Win11')
        $t.MinPasswordLength | Should -Be 14
        $t.LockoutThresholdMax | Should -Be 3
        $t.MaxLocalAdmins | Should -Be 2
    }

    It 'lets a profile override a framework value, warning when it is looser' {
        $path = Join-Path $TestDrive 'loose.psd1'
        Set-Content -LiteralPath $path -Value '@{ MinPasswordLength = 12; LockoutThresholdMax = 2 }'
        $t = Get-ScanThreshold -ExamplePath $ExamplePath -Catalog (Get-Framework 'DISA-STIG-Win11') -OverridePath $path -WarningVariable w -WarningAction SilentlyContinue
        $t.MinPasswordLength | Should -Be 12
        $t.LockoutThresholdMax | Should -Be 2
        @($w).Count | Should -Be 1
        "$w" | Should -Match 'MinPasswordLength'
    }

    It 'refuses a framework that sets an unknown threshold' {
        $fw = @{ Id = 'T'; Thresholds = @{ MinPaswordLength = 16 } }
        { Get-ScanThreshold -ExamplePath $ExamplePath -Catalog $fw } | Should -Throw '*unknown threshold*'
    }

    It 'ignores an unknown key with a warning' {
        $path = Join-Path $TestDrive 'q.psd1'
        Set-Content -LiteralPath $path -Value '@{ MinPaswordLength = 16 }'
        $t = Get-ScanThreshold -ExamplePath $ExamplePath -OverridePath $path -WarningVariable w -WarningAction SilentlyContinue
        $t.ContainsKey('MinPaswordLength') | Should -BeFalse
        "$w" | Should -Match 'Unknown threshold'
    }
}

Describe 'Reports' {
    BeforeAll {
        $script:Eval = Invoke-Evaluation (Get-Fixture)
    }

    It 'names a scan by computer and collection time, UTC' {
        Get-ScanId (Get-Fixture) | Should -Be 'WESTMARK-PC01-20261020T150000Z'
    }

    It 'writes one flat record per requirement, each carrying the scan' {
        $records = @(ConvertTo-ScanRecord $Eval (Get-Fixture) $Catalog)
        $records.Count | Should -Be 110
        foreach ($k in 'ScanId', 'ComputerName', 'CollectedUtc', 'Framework', 'FrameworkLevel', 'Requirement', 'Reference', 'Family', 'State', 'Findings') {
            $records[0].Contains($k) | Should -BeTrue -Because $k
        }
        @($records | ForEach-Object { $_.ScanId } | Select-Object -Unique) | Should -Be 'WESTMARK-PC01-20261020T150000Z'
        $records[0].CollectedUtc | Should -Be '2026-10-20T15:00:00.0000000Z'
        ($records | Where-Object Requirement -eq '3.1.8').Reference | Should -Be 'AC.L2-3.1.8'
    }

    It 'writes the records as a JSON array even for a one-requirement framework' {
        $fw = @{ Id = 'T'; Name = 'T'; Source = 'https://example.invalid'; Levels = @('One'); Complete = $true; Thresholds = @{}
            Requirements = @(@{ Id = '1'; Family = 'X'; Level = 'One'; Title = 't'; Checks = @('AC-UacEnabled') }) }
        $e = Invoke-Evaluation (Get-Fixture) -Level 'One' -For $fw
        $files = Export-ScanReport -Evaluation $e -Snapshot (Get-Fixture) -Thresholds (Get-Threshold) -Catalog $fw -Folder (Join-Path $TestDrive 'one')
        $path = @($files | Where-Object { $_ -like '*.records.json' })[0]
        (Get-Content -LiteralPath $path -Raw).TrimStart() | Should -Match '^\['
        @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).Count | Should -Be 1
    }

    It 'replaces its reports when the same snapshot is evaluated again' {
        $folder = Join-Path $TestDrive 'again'
        $first = Export-ScanReport -Evaluation $Eval -Snapshot (Get-Fixture) -Thresholds (Get-Threshold) -Catalog $Catalog -Folder $folder
        $second = Export-ScanReport -Evaluation $Eval -Snapshot (Get-Fixture) -Thresholds (Get-Threshold) -Catalog $Catalog -Folder $folder
        $second | Should -Be $first
        @(Get-ChildItem -LiteralPath $folder).Count | Should -Be 4
    }

    It 'says when a STIG is retired, and when no checklist will be written' {
        $notes = @(Get-CatalogNotice (Get-Framework 'DISA-STIG-WS2019-MS'))
        $notes.Count | Should -Be 2
        $notes[0] | Should -BeLike 'Retired STIG: DISA has sunset this STIG*not current DISA guidance.'
        $notes[1] | Should -BeLike 'No STIG Viewer checklists*'
        @(Get-CatalogNotice (Get-Framework 'DISA-STIG-WS2019-DC') -HasStig) | Should -BeLike 'Retired STIG:*'
        @(Get-CatalogNotice (Get-Framework 'DISA-STIG-WS2022-MS') -HasStig).Count | Should -Be 0
        @(Get-CatalogNotice (Get-Framework 'CMMC')).Count | Should -Be 0
    }

    It 'shows the retired notice on the HTML report' {
        $fw = Get-Framework 'DISA-STIG-WS2019-MS'
        $html = ConvertTo-HtmlReport (Invoke-Evaluation (Get-Fixture) -Level 'CAT III' -For $fw) (Get-Fixture) $fw @(Get-CatalogNotice $fw -HasStig)
        $html | Should -Match 'Retired STIG: DISA has sunset this STIG'
    }

    It 'writes a relative -OutputPath under the PowerShell location, not the process folder' {
        # The roll-up's first run on a PC: .NET resolved .\Reports against the home folder.
        $here = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'here')
        $elsewhere = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'elsewhere')
        $was = [Environment]::CurrentDirectory
        Push-Location -LiteralPath $here.FullName
        try {
            [Environment]::CurrentDirectory = $elsewhere.FullName
            $files = Export-ScanReport -Evaluation $Eval -Snapshot (Get-Fixture) -Thresholds (Get-Threshold) -Catalog $Catalog -Folder (Join-Path '.' 'out')
        } finally {
            [Environment]::CurrentDirectory = $was
            Pop-Location
        }
        @(Get-ChildItem -LiteralPath (Join-Path $here.FullName 'out')).Count | Should -Be 4
        @(Get-ChildItem -LiteralPath $elsewhere.FullName).Count | Should -Be 0
        $files | ForEach-Object { [IO.Path]::IsPathRooted($_) | Should -BeTrue }
    }

    It 'writes a self-contained HTML report with every requirement' {
        $html = ConvertTo-HtmlReport $Eval (Get-Fixture) $Catalog
        $html | Should -Match '^<!doctype html>'
        $html | Should -Not -Match '<script src|<link |https?://(?!example)'
        ([regex]::Matches($html, '<tr data-state=')).Count | Should -Be 110
        $html | Should -Match 'WESTMARK-PC01-20261020T150000Z'
    }

    It 'escapes catalog and evidence text in the HTML report' {
        $fw = @{ Id = 'T'; Name = 'T <b>bold</b>'; Source = 'https://example.invalid'; Levels = @('One'); Complete = $false; Thresholds = @{}
            Requirements = @(@{ Id = '1'; Family = 'X&Y'; Level = 'One'; Title = '<script>alert(1)</script>'; Checks = @(); Note = 'a < b' }) }
        $html = ConvertTo-HtmlReport (Invoke-Evaluation (Get-Fixture) -Level 'One' -For $fw) (Get-Fixture) $fw @('notice <i>')
        $html | Should -Not -Match '<script>alert|<b>bold|<i>'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should -Match 'X&amp;Y'
        $html | Should -Match 'lists only the requirements'
        $html | Should -Match 'notice &lt;i&gt;'
    }

    It 'shows the platform warning in the HTML report' {
        $fw = Get-Framework 'DISA-STIG-WS2022-MS'
        ConvertTo-HtmlReport (Invoke-Evaluation (Get-Fixture) -Level 'CAT I' -For $fw) (Get-Fixture) $fw | Should -Match 'is written for Windows Server'
    }
}

Describe 'STIG Viewer checklist' {
    BeforeAll {
        $script:XccdfPath = Join-Path $PSScriptRoot 'fixtures/stig-sample-xccdf.xml'
        $script:StigFw = @{
            Id = 'SAMPLE-STIG'; Name = 'Sample STIG'; Source = 'https://example.invalid'; StigId = 'Sample_Westmark_STIG'
            Levels = @('CAT I', 'CAT II', 'CAT III'); Complete = $true; Thresholds = @{}
            Requirements = @(
                @{ Id = 'V-900001'; Family = 'X'; Level = 'CAT II'; Title = 'UAC'; Checks = @('AC-UacEnabled') }
                @{ Id = 'V-900002.a'; Family = 'X'; Level = 'CAT I'; Title = 'UAC part'; Checks = @('AC-UacEnabled') }
                @{ Id = 'V-900002.b'; Family = 'X'; Level = 'CAT I'; Title = 'BitLocker part'; Checks = @('SC-BitLocker') }
                @{ Id = 'V-900003'; Family = 'X'; Level = 'CAT III'; Title = 'RDP idle'; Checks = @('AC-RdpIdleTimeout') }
                @{ Id = 'V-900005'; Family = 'X'; Level = 'CAT II'; Title = 'Review'; Checks = @(); Note = 'Review the accounts.' }
            )
        }
        function Get-Checklist {
            param([string]$Level = 'CAT III')
            $s = Get-Fixture
            $s.BitLocker.ProtectionStatus = 'Off'
            Write-RegFact $s "$TsPol\fDenyTSConnections" 1
            $e = Invoke-Evaluation $s -Level $Level -For $StigFw
            $c = ConvertTo-StigChecklist $e $s $StigFw (Read-StigBenchmark $XccdfPath)
            [pscustomobject]@{ Result = $c; Xml = [xml]$c.Xml }
        }
        function Get-Vuln {
            param($Xml, [string]$Id)
            $Xml.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { ($_.STIG_DATA | Where-Object VULN_ATTRIBUTE -eq 'Vuln_Num').ATTRIBUTE_DATA -eq $Id }
        }
        function Get-ChecklistJson {
            param([string]$Level = 'CAT III')
            $s = Get-Fixture
            $s.BitLocker.ProtectionStatus = 'Off'
            Write-RegFact $s "$TsPol\fDenyTSConnections" 1
            $e = Invoke-Evaluation $s -Level $Level -For $StigFw
            $c = ConvertTo-StigChecklistJson $e $s $StigFw (Read-StigBenchmark $XccdfPath) -Title 'sample'
            [pscustomobject]@{ Result = $c; Text = $c.Json; Doc = ($c.Json | ConvertFrom-Json) }
        }
        function Get-JsonRule {
            param($Doc, [string]$Id)
            @($Doc.stigs[0].rules | Where-Object group_id -eq $Id)[0]
        }
        function Get-VulnData {
            param($Vuln, [string]$Attribute)
            @($Vuln.STIG_DATA | Where-Object VULN_ATTRIBUTE -eq $Attribute | ForEach-Object { $_.ATTRIBUTE_DATA })
        }
    }

    It 'reads the rules of an XCCDF benchmark' {
        $b = Read-StigBenchmark $XccdfPath
        $b.Id | Should -Be 'Sample_Westmark_STIG'
        $b.Version | Should -Be '1'
        $b.ReleaseInfo | Should -Be 'Release: 3 Benchmark Date: 01 Apr 2026'
        @($b.Rules).Count | Should -Be 5
        $r = $b.Rules[0]
        $r.GroupId | Should -Be 'V-900001'
        $r.RuleId | Should -Be 'SV-900001r1_rule'
        $r.RuleVersion | Should -Be 'WM-00-000001'
        $r.Severity | Should -Be 'medium'
        $r.Discussion | Should -Be 'UAC limits what software can do.'
        $r.Documentable | Should -Be 'false'
        $r.CheckContentRef | Should -Be 'M'
        $r.TargetKey | Should -Be '9001'
        $r.Cci | Should -Be @('CCI-000366')
        $r.Legacy | Should -Be @('V-100001')
        $b.Rules[1].Discussion | Should -Be 'Two parts & one rule.'
    }

    It 'reads the XCCDF file inside a STIG zip' {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $dir = Join-Path $TestDrive 'zipsrc/U_Sample_V1R3_Manual_STIG'
        $null = New-Item -ItemType Directory -Path $dir -Force
        Copy-Item -LiteralPath $XccdfPath -Destination (Join-Path $dir 'U_Sample_V1R3_Manual-xccdf.xml')
        $zip = Join-Path $TestDrive 'U_Sample_V1R3_STIG.zip'
        [IO.Compression.ZipFile]::CreateFromDirectory((Join-Path $TestDrive 'zipsrc'), $zip)
        $b = Read-StigBenchmark $zip
        @($b.Rules).Count | Should -Be 5
        $b.FileName | Should -BeLike '*U_Sample_V1R3_Manual-xccdf.xml'
    }

    It 'refuses a zip holding more than one XCCDF file' {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $dir = Join-Path $TestDrive 'twosrc'
        $null = New-Item -ItemType Directory -Path $dir -Force
        Copy-Item -LiteralPath $XccdfPath -Destination (Join-Path $dir 'a-xccdf.xml')
        Copy-Item -LiteralPath $XccdfPath -Destination (Join-Path $dir 'b-xccdf.xml')
        $zip = Join-Path $TestDrive 'two.zip'
        [IO.Compression.ZipFile]::CreateFromDirectory($dir, $zip)
        { Read-StigBenchmark $zip } | Should -Throw '*2 XCCDF files*'
    }

    It 'refuses an XCCDF file with a DTD' {
        $path = Join-Path $TestDrive 'dtd-xccdf.xml'
        Set-Content -LiteralPath $path -Value '<?xml version="1.0"?><!DOCTYPE Benchmark [<!ENTITY x "y">]><Benchmark>&x;</Benchmark>'
        { Read-StigBenchmark $path } | Should -Throw
    }

    It 'refuses a STIG file that is not the catalog''s STIG' {
        { Assert-StigBenchmark (Get-Framework 'DISA-STIG-Win11') (Read-StigBenchmark $XccdfPath) } | Should -Throw '*shares 0 of*'
        { Assert-StigBenchmark $Catalog (Read-StigBenchmark $XccdfPath) } | Should -Throw '*not a STIG*'
    }

    It 'records <Id> as <Status>' -ForEach @(
        @{ Id = 'V-900001'; Status = 'NotAFinding' }
        @{ Id = 'V-900002'; Status = 'Open' }
        @{ Id = 'V-900003'; Status = 'Not_Applicable' }
        @{ Id = 'V-900004'; Status = 'Not_Reviewed' }
        @{ Id = 'V-900005'; Status = 'Not_Reviewed' }
    ) {
        (Get-Vuln (Get-Checklist).Xml $Id).STATUS | Should -Be $Status
    }

    It 'lists every rule of the STIG and counts the ones with results' {
        $c = Get-Checklist
        @($c.Xml.CHECKLIST.STIGS.iSTIG.VULN).Count | Should -Be 5
        $c.Result.Matched | Should -Be 4
        $c.Result.Unmatched | Should -BeNullOrEmpty
    }

    It 'rolls a split rule up to its worst part and keeps the evidence of each' {
        $v = Get-Vuln (Get-Checklist).Xml 'V-900002'
        $v.FINDING_DETAILS | Should -Match 'V-900002.a Pass'
        $v.FINDING_DETAILS | Should -Match 'V-900002.b Fail'
    }

    It 'carries the STIG''s rule data and the scan in each entry' {
        $x = (Get-Checklist).Xml
        $v = Get-Vuln $x 'V-900002'
        Get-VulnData $v 'Rule_ID' | Should -Be 'SV-900002r1_rule'
        Get-VulnData $v 'Rule_Ver' | Should -Be 'WM-00-000002'
        Get-VulnData $v 'Severity' | Should -Be 'high'
        Get-VulnData $v 'CCI_REF' | Should -Be @('CCI-001199', 'CCI-002475')
        Get-VulnData $v 'Fix_Text' | Should -Be 'Turn on BitLocker.'
        $v.COMMENTS | Should -Match 'WESTMARK-PC01-20261020T150000Z'
        $x.CHECKLIST.ASSET.HOST_NAME | Should -Be 'WESTMARK-PC01'
        $x.CHECKLIST.ASSET.ROLE | Should -Be 'Workstation'
        ($x.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | Where-Object SID_NAME -eq 'stigid').SID_DATA | Should -Be 'Sample_Westmark_STIG'
        (Get-Vuln $x 'V-900005').COMMENTS | Should -Match 'Review the accounts'
        (Get-Vuln $x 'V-900004').COMMENTS | Should -Match 'Not in the SAMPLE-STIG catalog'
    }

    It 'leaves rules above the chosen level Not_Reviewed and says why' {
        $v = Get-Vuln (Get-Checklist -Level 'CAT I').Xml 'V-900001'
        $v.STATUS | Should -Be 'Not_Reviewed'
        $v.COMMENTS | Should -Match 'outside level CAT I'
    }

    It 'writes a STIG Viewer 3 checklist in the layout STIG Viewer 3.8 saves' {
        # Key names and order as STIG Viewer 3.8.1 saves a .cklb.
        $j = Get-ChecklistJson
        @($j.Doc.PSObject.Properties.Name) | Should -Be @('title', 'id', 'stigs', 'active', 'mode', 'has_path', 'target_data')
        @($j.Doc.stigs[0].PSObject.Properties.Name) | Should -Be @('stig_name', 'display_name', 'stig_id', 'release_info', 'version', 'uuid', 'reference_identifier', 'size', 'rules')
        @($j.Doc.stigs[0].rules[0].PSObject.Properties.Name) | Should -Be @(
            'group_id_src', 'group_tree', 'group_id', 'severity', 'group_title', 'rule_id_src', 'rule_id', 'rule_version', 'rule_title',
            'fix_text', 'weight', 'check_content', 'check_content_ref', 'classification', 'discussion', 'false_positives', 'false_negatives',
            'documentable', 'security_override_guidance', 'potential_impacts', 'third_party_tools', 'ia_controls', 'responsibility',
            'mitigations', 'mitigation_control', 'legacy_ids', 'ccis', 'reference_identifier', 'uuid', 'stig_uuid', 'status', 'overrides',
            'comments', 'finding_details', 'srg_id')
        @($j.Doc.target_data.PSObject.Properties.Name) | Should -Be @('target_type', 'host_name', 'ip_address', 'mac_address', 'fqdn', 'comments',
            'role', 'is_web_database', 'technology_area', 'web_db_site', 'web_db_instance', 'classification')
    }

    It 'records <Id> as <Status> in the STIG Viewer 3 checklist' -ForEach @(
        @{ Id = 'V-900001'; Status = 'not_a_finding' }
        @{ Id = 'V-900002'; Status = 'open' }
        @{ Id = 'V-900003'; Status = 'not_applicable' }
        @{ Id = 'V-900004'; Status = 'not_reviewed' }
        @{ Id = 'V-900005'; Status = 'not_reviewed' }
    ) {
        (Get-JsonRule (Get-ChecklistJson).Doc $Id).status | Should -Be $Status
    }

    It 'carries the STIG''s rule data and the scan in the STIG Viewer 3 checklist' {
        $j = Get-ChecklistJson
        $stig = $j.Doc.stigs[0]
        $stig.stig_name | Should -Be 'Sample Westmark Security Technical Implementation Guide'
        $stig.display_name | Should -Be 'Sample Westmark'
        $stig.stig_id | Should -Be 'Sample_Westmark_STIG'
        $stig.release_info | Should -Be 'Release: 3 Benchmark Date: 01 Apr 2026'
        $stig.reference_identifier | Should -Be '9001'
        $stig.size | Should -Be 5
        $r = Get-JsonRule $j.Doc 'V-900001'
        $r.rule_id_src | Should -Be 'SV-900001r1_rule'
        $r.rule_id | Should -Be 'SV-900001r1'
        $r.group_title | Should -Be 'User Account Control must be on.'
        $r.srg_id | Should -Be 'SRG-OS-000001-GPOS-00001'
        $r.group_tree[0].title | Should -Be 'SRG-OS-000001-GPOS-00001'
        $r.check_content_ref.href | Should -Be 'Sample_Westmark_STIG.xml'
        $r.check_content_ref.name | Should -Be 'M'
        $r.stig_uuid | Should -Be $stig.uuid
        $r.comments | Should -Match 'WESTMARK-PC01-20261020T150000Z'
        $r.finding_details | Should -Match 'V-900001 Pass'
        (Get-JsonRule $j.Doc 'V-900002').finding_details | Should -Match 'V-900002.b Fail'
        $j.Doc.target_data.host_name | Should -Be 'WESTMARK-PC01'
        $j.Doc.target_data.role | Should -Be 'Workstation'
        $j.Doc.title | Should -Be 'sample'
        # One CCI stays a list, and no legacy IDs is an empty list.
        $j.Text | Should -Match '"ccis":\["CCI-000366"\]'
        $j.Text | Should -Match '"legacy_ids":\[\]'
        $j.Result.Matched | Should -Be 4
    }

    It 'writes a valid checklist when the evidence holds characters XML can''t' {
        # Regression (0.4.1): a NUL in registry evidence crashed XmlWriter on a real machine.
        $s = Get-Fixture
        $s.Meta.ComputerName = "WESTMARK-PC01$([char]0)"
        $e = Invoke-Evaluation $s -Level 'CAT III' -For $StigFw
        $r = @($e.Requirements | Where-Object Requirement -eq 'V-900001')[0]
        $r.Evidence = "Legal notice$([char]0)text$([char]1) ok $([char]0xD83D)$([char]0xDE00) end$([char]0xD800)"
        $c = ConvertTo-StigChecklist $e $s $StigFw (Read-StigBenchmark $XccdfPath)
        $x = [xml]$c.Xml
        (Get-Vuln $x 'V-900001').FINDING_DETAILS | Should -Be "V-900001 Pass: Legal noticetext ok $([char]0xD83D)$([char]0xDE00) end"
        $x.CHECKLIST.ASSET.HOST_NAME | Should -Be 'WESTMARK-PC01'
        $j = ConvertTo-StigChecklistJson $e $s $StigFw (Read-StigBenchmark $XccdfPath) -Title 'sample'
        (Get-JsonRule ($j.Json | ConvertFrom-Json) 'V-900001').finding_details | Should -Not -Match "$([char]0)"
    }

    It 'keeps text XML can hold as it is' {
        ConvertTo-XmlText "a`tb`r`nc & <d>" | Should -BeExactly "a`tb`r`nc & <d>"
        ConvertTo-XmlText $null | Should -BeExactly ''
    }

    It 'writes both checklists beside the other reports and names them in the HTML' {
        $s = Get-Fixture
        $e = Invoke-Evaluation $s -Level 'CAT III' -For $StigFw
        $files = Export-ScanReport -Evaluation $e -Snapshot $s -Thresholds (Get-Threshold) -Catalog $StigFw -Folder (Join-Path $TestDrive 'ckl') -Benchmark (Read-StigBenchmark $XccdfPath)
        $ckl = @($files | Where-Object { $_ -like '*.ckl' })
        $ckl.Count | Should -Be 1
        { [xml](Get-Content -LiteralPath $ckl[0] -Raw) } | Should -Not -Throw
        $cklb = @($files | Where-Object { $_ -like '*.cklb' })
        $cklb.Count | Should -Be 1
        $doc = Get-Content -LiteralPath $cklb[0] -Raw | ConvertFrom-Json
        $doc.title | Should -Be ([IO.Path]::GetFileNameWithoutExtension($cklb[0]))
        @($doc.stigs[0].rules).Count | Should -Be 5
        Get-Content -LiteralPath @($files | Where-Object { $_ -like '*.html' })[0] -Raw | Should -Match '4 of 5 rules'
    }
}

Describe 'Running the script on a saved snapshot' {
    BeforeAll {
        $script:Exe = (Get-Process -Id $PID).Path
        function Get-Report {
            # The one report of this extension in a folder, by its full path.
            param([string]$Folder, [string]$Extension)
            $hit = @(Get-ChildItem -LiteralPath $Folder -File | Where-Object { $_.Name -match "-[a-z0-9.-]+?\.$([regex]::Escape($Extension))$" -and
                    ($Extension -ne 'json' -or $_.Name -notlike '*.records.json') })
            if ($hit.Count -ne 1) { throw "Expected one .$Extension report in $Folder, found $($hit.Count)." }
            return $hit[0].FullName
        }
    }

    It 'exits 0 and writes one CSV row per requirement for the compliant fixture' {
        $out = Join-Path $TestDrive 'ok'
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework CMMC -FromSnapshot $FixturePath -OutputPath $out
        $LASTEXITCODE | Should -Be 0
        $csv = @(Get-ChildItem -LiteralPath $out -Filter '*.csv')
        $csv.Count | Should -Be 1
        $csv[0].Name | Should -Be 'compliance-scan-WESTMARK-PC01-20261020T150000Z-cmmc.csv'
        foreach ($ext in 'json', 'records.json', 'html') { Test-Path -LiteralPath (Join-Path $out "compliance-scan-WESTMARK-PC01-20261020T150000Z-cmmc.$ext") | Should -BeTrue -Because $ext }
        @(Get-ChildItem -LiteralPath $out -Filter '*.ckl').Count | Should -Be 0
        @(Import-Csv -LiteralPath $csv[0].FullName).Count | Should -Be 110
        $json = Get-Content -LiteralPath (Get-Report $out 'json') -Raw | ConvertFrom-Json
        $json.Summary.Fail | Should -Be 0
        $json.Framework | Should -Be 'CMMC'
        $json.Level | Should -Be 'L2'
        $json.Complete | Should -BeTrue
        $json.PSObject.Properties.Name | Should -Not -Contain 'Snapshot'
    }

    It 'takes a CMMC level as a number' {
        $out = Join-Path $TestDrive 'l1'
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework cmmc -Level 1 -FromSnapshot $FixturePath -OutputPath $out
        $LASTEXITCODE | Should -Be 0
        @(Import-Csv -LiteralPath (Get-ChildItem -LiteralPath $out -Filter '*.csv')[0].FullName).Count | Should -Be 17
    }

    It 'evaluates a snapshot against another framework' {
        $s = Get-CompliantSnapshot (Get-Framework 'PCI-DSS-4.0.1')
        $path = Join-Path $TestDrive 'pci.json'
        $s | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        $out = Join-Path $TestDrive 'pci'
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework PCI-DSS-4.0.1 -FromSnapshot $path -OutputPath $out
        $LASTEXITCODE | Should -Be 0
        $json = Get-Content -LiteralPath (Get-Report $out 'json') -Raw | ConvertFrom-Json
        $json.Complete | Should -BeFalse
        @($json.Requirements).Count | Should -Be 22
    }

    It 'warns, and says so in the report, when the framework is for another Windows' {
        $s = Get-CompliantSnapshot (Get-Framework 'DISA-STIG-WS2019-MS')
        $path = Join-Path $TestDrive 'ws2019.json'
        $s | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        $out = Join-Path $TestDrive 'ws2019'
        $ErrorActionPreference = 'Continue'
        $output = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework disa-stig-ws2019-ms -FromSnapshot $path -OutputPath $out 2>&1
        "$output" | Should -Match 'build 17763'
        $json = Get-Content -LiteralPath (Get-Report $out 'json') -Raw | ConvertFrom-Json
        $json.PlatformWarning | Should -Match 'DISA-STIG-WS2019-MS is written for Windows Server'
        $LASTEXITCODE | Should -Be 0
    }

    It 'writes a checklist with -StigPath, and refuses a STIG file for another framework before scanning' {
        $out = Join-Path $TestDrive 'stigpath'
        $ErrorActionPreference = 'Continue'
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework DISA-STIG-Win11 -FromSnapshot $FixturePath -OutputPath $out -StigPath (Join-Path $PSScriptRoot 'fixtures/stig-sample-xccdf.xml') 2>&1
        $LASTEXITCODE | Should -Be 2
        Test-Path -LiteralPath $out | Should -BeFalse
    }

    It 'says how to get a checklist when a STIG runs without -StigPath' {
        $output = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework DISA-STIG-Win11 -Level 'CAT I' -FromSnapshot $FixturePath -OutputPath (Join-Path $TestDrive 'nostig') 2>&1
        "$output" | Should -Match 'pass the DISA STIG zip'
    }

    It 'exits 2 and lists the frameworks when none is chosen' {
        $ErrorActionPreference = 'Continue'
        $output = & $Exe -NoProfile -NonInteractive -File $ScriptPath -FromSnapshot $FixturePath -OutputPath (Join-Path $TestDrive 'none') 2>&1
        $LASTEXITCODE | Should -Be 2
        "$output" | Should -Match 'DISA-STIG-Win11'
    }

    It 'exits 1 when a check fails' {
        $s = Get-Fixture
        $s.BitLocker.ProtectionStatus = 'Off'
        $path = Join-Path $TestDrive 'fail.json'
        $s | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework CMMC -FromSnapshot $path -OutputPath (Join-Path $TestDrive 'fail')
        $LASTEXITCODE | Should -Be 1
    }

    It 'exits 2 when the snapshot cannot be read' {
        # The script writes its error to stderr. Under the Stop preference the
        # dot-sourced script sets, Windows PowerShell 5.1 turns a native command's
        # stderr into a terminating error, so relax it for this call.
        $ErrorActionPreference = 'Continue'
        $null = & $Exe -NoProfile -NonInteractive -File $ScriptPath -Framework CMMC -FromSnapshot (Join-Path $TestDrive 'missing.json') -OutputPath (Join-Path $TestDrive 'err') 2>&1
        $LASTEXITCODE | Should -Be 2
    }
}
