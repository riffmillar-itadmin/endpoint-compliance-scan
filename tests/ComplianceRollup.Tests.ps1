# Pester tests for New-ComplianceRollup.ps1. The scan reports are made up in
# TestDrive, apart from one end-to-end case that writes real reports from the
# compliant fixture snapshot.
#
# Run through ..\Test-ComplianceScan.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:Rollup = Join-Path $Root 'New-ComplianceRollup.ps1'
    . $Rollup -Path $TestDrive
    $script:AsOfDate = [datetime]::new(2026, 10, 27, 12, 0, 0, [DateTimeKind]::Utc)
    # The scripts run as a separate process under the edition running the tests.
    $script:Shell = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

    function Get-TestFolder {
        # A new, empty folder under TestDrive.
        $p = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $p
        $p
    }

    function Write-FakeReport {
        # A scan report as the scanner writes it, with requirements R-1 to R-4
        # unless -Requirement lists others, all Pass unless -Fail names some.
        param([string]$Folder, [string]$Computer, [string]$Collected, [string]$Framework = 'FW-A',
            [string[]]$Fail = @(), [string[]]$Requirement = @('R-1', 'R-2', 'R-3', 'R-4'),
            [string]$Version = '0.12.0', [string]$Level = 'L2', [bool]$Elevated = $true, [string]$Title = 'Requirement')
        $report = [ordered]@{
            Tool = 'endpoint-compliance-scan'; Version = $Version; ScanId = "$Computer-x"; Framework = $Framework
            FrameworkName = "Framework $Framework"; Complete = $true; Level = $Level; PlatformWarning = ''
            ComputerName = $Computer; CollectedUtc = $Collected; IsElevated = $Elevated; Summary = @{}
            Requirements = @(foreach ($id in $Requirement) {
                $state = if ($id -in $Fail) { 'Fail' } else { 'Pass' }
                [ordered]@{ Requirement = $id; Reference = $id; Level = 'L1'; Family = 'Family'; Title = "$Title $id"
                    State = $state; Checks = ''; Evidence = ''; Findings = $(if ($state -eq 'Fail') { "finding on $Computer" } else { '' }); Note = '' }
            })
        }
        $stamp = $Collected -replace '[-:]', ''
        $file = Join-Path $Folder "compliance-scan-$Computer-$stamp-$($Framework.ToLowerInvariant()).json"
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $file -Encoding UTF8
        $file
    }

    function Invoke-TestRollup {
        # Reads the folder and writes its roll-ups into a new folder; returns what was written.
        param([string]$Folder, [string[]]$Framework = @(), [int]$MaxAge = 30)
        $out = Get-TestFolder
        @(Export-ComplianceRollup -Report @(Read-ScanReport -Folder $Folder) -Folder $out -Framework $Framework -AsOf $AsOfDate -MaxAge $MaxAge)
    }
}

Describe 'Roll-up report' {
    It 'reads only scan reports, passing over records, roll-ups and other JSON' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z'
        Set-Content -LiteralPath (Join-Path $dir 'compliance-scan-WESTMARK-A-20261026T100000Z-fw-a.records.json') -Value '[{"Tool":"endpoint-compliance-scan"}]'
        Set-Content -LiteralPath (Join-Path $dir 'compliance-rollup-fw-a.json') -Value '{}'
        Set-Content -LiteralPath (Join-Path $dir 'compliance-scan-other.json') -Value '{"Tool":"something-else","Requirements":[]}'
        $reports = @(Read-ScanReport -Folder $dir)
        $reports.Count | Should -Be 1
        $reports[0].ComputerName | Should -Be 'WESTMARK-A'
    }

    It 'warns about a report it cannot read and leaves it out' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z'
        Set-Content -LiteralPath (Join-Path $dir 'compliance-scan-broken.json') -Value '{ not json'
        $reports = @(Read-ScanReport -Folder $dir -WarningVariable warned 3>$null)
        $reports.Count | Should -Be 1
        "$warned" | Should -BeLike "*Couldn't read compliance-scan-broken.json*"
    }

    It "takes each computer's latest scan, whatever the case of its name" {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-01T10:00:00Z' -Fail 'R-1', 'R-2', 'R-3'
        $null = Write-FakeReport $dir 'westmark-a' '2026-10-26T10:00:00Z' -Fail 'R-4'
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-20T10:00:00Z'
        $latest = @(Select-LatestScan @(Read-ScanReport -Folder $dir))
        $latest.Count | Should -Be 2
        $a = $latest | Where-Object { $_.ComputerName -eq 'westmark-a' }
        @($a.Requirements | Where-Object State -eq 'Fail').Requirement | Should -Be 'R-4'
    }

    It 'reads the collection time whether it arrives as text or as a date' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z'
        $r = @(Read-ScanReport -Folder $dir)[0]
        $r.CollectedUtc | Should -Be ([datetime]::new(2026, 10, 26, 10, 0, 0, [DateTimeKind]::Utc))
        $r.CollectedUtc.Kind | Should -Be 'Utc'
    }

    It 'writes one page and one CSV per framework' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Framework 'FW-A'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Framework 'FW-B'
        $written = Invoke-TestRollup $dir
        @($written.Framework) | Should -Be @('FW-A', 'FW-B')
        foreach ($w in $written) { $w.Files | ForEach-Object { $_ | Should -Exist } }
        Split-Path $written[0].Files[0] -Leaf | Should -Be 'compliance-rollup-fw-a.html'
    }

    It 'rolls up only the frameworks asked for, and says when none of them is there' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Framework 'FW-A'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Framework 'FW-B'
        @((Invoke-TestRollup $dir -Framework 'FW-B').Framework) | Should -Be @('FW-B')
        { Invoke-TestRollup $dir -Framework 'FW-C' } | Should -Throw '*No scan reports for FW-C*'
    }

    It 'orders requirements by how many machines fail them' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Fail 'R-3', 'R-4'
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-26T10:00:00Z' -Fail 'R-4'
        $grid = @(Get-RollupGrid @(Select-LatestScan @(Read-ScanReport -Folder $dir)))
        @($grid.Requirement) | Should -Be @('R-4', 'R-3', 'R-1', 'R-2')
        @($grid.Fail) | Should -Be @(2, 1, 0, 0)
        $grid[0].Detail['WESTMARK-B'] | Should -Be 'Fail: finding on WESTMARK-B'
    }

    It 'flags a stale scan only past -MaxAge days' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-OLD' '2026-09-26T11:00:00Z'
        $null = Write-FakeReport $dir 'WESTMARK-NEW' '2026-09-28T13:00:00Z'
        $notice = @(Get-RollupNotice -Scan @(Read-ScanReport -Folder $dir) -AsOf $AsOfDate -MaxAge 30)
        @($notice | Where-Object { $_ -like '*older than 30 days*' }) | Should -Be "1 of 2 machines' latest scan is older than 30 days: WESTMARK-OLD."
    }

    It 'says when the scans list different requirements, and leaves those cells blank' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Requirement 'R-1', 'R-2' -Level 'L1' -Version '0.11.2'
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-26T10:00:00Z' -Requirement 'R-1', 'R-2', 'R-3'
        $written = Invoke-TestRollup $dir
        "$($written[0].Notice)" | Should -BeLike '*levels: L1, L2; tool versions: 0.11.2, 0.12.0*'
        $csv = @(Import-Csv -LiteralPath $written[0].Files[1])
        ($csv | Where-Object Requirement -eq 'R-3').'WESTMARK-A' | Should -Be ''
        ($csv | Where-Object Requirement -eq 'R-3').'WESTMARK-B' | Should -Be 'Pass'
    }

    It 'says nothing about requirement lists when every scan lists the same ones' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z'
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-26T10:00:00Z'
        @(Get-RollupNotice -Scan @(Read-ScanReport -Folder $dir) -AsOf $AsOfDate -MaxAge 30) | Should -BeNullOrEmpty
    }

    It 'names the machines scanned without elevation' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Elevated $false
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-26T10:00:00Z'
        "$(Get-RollupNotice -Scan @(Read-ScanReport -Folder $dir) -AsOf $AsOfDate -MaxAge 30)" | Should -BeLike '*Skipped: WESTMARK-A.'
    }

    It 'writes a CSV with a column per machine and the failing count' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-26T10:00:00Z' -Fail 'R-2'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Fail 'R-2'
        $csv = @(Import-Csv -LiteralPath (Invoke-TestRollup $dir)[0].Files[1])
        @($csv[0].PSObject.Properties.Name) | Should -Be @('Requirement', 'Reference', 'Family', 'Title', 'FailingMachines', 'WESTMARK-A', 'WESTMARK-B')
        $csv[0].Requirement | Should -Be 'R-2'
        $csv[0].FailingMachines | Should -Be '2'
        $csv[0].'WESTMARK-A' | Should -Be 'Fail'
    }

    It 'encodes names and titles in the page' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Title '<script>alert(1)</script>' -Fail 'R-1'
        $html = Get-Content -LiteralPath (Invoke-TestRollup $dir)[0].Files[0] -Raw
        $html | Should -Not -BeLike '*<script>alert*'
        $html | Should -BeLike '*&lt;script&gt;alert(1)&lt;/script&gt; R-1*'
        $html | Should -BeLike '*title="Fail: finding on WESTMARK-A"*'
        $html | Should -BeLike '*gives no score*'
    }

    It 'keeps its own -Framework and -OutputPath after loading the scanner' {
        $dir = Get-TestFolder
        $out = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Framework 'FW-A'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-26T10:00:00Z' -Framework 'FW-B'
        & $Shell -NoProfile -ExecutionPolicy Bypass -File $Rollup -Path $dir -OutputPath $out -Framework 'FW-A,FW-B' | Out-Null
        $LASTEXITCODE | Should -Be 0
        @(Get-ChildItem -LiteralPath $out -Name | Sort-Object) | Should -Be @(@('compliance-rollup-fw-a-trend.csv', 'compliance-rollup-fw-a.csv', 'compliance-rollup-fw-a.html', 'compliance-rollup-fw-b-trend.csv', 'compliance-rollup-fw-b.csv', 'compliance-rollup-fw-b.html') | Sort-Object)
    }

    It 'writes into a relative folder under the PowerShell location, not the process folder' {
        # The first run on a PC: .NET resolved .\Reports against the home folder.
        $here = Get-TestFolder
        $elsewhere = Get-TestFolder
        $null = Write-FakeReport $here 'WESTMARK-A' '2026-10-26T10:00:00Z'
        $was = [Environment]::CurrentDirectory
        Push-Location -LiteralPath $here
        try {
            [Environment]::CurrentDirectory = $elsewhere
            $written = @(Export-ComplianceRollup -Report @(Read-ScanReport -Folder '.') -Folder (Join-Path '.' 'out') -AsOf $AsOfDate -MaxAge 30)
        } finally {
            [Environment]::CurrentDirectory = $was
            Pop-Location
        }
        @(Get-ChildItem -LiteralPath (Join-Path $here 'out') -Name | Sort-Object) | Should -Be @(@('compliance-rollup-fw-a-trend.csv', 'compliance-rollup-fw-a.csv', 'compliance-rollup-fw-a.html') | Sort-Object)
        @(Get-ChildItem -LiteralPath $elsewhere).Count | Should -Be 0
        $written[0].Files | ForEach-Object { [IO.Path]::IsPathRooted($_) | Should -BeTrue }
    }

    It 'exits 2 when the folder holds no scan reports' {
        # Windows PowerShell 5.1 turns a child's stderr into error records, which
        # the inherited 'Stop' would throw despite 2>$null.
        $ErrorActionPreference = 'Continue'
        & $Shell -NoProfile -ExecutionPolicy Bypass -File $Rollup -Path (Get-TestFolder) 2>$null | Out-Null
        $LASTEXITCODE | Should -Be 2
    }

    It 'refuses a -MaxAge of 0 or less before reading anything' {
        foreach ($age in 0, -5) {
            { & $Rollup -Path (Get-TestFolder) -MaxAge $age } | Should -Throw '*MaxAge*' -Because "-MaxAge $age"
        }
    }

    It "rolls up the scanner's real reports" {
        $dir = Get-TestFolder
        $scanner = Join-Path $Root 'Invoke-EndpointComplianceScan.ps1'
        & $Shell -NoProfile -ExecutionPolicy Bypass -File $scanner -Framework CMMC -FromSnapshot (Join-Path $PSScriptRoot 'fixtures/compliant.json') -OutputPath $dir | Out-Null
        $LASTEXITCODE | Should -BeIn 0, 1
        $written = Invoke-TestRollup $dir
        $written[0].Framework | Should -Be 'CMMC'
        $written[0].Machines | Should -Be 1
        (Get-Content -LiteralPath $written[0].Files[0] -Raw) | Should -BeLike '*WESTMARK-PC01*'
    }
}

Describe 'Roll-up trends' {
    BeforeAll {
        function Get-TestScan {
            # Reads a folder and returns its reports, the latest FW-A scan per machine, and
            # their history, as the roll-up does for one framework.
            param([string]$Folder, [int]$TrendDays = 90)
            $reports = @(Read-ScanReport -Folder $Folder)
            $latest = @(Select-LatestScan $reports | Where-Object Framework -eq 'FW-A')
            [pscustomobject]@{ Reports = $reports; Latest = $latest; History = (Get-ScanHistory -Report $reports -Latest $latest -AsOf $AsOfDate -TrendDays $TrendDays) }
        }
    }

    It 'takes each machine''s scans within -TrendDays, oldest first, whatever the name''s case' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-06-01T10:00:00Z'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-01T10:00:00Z'
        $null = Write-FakeReport $dir 'westmark-a' '2026-10-20T10:00:00Z'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-20T10:00:00Z' -Framework 'FW-B'
        $t = Get-TestScan $dir
        @($t.History.Keys).Count | Should -Be 1
        @($t.History['WESTMARK-A'].CollectedUtc | ForEach-Object { $_.ToString('yyyy-MM-dd') }) | Should -Be @('2026-10-01', '2026-10-20')
    }

    It 'keeps a machine''s latest scan even when it is older than -TrendDays' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-05-01T10:00:00Z'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-06-01T10:00:00Z'
        $t = Get-TestScan $dir
        @($t.History['WESTMARK-A']).Count | Should -Be 1
        Get-ScanChange $t.History['WESTMARK-A'] | Should -BeNullOrEmpty
    }

    It 'lists requirements that newly fail and ones that no longer do' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-10T10:00:00Z' -Fail 'R-1', 'R-2'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-20T10:00:00Z' -Fail 'R-2', 'R-3'
        $c = Get-ScanChange (Get-TestScan $dir).History['WESTMARK-A']
        $c.Comparable | Should -BeTrue
        @($c.NewlyFailing.Requirement) | Should -Be @('R-3')
        @($c.Fixed.Requirement) | Should -Be @('R-1')
    }

    It 'compares only requirements in both scans, and says when the lists differ' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-10T10:00:00Z' -Fail 'R-4' -Requirement 'R-1', 'R-2', 'R-4'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-20T10:00:00Z' -Fail 'R-3' -Requirement 'R-1', 'R-2', 'R-3'
        $c = Get-ScanChange (Get-TestScan $dir).History['WESTMARK-A']
        $c.Comparable | Should -BeFalse
        @($c.NewlyFailing).Count | Should -Be 0
        @($c.Fixed).Count | Should -Be 0
        Format-ScanChange $c | Should -Be 'Fail 1 &rarr; 1 (not comparable)'
    }

    It 'breaks the trend where the level changes, and names the machine' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-01T10:00:00Z' -Level 'L1'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-10T10:00:00Z' -Level 'L2'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-20T10:00:00Z' -Level 'L2'
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-10T10:00:00Z'
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-20T10:00:00Z'
        $t = Get-TestScan $dir
        $points = @(Get-ScanPoint $t.History['WESTMARK-A'])
        @($points.First) | Should -Be @($true, $false, $false)
        @($points.Comparable) | Should -Be @($false, $false, $true)
        @(Get-TrendNotice $t.History) | Should -Be "Counts don't compare across a change of level or requirement list, so the trend lines break there: WESTMARK-A."
    }

    It 'says nothing about breaks when every machine''s scans compare' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-10T10:00:00Z'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-20T10:00:00Z' -Fail 'R-1'
        @(Get-TrendNotice (Get-TestScan $dir).History).Count | Should -Be 0
    }

    It 'totals each week by every machine''s latest scan at the week''s end' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-01T10:00:00Z' -Fail 'R-1', 'R-2', 'R-3'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-25T10:00:00Z' -Fail 'R-1'
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-14T10:00:00Z' -Fail 'R-4'
        $t = Get-TestScan $dir
        $weeks = @(Get-FleetWeek -Report $t.Reports -Latest $t.Latest -AsOf $AsOfDate -TrendDays 28)
        @($weeks.WeekEnding | ForEach-Object { $_.ToString('yyyy-MM-dd') }) | Should -Be @('2026-10-06', '2026-10-13', '2026-10-20', '2026-10-27')
        @($weeks.Machines) | Should -Be @(1, 1, 2, 2)
        @($weeks.Fail) | Should -Be @(3, 3, 4, 2)
    }

    It 'writes one trend CSV row per scan, saying whether it compares with the one before' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-20T10:00:00Z'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-01T10:00:00Z' -Level 'L1'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-10T10:00:00Z' -Fail 'R-1'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-20T10:00:00Z'
        $rows = @(ConvertTo-RollupTrendRow (Get-TestScan $dir).History)
        @($rows[0].PSObject.Properties.Name) | Should -Be @('Computer', 'CollectedUtc', 'Level', 'Version', 'IsElevated', 'Requirements', 'Fail', 'Error', 'Accepted', 'Skipped', 'Manual', 'Pass', 'NotApplicable', 'ComparableWithPrevious')
        @($rows.Computer) | Should -Be @('WESTMARK-A', 'WESTMARK-A', 'WESTMARK-A', 'WESTMARK-B')
        @($rows.CollectedUtc)[1] | Should -Be '2026-10-10T10:00:00Z'
        @($rows.Fail) | Should -Be @(0, 1, 0, 0)
        @($rows.ComparableWithPrevious) | Should -Be @('', 'No', 'Yes', '')
    }

    It 'draws a broken line as separate runs and a lone point as a dot' {
        $svg = ConvertTo-SvgSeries -X 0, 10, 20, 30 -Y 5, 5, 5, 5 -Break $false, $false, $true, $false -Class 'Fail'
        $svg | Should -Be '<g class="Fail"><polyline points="0,5 10,5" /><polyline points="20,5 30,5" /></g>'
        ConvertTo-SvgSeries -X 0, 10 -Y 5, 5 -Break $false, $true -Class 'Error' | Should -Match '<circle cx="10" cy="5" r="1.8" />'
    }

    It 'breaks a machine''s trend line at a scan that doesn''t compare with the one before' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-01T10:00:00Z' -Level 'L1' -Fail 'R-1'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-10T10:00:00Z' -Fail 'R-1', 'R-2'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-20T10:00:00Z' -Fail 'R-2'
        $points = @(Get-ScanPoint (Get-TestScan $dir).History['WESTMARK-A'])
        $svg = ConvertTo-TrendChart -Point $points -Width 120 -Height 28 -Label 'WESTMARK-A'
        $fail = [regex]::Match($svg, '<g class="Fail">(.*?)</g>').Groups[1].Value
        ([regex]::Matches($fail, '<circle ')).Count | Should -Be 1
        ([regex]::Matches($fail, '<polyline ')).Count | Should -Be 1
        $svg | Should -Match '<title>WESTMARK-A</title>'
    }

    It 'shows trend lines, changes and the weekly chart on the page' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-10T10:00:00Z' -Fail 'R-1', 'R-2'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-20T10:00:00Z' -Fail 'R-2', 'R-3' -Title 'Mind <this>'
        $null = Write-FakeReport $dir 'WESTMARK-B' '2026-10-20T10:00:00Z'
        $written = Invoke-TestRollup $dir
        $html = Get-Content -LiteralPath $written[0].Files[0] -Raw
        $html | Should -Match '<svg class="trend" width="120"'
        $html | Should -Match 'Fail 2 &rarr; 2'
        $html | Should -Match 'No earlier scan in the trend window'
        $html | Should -Match 'All machines, week by week'
        $html | Should -Match '<b>R-3</b> Mind &lt;this&gt; R-3</td><td class="list">.*<b>R-1</b>'
        $written[0].Scans | Should -Be 3
        $written[0].Files[2] | Should -BeLike '*compliance-rollup-fw-a-trend.csv'
        @(Import-Csv -LiteralPath $written[0].Files[2]).Count | Should -Be 3
    }

    It 'says so when no requirement changed state' {
        $dir = Get-TestFolder
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-10T10:00:00Z' -Fail 'R-1'
        $null = Write-FakeReport $dir 'WESTMARK-A' '2026-10-20T10:00:00Z' -Fail 'R-1'
        $html = Get-Content -LiteralPath (Invoke-TestRollup $dir)[0].Files[0] -Raw
        $html | Should -Match 'No requirement changed between Fail or Error and any other state'
        $html | Should -Not -Match 'Now Fail or Error'
    }
}
