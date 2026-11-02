# Pester tests that keep the documentation and CI in step with the code: the
# README's framework table and named check count, the version notes and the
# changelog, frameworks/README.md, and the frameworks the live-scan job
# evaluates. Each of these was checked by hand before; a new catalog or release
# that misses one now fails here instead.
#
# Run through ..\Test-ComplianceScan.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:ScriptPath = Join-Path $Root 'Invoke-EndpointComplianceScan.ps1'
    . $ScriptPath
    $script:Catalogs = @(Get-FrameworkCatalog (Join-Path $Root 'frameworks'))
    $script:Readme = [IO.File]::ReadAllLines((Join-Path $Root 'README.md'))
    $script:Utf8 = [Text.UTF8Encoding]::new($false)

    function Get-EvidenceCount {
        # Requirements with a named check or a setting expectation.
        param($Catalog)
        @(@($Catalog.Requirements) | Where-Object {
                ($_.Contains('Checks') -and @($_.Checks).Count -gt 0) -or ($_.Contains('Expect') -and @($_.Expect).Count -gt 0)
            }).Count
    }
}

Describe 'README framework table' {
    BeforeAll {
        # | Name | `Id` | Levels | 110 or 18 (partial) | 32 |
        $script:Rows = @(foreach ($line in $Readme) {
                $m = [regex]::Match($line, '^\|[^|]+\|\s*`([^`]+)`\s*\|([^|]+)\|\s*(\d+)( \(partial\))?\s*\|\s*(\d+)\s*\|\s*$')
                if ($m.Success) {
                    [pscustomobject]@{
                        Id = $m.Groups[1].Value; Levels = $m.Groups[2].Value.Trim(); Requirements = [int]$m.Groups[3].Value
                        Partial = $m.Groups[4].Success; Evidence = [int]$m.Groups[5].Value
                    }
                }
            })
    }

    It 'has one row per catalog' {
        @($Rows | ForEach-Object Id | Sort-Object) | Should -Be @($Catalogs | ForEach-Object Id | Sort-Object)
    }

    It 'gives each catalog its requirement and evidence counts, levels and completeness' {
        foreach ($c in $Catalogs) {
            $row = @($Rows | Where-Object Id -eq $c.Id)[0]
            $row.Requirements | Should -Be @($c.Requirements).Count -Because "$($c.Id) requirements"
            $row.Evidence | Should -Be (Get-EvidenceCount $c) -Because "$($c.Id) with endpoint evidence"
            $row.Partial | Should -Be (-not $c.Complete) -Because "$($c.Id) is marked partial only when its catalog is"
            $row.Levels | Should -Be (@($c.Levels) -join ', ') -Because "$($c.Id) levels"
        }
    }
}

Describe 'README named checks' {
    It 'gives the number of named checks in the script' {
        $line = @($Readme | Where-Object { $_ -match 'which apply judgement: (\d+) of them' })
        $line.Count | Should -Be 1
        [int]([regex]::Match($line[0], '(\d+) of them').Groups[1].Value) | Should -Be (Get-CheckTable).Count
    }
}

Describe 'Versions' {
    BeforeAll {
        $script:Notes = @([regex]::Matches([IO.File]::ReadAllText($ScriptPath), '(?m)^\s{4}(\d+\.\d+\.\d+)\s+\d{4}-\d{2}-\d{2}\s') | ForEach-Object { $_.Groups[1].Value })
        $script:Changelog = @($Readme | ForEach-Object { [regex]::Match($_, '^\| (\d+\.\d+\.\d+) \| \d{4}-\d{2}-\d{2} \|') } | Where-Object Success | ForEach-Object { $_.Groups[1].Value })
    }

    It 'ends the version notes with $ComplianceScanVersion' {
        $Notes.Count | Should -BeGreaterThan 0
        $Notes[-1] | Should -Be $ComplianceScanVersion
    }

    It 'starts the README changelog with $ComplianceScanVersion' {
        $Changelog.Count | Should -BeGreaterThan 0
        $Changelog[0] | Should -Be $ComplianceScanVersion
    }

    It 'lists the same releases in the version notes and the changelog' {
        @($Changelog | Sort-Object { [version]$_ }) | Should -Be @($Notes | Sort-Object { [version]$_ })
    }
}

Describe 'frameworks/README.md' {
    It 'lists every catalog file in its sources table' {
        $text = [IO.File]::ReadAllText((Join-Path $Root 'frameworks/README.md'), $Utf8)
        foreach ($c in $Catalogs) { $text | Should -Match ([regex]::Escape("``$($c.File).psd1``")) -Because "$($c.File).psd1 needs its source" }
    }
}

Describe 'Tests workflow' {
    It 'evaluates the live snapshot against every framework' {
        $workflow = [IO.File]::ReadAllText((Join-Path $Root '.github/workflows/tests.yml'), $Utf8)
        $m = [regex]::Match($workflow, 'for %%F in \(([^)]+)\) do')
        $m.Success | Should -BeTrue -Because 'the live-scan job loops over the frameworks'
        @($m.Groups[1].Value -split '\s+' | Where-Object { $_ } | Sort-Object) | Should -Be @($Catalogs | ForEach-Object Id | Sort-Object)
    }
}
