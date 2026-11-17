# Pester tests for tools/Write-TestSummary.ps1, the banner every test script,
# lint run and CI check ends with, and for the scripts that print it.
#
# Run through ..\Test-ComplianceScan.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'tools/Write-TestSummary.ps1')
}

Describe 'Get-TestStatus' {
    It 'is PASS when nothing failed or was skipped' {
        Get-TestStatus -Fail 0 -Skip 0 | Should -Be 'PASS'
    }

    It 'is PASS WITH SKIPS when something was skipped' {
        Get-TestStatus -Fail 0 -Skip 3 | Should -Be 'PASS WITH SKIPS'
    }

    It 'is FAIL when anything failed, skips or not' {
        Get-TestStatus -Fail 1 -Skip 3 | Should -Be 'FAIL'
        Get-TestStatus -Fail 2 -Skip 0 | Should -Be 'FAIL'
    }
}

Describe 'Write-TestSummary' {
    BeforeAll {
        $rows = @([pscustomobject][ordered]@{ Edition = 'pwsh'; Passed = 5; Result = 'PASS' })
        $script:Lines = @(Write-TestSummary -Script 'Example.ps1 -BothEditions' -Target 'a target' -Rows $rows `
                -Pass 5 -Fail 0 -Skip 1 -PassThru 6>$null)
    }

    It 'starts with two blank lines, then the banner between two bars' {
        $Lines[0] | Should -Be ''
        $Lines[1] | Should -Be ''
        $Lines[2] | Should -Match '^#{60,}$'
        $Lines[3] | Should -Be '##  Example.ps1 -BothEditions  |  PASS WITH SKIPS  |  Pass 5  Fail 0  Skip 1'
        $Lines[4] | Should -Be $Lines[2]
    }

    It 'gives the target, run time and PowerShell version' {
        $Lines | Should -Contain 'Target:  a target'
        @($Lines | Where-Object { $_ -match '^Run:     \d{4}-\d{2}-\d{2} \d{2}:\d{2}$' }).Count | Should -Be 1
        $Lines | Should -Contain "PS:      $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    }

    It 'holds the table' {
        ($Lines -join "`n") | Should -Match 'Edition\s+Passed\s+Result'
        ($Lines -join "`n") | Should -Match 'pwsh\s+5\s+PASS'
    }

    It 'ends with a RESULT bar that matches the banner' {
        $Lines[-3] | Should -Be $Lines[2]
        $Lines[-2] | Should -Be '##  RESULT: PASS WITH SKIPS  (Pass 5  Fail 0  Skip 1)'
        $Lines[-1] | Should -Be $Lines[2]
    }

    It 'prints a banner with no table when there are no rows' {
        $l = @(Write-TestSummary -Script 'Empty.ps1' -Pass 0 -Fail 1 -Skip 0 -PassThru 6>$null)
        $l[3] | Should -Be '##  Empty.ps1  |  FAIL  |  Pass 0  Fail 1  Skip 0'
        $l | Should -Not -Contain 'Target:  '
        $l[-2] | Should -Be '##  RESULT: FAIL  (Pass 0  Fail 1  Skip 0)'
    }
}

Describe 'Scripts that print the summary' {
    It '<Path> loads the summary helper and prints it' -ForEach @(
        @{ Path = 'Test-ComplianceScan.ps1' }
        @{ Path = 'Test-ComplianceScanLint.ps1' }
        @{ Path = 'tests/ci/Test-ScheduledScanTask.ps1' }
    ) {
        $text = [IO.File]::ReadAllText((Join-Path $Root $Path))
        $text | Should -Match "tools/Write-TestSummary\.ps1'\)"
        $text | Should -Match 'Write-TestSummary -Script'
    }
}
