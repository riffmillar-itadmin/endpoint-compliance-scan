# Pester tests for tools/Build-Module.ps1 and the EndpointComplianceScan module
# it builds for the PowerShell Gallery. The module is built in TestDrive and
# imported into this session, so it is tested under whichever edition runs the
# suite.
#
# Run through ..\Test-ComplianceScan.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    $script:Builder = Join-Path $Root 'tools/Build-Module.ps1'
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures/compliant.json'
    $script:Commands = @('Invoke-EndpointComplianceScan', 'New-ComplianceRollup', 'Register-ComplianceScanTask')
    . (Join-Path $Root 'Invoke-EndpointComplianceScan.ps1')
    $script:Built = @(& $Builder -OutputPath (Join-Path $TestDrive 'out') 6>$null)[-1].FullName
    $script:Manifest = Join-Path $Built 'EndpointComplianceScan.psd1'
    $script:Data = Import-PowerShellDataFile -LiteralPath $Manifest
    Import-Module $Manifest -Force
}

AfterAll {
    Remove-Module EndpointComplianceScan -Force -ErrorAction SilentlyContinue
}

Describe 'Module manifest' {
    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest -Path $Manifest -ErrorAction Stop } | Should -Not -Throw
    }

    It 'takes its version from $ComplianceScanVersion' {
        $Data.ModuleVersion | Should -Be $ComplianceScanVersion
    }

    It 'keeps the GUID the Gallery knows the module by' {
        $Data.GUID | Should -Be 'f56b4274-590a-4778-baef-955f0d37e8e0'
    }

    It 'takes the author from the copyright line in LICENSE' {
        $m = [regex]::Match([IO.File]::ReadAllText((Join-Path $Root 'LICENSE')), '(?m)^\s*Copyright \d{4} (\S.*?)\s*$')
        $m.Success | Should -BeTrue
        $Data.Author | Should -Be $m.Groups[1].Value
    }

    It 'runs on Windows PowerShell 5.1 and PowerShell 7' {
        $Data.PowerShellVersion | Should -Be '5.1'
        @($Data.CompatiblePSEditions | Sort-Object) | Should -Be @('Core', 'Desktop')
    }

    It 'exports the three commands and nothing else' {
        @($Data.FunctionsToExport | Sort-Object) | Should -Be @($Commands | Sort-Object)
        @($Data.CmdletsToExport).Count | Should -Be 0
        @($Data.VariablesToExport).Count | Should -Be 0
        @($Data.AliasesToExport).Count | Should -Be 0
        @((Get-Module EndpointComplianceScan).ExportedFunctions.Keys | Sort-Object) | Should -Be @($Commands | Sort-Object)
    }

    It 'carries this version''s changelog entry and the project links' {
        $psData = $Data.PrivateData.PSData
        $psData.ReleaseNotes | Should -BeLike "$ComplianceScanVersion`: *"
        $psData.ReleaseNotes | Should -Not -Match '\]\('
        $psData.ProjectUri | Should -Be 'https://github.com/riffmillar-itadmin/endpoint-compliance-scan'
        $psData.LicenseUri | Should -BeLike 'https://github.com/riffmillar-itadmin/endpoint-compliance-scan/*'
        @($psData.Tags) | Should -Contain 'Compliance'
        @($psData.Tags | Where-Object { $_ -match '\s' }).Count | Should -Be 0
    }
}

Describe 'Module contents' {
    It 'holds the scripts, the example profile, the licence and every catalog' {
        foreach ($name in @($Commands | ForEach-Object { "$_.ps1" }) + 'ComplianceScan.example.psd1', 'LICENSE', 'frameworks/README.md') {
            Test-Path -LiteralPath (Join-Path $Built $name) | Should -BeTrue -Because $name
        }
        $want = @(Get-ChildItem -LiteralPath (Join-Path $Root 'frameworks') -Filter '*.psd1' | ForEach-Object Name | Sort-Object)
        @(Get-ChildItem -LiteralPath (Join-Path $Built 'frameworks') -Filter '*.psd1' | ForEach-Object Name | Sort-Object) | Should -Be $want
    }

    It 'never holds a local profile or scan output' {
        @(Get-ChildItem -LiteralPath $Built -Recurse -File | Where-Object { $_.Name -like 'ComplianceScan.local*' -or $_.Name -like 'compliance-scan-*' -or $_.Name -like '*.snapshot.json' }).Count | Should -Be 0
    }

    It 'copies the scripts byte for byte' {
        foreach ($name in $Commands) {
            $a = [IO.File]::ReadAllBytes((Join-Path $Root "$name.ps1"))
            $b = [IO.File]::ReadAllBytes((Join-Path $Built "$name.ps1"))
            [Convert]::ToBase64String($b) | Should -Be ([Convert]::ToBase64String($a)) -Because $name
        }
    }
}

Describe 'Module commands' {
    It '<_> has the same parameters as its script' -ForEach @('Invoke-EndpointComplianceScan', 'New-ComplianceRollup', 'Register-ComplianceScanTask') {
        $script = Get-Command (Join-Path $Root "$_.ps1")
        $command = Get-Command $_ -Module EndpointComplianceScan
        @($command.Parameters.Keys | Sort-Object) | Should -Be @($script.Parameters.Keys | Sort-Object)
        foreach ($p in $script.Parameters.Values) {
            $command.Parameters[$p.Name].ParameterType | Should -Be $p.ParameterType -Because $p.Name
        }
        @($command.ParameterSets | ForEach-Object Name | Sort-Object) | Should -Be @($script.ParameterSets | ForEach-Object Name | Sort-Object)
    }

    It '<_> has the script''s help, naming commands instead of script files' -ForEach @('Invoke-EndpointComplianceScan', 'New-ComplianceRollup', 'Register-ComplianceScanTask') {
        $help = Get-Help $_ -Full
        "$($help.Synopsis)".Trim() | Should -Not -BeNullOrEmpty
        $text = $help | Out-String -Width 200
        $text | Should -Not -Match '(Invoke-EndpointComplianceScan|New-ComplianceRollup|Register-ComplianceScanTask)\.ps1'
        @($help.Examples.Example).Count | Should -BeGreaterThan 0
    }

    It 'Register-ComplianceScanTask supports -WhatIf' {
        (Get-Command Register-ComplianceScanTask -Module EndpointComplianceScan).Parameters.Keys | Should -Contain 'WhatIf'
    }
}

Describe 'Running the module' {
    BeforeEach {
        $script:Work = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $Work
        Push-Location -LiteralPath $Work
    }

    AfterEach {
        Pop-Location
    }

    It 'scans a snapshot into .\Reports in the current folder and sets $LASTEXITCODE' {
        $null = Invoke-EndpointComplianceScan -Framework CMMC -FromSnapshot $FixturePath 6>$null
        $LASTEXITCODE | Should -Be 0
        $csv = @(Get-ChildItem -LiteralPath (Join-Path $Work 'Reports') -Filter 'compliance-scan-*-cmmc.csv')
        $csv.Count | Should -Be 1
        @(Import-Csv -LiteralPath $csv[0].FullName).Count | Should -Be 110
        Test-Path -LiteralPath (Join-Path $Built 'Reports') | Should -BeFalse -Because 'nothing is written in the module folder'
    }

    It 'passes -PassThru and other switches through' {
        $results = @(Invoke-EndpointComplianceScan -Framework CMMC -Level 1 -FromSnapshot $FixturePath -OutputPath (Join-Path $Work 'out') -PassThru 6>$null)
        $results.Count | Should -Be 17
    }

    It 'exits 1 through the module when a check fails' {
        $s = Read-Snapshot $FixturePath
        $s.BitLocker.ProtectionStatus = 'Off'
        $path = Join-Path $Work 'fail.json'
        $s | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        $null = Invoke-EndpointComplianceScan -Framework CMMC -FromSnapshot $path -OutputPath (Join-Path $Work 'out') 6>$null
        $LASTEXITCODE | Should -Be 1
    }

    It 'rolls up reports through the module' {
        $null = Invoke-EndpointComplianceScan -Framework CMMC -FromSnapshot $FixturePath 6>$null
        $null = New-ComplianceRollup -Path (Join-Path $Work 'Reports') -OutputPath (Join-Path $Work 'Rollup') 6>$null
        $LASTEXITCODE | Should -Be 0
        @(Get-ChildItem -LiteralPath (Join-Path $Work 'Rollup') -Filter 'compliance-rollup-cmmc.html').Count | Should -Be 1
    }
}

Describe 'Building the module' {
    It 'replaces an earlier build' {
        $out = Join-Path $TestDrive 'again'
        $first = @(& $Builder -OutputPath $out 6>$null)[-1].FullName
        Set-Content -LiteralPath (Join-Path $first 'stale.txt') -Value 'x'
        $second = @(& $Builder -OutputPath $out 6>$null)[-1].FullName
        $second | Should -Be $first
        Test-Path -LiteralPath (Join-Path $second 'stale.txt') | Should -BeFalse
    }

    It 'refuses to replace a folder that is not an earlier build' {
        $out = Join-Path $TestDrive 'other'
        $null = New-Item -ItemType Directory -Path (Join-Path $out 'EndpointComplianceScan')
        Set-Content -LiteralPath (Join-Path $out 'EndpointComplianceScan/keep.txt') -Value 'x'
        { & $Builder -OutputPath $out 6>$null } | Should -Throw "*doesn't hold an earlier build*"
        Test-Path -LiteralPath (Join-Path $out 'EndpointComplianceScan/keep.txt') | Should -BeTrue
    }

    It 'stops when the changelog has no row for the version' {
        . $Builder
        $readme = Join-Path $TestDrive 'README.md'
        Set-Content -LiteralPath $readme -Value '| 0.1.0 | 2026-10-23 | First. |'
        { Get-ReleaseNote -ReadmePath $readme -Version '9.9.9' } | Should -Throw '*no row for 9.9.9*'
        Get-ReleaseNote -ReadmePath $readme -Version '0.1.0' | Should -Be 'First.'
    }

    It 'documents publishing by the manifest file, not the folder (regression: Publish-PSResource read the example profile)' {
        $manifestPath = [regex]::Escape('out\EndpointComplianceScan\EndpointComplianceScan.psd1')
        foreach ($doc in 'tools/Build-Module.ps1', 'README.md') {
            $text = [IO.File]::ReadAllText((Join-Path $Root $doc))
            $text | Should -Match "Publish-PSResource -Path \.\\$manifestPath " -Because $doc
            $text | Should -Not -Match '(?m)^\s*Publish-Module ' -Because "$doc shouldn't offer Publish-Module, which fails to pack with a newer .NET SDK"
        }
    }

    It 'stops when LICENSE has no copyright line' {
        . $Builder
        $license = Join-Path $TestDrive 'LICENSE'
        Set-Content -LiteralPath $license -Value 'No line here.'
        { Get-CopyrightHolder $license } | Should -Throw '*copyright line*'
    }
}
