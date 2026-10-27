# Pester tests for tools/Install-PinnedModule.ps1, which installs the test
# scripts' pinned Pester and PSScriptAnalyzer. No network: the Gallery and the
# download are mocked, the packages are made up, and modules land in TestDrive.
#
# Run through ..\Test-ComplianceScan.ps1, which pins the Pester version and can
# run both PowerShell editions.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'tools/Install-PinnedModule.ps1')
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    function Get-TestFolder {
        # A new, empty folder under TestDrive.
        $p = Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))
        $null = New-Item -ItemType Directory -Path $p
        $p
    }

    function Build-FakePackage {
        # A made-up module package (a zip), with the module at the root or under
        # tools/ as nuget.org's Pester has it.
        param([string]$Version = '1.0.0', [string]$Under = '', [string]$Marker = 'one')
        $src = Get-TestFolder
        $dir = if ($Under) { Join-Path $src $Under } else { $src }
        $null = New-Item -ItemType Directory -Path $dir -Force
        Set-Content -LiteralPath (Join-Path $dir 'FakeModule.psd1') -Value "@{ ModuleVersion = '$Version'; RootModule = 'FakeModule.psm1' }"
        Set-Content -LiteralPath (Join-Path $dir 'FakeModule.psm1') -Value "# $Marker"
        Set-Content -LiteralPath (Join-Path $src 'FakeModule.nuspec') -Value '<package />'
        # A deeper manifest of the same name, which must not be taken for the module.
        $decoy = New-Item -ItemType Directory -Path (Join-Path $dir 'samples/FakeModule') -Force
        Set-Content -LiteralPath (Join-Path $decoy.FullName 'FakeModule.psd1') -Value "@{ ModuleVersion = '0.0.1' }"
        $zip = Join-Path (Get-TestFolder) 'FakeModule.nupkg'
        [IO.Compression.ZipFile]::CreateFromDirectory($src, $zip)
        $zip
    }

    $script:PinnedZip = Build-FakePackage -Under 'tools'
    $script:OtherZip = Build-FakePackage -Marker 'two'
    $script:FakeUrl = 'https://example.invalid/fakemodule.1.0.0.nupkg'
    $PinnedPackage['FakeModule/1.0.0'] = @{ Url = $FakeUrl; Sha256 = (Get-PackageSha256 $PinnedZip) }
}

Describe 'Test tool install' {
    BeforeEach {
        $script:ModuleRoot = Get-TestFolder
        $script:Installed = Join-Path $ModuleRoot 'FakeModule/1.0.0'
        Mock Get-UserModuleRoot { $ModuleRoot }
        Mock Get-PackageProvider { [pscustomobject]@{ Name = 'NuGet' } }
        Mock Install-PackageProvider { throw 'The NuGet provider is already present.' }
    }

    It 'uses the PowerShell Gallery when it works, and downloads nothing' {
        Mock Install-Module { }
        Mock Get-Module { [pscustomobject]@{ Name = 'FakeModule'; Version = [version]'1.0.0' } } -ParameterFilter { $ListAvailable }
        Mock Invoke-WebRequest { throw 'no download expected' }
        $out = Install-PinnedModule -Name FakeModule -Version 1.0.0 -GalleryParameters @{ AllowClobber = $true }
        $out | Should -Be 'Installed FakeModule 1.0.0 from the PowerShell Gallery.'
        Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter { $RequiredVersion -eq '1.0.0' -and $Scope -eq 'CurrentUser' -and $AllowClobber }
        Should -Invoke Invoke-WebRequest -Times 0
    }

    It 'falls back to the pinned download, taking the module from under tools/' {
        Mock Install-Module { throw 'No match was found for the specified search criteria and module name' }
        Mock Invoke-WebRequest { Copy-Item -LiteralPath $PinnedZip -Destination $OutFile }
        $out = Install-PinnedModule -Name FakeModule -Version 1.0.0 -WarningVariable warned 3>$null
        $out | Should -Be "Installed FakeModule 1.0.0 from $FakeUrl (SHA-256 checked)."
        "$warned" | Should -BeLike '*PowerShell Gallery: No match was found*'
        Join-Path $Installed 'FakeModule.psd1' | Should -Exist
        Join-Path $Installed 'FakeModule.psm1' | Should -Exist
        Join-Path $Installed 'tools' | Should -Not -Exist
    }

    It 'falls back when Install-Module reports an error without throwing' {
        # The CI failure of 2026-10-27: the Gallery had no match, as a non-terminating error.
        Mock Install-Module { Write-Error 'No match was found for the specified search criteria and module name' }
        Mock Invoke-WebRequest { Copy-Item -LiteralPath $PinnedZip -Destination $OutFile }
        $out = Install-PinnedModule -Name FakeModule -Version 1.0.0 -WarningVariable warned 3>$null
        $out | Should -Be "Installed FakeModule 1.0.0 from $FakeUrl (SHA-256 checked)."
        "$warned" | Should -BeLike '*No match was found*'
    }

    It 'falls back when Install-Module finishes but the module is not there' {
        Mock Install-Module { }
        Mock Get-Module { } -ParameterFilter { $ListAvailable }
        Mock Invoke-WebRequest { Copy-Item -LiteralPath $PinnedZip -Destination $OutFile }
        $out = Install-PinnedModule -Name FakeModule -Version 1.0.0 -WarningVariable warned 3>$null
        $out | Should -Be "Installed FakeModule 1.0.0 from $FakeUrl (SHA-256 checked)."
        "$warned" | Should -BeLike "*Install-Module finished, but FakeModule 1.0.0 isn't installed*"
    }

    It 'refuses a download whose content is not the pinned package' {
        Mock Install-Module { throw 'gallery down' }
        Mock Invoke-WebRequest { Copy-Item -LiteralPath $OtherZip -Destination $OutFile }
        { Install-PinnedModule -Name FakeModule -Version 1.0.0 3>$null } | Should -Throw '*not the pinned*'
        Join-Path $ModuleRoot 'FakeModule' | Should -Not -Exist
    }

    It 'installs from -PackagePath when both downloads fail, matching the file name in any case' {
        Mock Install-Module { throw 'gallery down' }
        Mock Invoke-WebRequest { throw 'host not found' }
        $packages = Get-TestFolder
        Copy-Item -LiteralPath $OtherZip -Destination (Join-Path $packages 'fakemodule.1.0.0.nupkg')
        $out = Install-PinnedModule -Name FakeModule -Version 1.0.0 -PackagePath $packages 3>$null
        $out | Should -BeLike 'Installed FakeModule 1.0.0 from *fakemodule.1.0.0.nupkg (version checked).'
        (Get-Content -LiteralPath (Join-Path $Installed 'FakeModule.psm1')) | Should -Be '# two'
    }

    It 'says a local package was SHA-256 checked when it is the pinned file' {
        Mock Install-Module { throw 'gallery down' }
        Mock Invoke-WebRequest { throw 'host not found' }
        $packages = Get-TestFolder
        Copy-Item -LiteralPath $PinnedZip -Destination (Join-Path $packages 'FakeModule.1.0.0.nupkg')
        Install-PinnedModule -Name FakeModule -Version 1.0.0 -PackagePath $packages 3>$null |
            Should -BeLike '*(SHA-256 checked).'
    }

    It 'refuses a package that holds another version' {
        Mock Install-Module { throw 'gallery down' }
        Mock Invoke-WebRequest { throw 'host not found' }
        $packages = Get-TestFolder
        Copy-Item -LiteralPath (Build-FakePackage -Version '2.0.0') -Destination (Join-Path $packages 'FakeModule.1.0.0.nupkg')
        { Install-PinnedModule -Name FakeModule -Version 1.0.0 -PackagePath $packages 3>$null } |
            Should -Throw '*holds FakeModule 2.0.0, not 1.0.0*'
        Join-Path $ModuleRoot 'FakeModule' | Should -Not -Exist
    }

    It 'names every source and its reason when all of them fail' {
        Mock Install-Module { throw 'gallery down' }
        Mock Invoke-WebRequest { throw 'host not found' }
        $packages = Get-TestFolder
        $err = { Install-PinnedModule -Name FakeModule -Version 1.0.0 -PackagePath $packages 3>$null } |
            Should -Throw -PassThru
        $msg = $err.Exception.Message
        $msg | Should -BeLike '*PowerShell Gallery: gallery down*'
        $msg | Should -BeLike "*${FakeUrl}: host not found*"
        $msg | Should -BeLike '*FakeModule.1.0.0.nupkg is not in*'
        $msg | Should -BeLike '*pass its folder with -PackagePath*'
    }

    It 'says when no -PackagePath was given' {
        Mock Install-Module { throw 'gallery down' }
        Mock Invoke-WebRequest { throw 'host not found' }
        { Install-PinnedModule -Name FakeModule -Version 1.0.0 3>$null } | Should -Throw '*no -PackagePath was given*'
    }

    It 'says when no second download site is pinned, and downloads nothing' {
        Mock Install-Module { throw 'gallery down' }
        Mock Invoke-WebRequest { throw 'no download expected' }
        { Install-PinnedModule -Name OtherModule -Version 9.9.9 3>$null } | Should -Throw '*no second site is pinned for OtherModule 9.9.9*'
        Should -Invoke Invoke-WebRequest -Times 0
    }

    It 'pins a download for the exact versions the test scripts use' {
        foreach ($s in @(@{ Script = 'Test-ComplianceScan.ps1'; Name = 'Pester' }, @{ Script = 'Test-ComplianceScanLint.ps1'; Name = 'PSScriptAnalyzer' })) {
            $text = Get-Content -LiteralPath (Join-Path $Root $s.Script) -Raw
            $m = [regex]::Match($text, "(?m)^\`$version = '([0-9.]+)'")
            $m.Success | Should -BeTrue -Because "$($s.Script) sets `$version"
            $v = $m.Groups[1].Value
            $pin = $PinnedPackage["$($s.Name)/$v"]
            $pin | Should -Not -BeNullOrEmpty -Because "$($s.Script) pins $($s.Name) $v"
            $pin.Url | Should -Match '^https://'
            $pin.Sha256 | Should -Match '^[0-9a-f]{64}$'
        }
    }
}
