<#
.SYNOPSIS
    Installs the module versions the test scripts are pinned to, with fallbacks.

.DESCRIPTION
    Dot-sourced by Test-ComplianceScan.ps1 and Test-ComplianceScanLint.ps1.
    Install-PinnedModule installs a module for the current user from the first
    source that works:

        1. the PowerShell Gallery (Install-Module)
        2. a second download site, with the package checked against a pinned
           SHA-256: nuget.org for Pester, the GitHub release for PSScriptAnalyzer
        3. <Name>.<Version>.nupkg in -PackagePath, for a machine with no
           internet access

    Each source that fails is reported with its reason before the next is
    tried, and the source that worked is named. When every source fails it
    throws, listing each one and why.
#>

# The second download site for each pinned version. Update the hash with the
# version; a package with any other content is refused.
$PinnedPackage = @{
    'Pester/6.2.0'            = @{
        Url    = 'https://api.nuget.org/v3-flatcontainer/pester/6.2.0/pester.6.2.0.nupkg'
        Sha256 = 'f7a97aae1ce55199fa8b6f385442c99c120dbcc2dd19509d03a44b14475e367f'
    }
    'PSScriptAnalyzer/1.25.0' = @{
        Url    = 'https://github.com/PowerShell/PSScriptAnalyzer/releases/download/1.25.0/PSScriptAnalyzer.1.25.0.nupkg'
        Sha256 = '14e634c828eb98efb9f40b2918ba90f139ed5eccdf663a2a747736d996995d60'
    }
}

function Get-PackageSha256 {
    param([string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Get-UserModuleRoot {
    # Where Install-Module -Scope CurrentUser puts modules, so Get-Module
    # -ListAvailable finds a module installed from a package the same way.
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        return Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules'
    }
    if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
        return Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules'
    }
    Join-Path $HOME '.local/share/powershell/Modules'
}

function Install-ModulePackage {
    # Unpacks a module .nupkg into the user's module folder. The module is the
    # folder holding <Name>.psd1, wherever the package keeps it (nuget.org's
    # Pester has it under tools/), and it must declare the pinned version.
    param([string]$Package, [string]$Name, [string]$Version)
    $temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($Package, $temp)
        $manifest = @(Get-ChildItem -LiteralPath $temp -Recurse -File |
                Where-Object Name -eq "$Name.psd1" | Sort-Object { $_.FullName.Length })
        if ($manifest.Count -eq 0) { throw "the package has no $Name.psd1" }
        $found = (Import-PowerShellDataFile -LiteralPath $manifest[0].FullName).ModuleVersion
        if ("$found" -ne $Version) { throw "the package holds $Name $found, not $Version" }
        $target = Join-Path (Join-Path (Get-UserModuleRoot) $Name) $Version
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Get-ChildItem -LiteralPath $manifest[0].DirectoryName | Copy-Item -Destination $target -Recurse -Force
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-PinnedModule {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Version,
        [string]$PackagePath,
        [hashtable]$GalleryParameters = @{}
    )
    $failed = [Collections.Generic.List[string]]::new()
    # Windows PowerShell 5.1 may not offer TLS 1.2 by default.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    try {
        # Windows PowerShell 5.1 needs the NuGet provider for the Gallery.
        if ($PSVersionTable.PSEdition -ne 'Core' -and -not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
        }
        Install-Module $Name -RequiredVersion $Version -Scope CurrentUser -Force -ErrorAction Stop @GalleryParameters
        # Install-Module can report a failure without throwing, so check the result.
        if (-not (Get-Module -ListAvailable -Name $Name | Where-Object { "$($_.Version)" -eq $Version })) {
            throw "Install-Module finished, but $Name $Version isn't installed."
        }
        Write-Output "Installed $Name $Version from the PowerShell Gallery."
        return
    } catch {
        $failed.Add("PowerShell Gallery: $($_.Exception.Message)")
        Write-Warning "Couldn't install $Name $Version from the PowerShell Gallery: $($_.Exception.Message) Trying the next source."
    }

    $pin = $PinnedPackage["$Name/$Version"]
    if (-not $pin) {
        $failed.Add("download: no second site is pinned for $Name $Version in tools/Install-PinnedModule.ps1")
    } else {
        $file = Join-Path ([IO.Path]::GetTempPath()) "$Name.$Version.$([guid]::NewGuid().ToString()).nupkg"
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $pin.Url -OutFile $file -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
            $hash = Get-PackageSha256 $file
            if ($hash -ne $pin.Sha256) { throw "the package's SHA-256 is $hash, not the pinned $($pin.Sha256)" }
            Install-ModulePackage -Package $file -Name $Name -Version $Version
            Write-Output "Installed $Name $Version from $($pin.Url) (SHA-256 checked)."
            return
        } catch {
            $failed.Add("$($pin.Url): $($_.Exception.Message)")
            Write-Warning "Couldn't install $Name $Version from $($pin.Url): $($_.Exception.Message) Trying the next source."
        } finally {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }

    $leaf = "$Name.$Version.nupkg"
    if (-not $PackagePath) {
        $failed.Add("local package: no -PackagePath was given to look for $leaf in")
    } else {
        try {
            $file = @(Get-ChildItem -LiteralPath $PackagePath -File | Where-Object Name -eq $leaf)
            if ($file.Count -eq 0) { throw "$leaf is not in $PackagePath" }
            # A package saved from the Gallery is a different file from the pinned
            # download, so only the version it declares is checked.
            $note = if ($pin -and (Get-PackageSha256 $file[0].FullName) -eq $pin.Sha256) { 'SHA-256 checked' } else { 'version checked' }
            Install-ModulePackage -Package $file[0].FullName -Name $Name -Version $Version
            Write-Output "Installed $Name $Version from $($file[0].FullName) ($note)."
            return
        } catch {
            $failed.Add("local package: $($_.Exception.Message)")
        }
    }

    throw ("Couldn't install $Name $Version from any source:`n  $($failed -join "`n  ")`n" +
        "Save $leaf (from https://www.powershellgallery.com/packages/$Name/$Version) and pass its folder with -PackagePath.")
}
