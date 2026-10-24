# Fixture for tests/UpdateFrameworkCatalog.Tests.ps1: the sources in
# ../sources, pinned as tools/mappings/sources.psd1 pins the real ones. The
# mirrors are never reached: the tests pass -SourcePath and -Offline, or mock
# the download.

@{
    Oscal = @{
        Ref = 'fixture'
        Mirrors = @(
            'https://mirror-one.invalid/{Ref}/{Path}'
            'https://mirror-two.invalid/{Ref}/{Path}'
        )
        Files = @(
            @{ Name = 'NIST_SP800-171_rev3_catalog.json'; Path = 'sp800-171.json'; Sha256 = '97d8f090f676896f34ae540626c2fdeec7dbf84f1c4b81b26769bc739ea9252e' }
            @{ Name = 'NIST_SP-800-53_rev5_catalog.json'; Path = 'sp800-53.json'; Sha256 = '0487cc95ae605078a5a6e7fe4e1ababc08bbafcf28f6015f5cbe8d64a23c6ff7' }
            @{ Name = 'NIST_SP-800-53_rev5_LOW-baseline_profile.json'; Path = 'low.json'; Sha256 = '1cccfc45ed06090b1b572639e9c5d4924d7b9b1ab33c9eb99c3963cbcf1c1c99' }
            @{ Name = 'NIST_SP-800-53_rev5_MODERATE-baseline_profile.json'; Path = 'moderate.json'; Sha256 = '5ba1666a5957d2030d638fdcb639aa3c543de062b6ccf96e1972e2bf8062edec' }
            @{ Name = 'NIST_CSF_v2.0_catalog.json'; Path = 'csf.json'; Sha256 = 'e8995a29adaf1f65d86e1c134cca916321fe8c693b7756670f56355d7491a9fe' }
        )
    }

    PowerStig = @{
        Version = '1.2'
        Ref = 'fixture'
        Mirrors = @('https://mirror-one.invalid/{Ref}/{Path}')
        Package = 'https://package.invalid/Sample/1.2'
        Files = @(
            @{ Name = 'Sample-1.2.xml'; Path = 'Sample-1.2.xml'; Sha256 = 'cc2ae0bc979e0507e1127c171c5baf9ad7588600aaa2a67ba4a6588ed7da4b72' }
            @{ Name = 'Sample-1.2.org.default.xml'; Path = 'Sample-1.2.org.default.xml'; Sha256 = 'a7e7d0ece3b361820fd345916d09184eedf9f8f905e14d5a51eeb9c44448af48' }
        )
    }

    # No pinned DISA zip: the tests pass the DISA fixture with -StigPath.
    Disa = @()
}
