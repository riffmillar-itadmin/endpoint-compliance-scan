# Data for tools/Update-FrameworkCatalog.ps1: where the published source files come
# from. Read as data (literals, arrays and hashtables only); key order is kept.
#
# Every file is pinned by SHA-256, so a mirror can't hand back other content. The
# generator tries, in order: -SourcePath, its download cache, then each URL in
# Mirrors ({Ref} and {Path} filled in), then Package where one is given. A file
# whose hash doesn't match is skipped with a warning and the next source is tried.
#
# To move to a newer release, change Ref (and Version), update the file names and
# hashes, and regenerate.

@{
    # NIST OSCAL content, https://github.com/usnistgov/oscal-content (public domain).
    Oscal = @{
        Ref = 'f0de6d8d8c059d374f15e0ae07508d82e370fc1d'
        Mirrors = @(
            'https://raw.githubusercontent.com/usnistgov/oscal-content/{Ref}/{Path}'
            'https://cdn.jsdelivr.net/gh/usnistgov/oscal-content@{Ref}/{Path}'
        )
        Files = @(
            @{ Name = 'NIST_SP800-171_rev3_catalog.json'; Path = 'nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json'; Sha256 = 'fd68bad4c1fee98dd1b2511884b585fb1f14265d4c5693d0492a25dd66e73dde' }
            @{ Name = 'NIST_SP-800-53_rev5_catalog.json'; Path = 'nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json'; Sha256 = '64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb' }
            @{ Name = 'NIST_SP-800-53_rev5_LOW-baseline_profile.json'; Path = 'nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_LOW-baseline_profile.json'; Sha256 = 'cfd4f5d9a192eb42dc04b745d82f95a85926a2a85a45418034a380a42bda9424' }
            @{ Name = 'NIST_SP-800-53_rev5_MODERATE-baseline_profile.json'; Path = 'nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json'; Sha256 = 'e3a0f11237cfaac24dfcf1586e07683f17423757fd84208deb33196b12e8f590' }
            @{ Name = 'NIST_CSF_v2.0_catalog.json'; Path = 'nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json'; Sha256 = '0ac12904a4bcd877ec91be8e7ddc27278c88b0088c7db77d60ee24918e2563e2' }
        )
    }

    # Microsoft PowerStig processed STIG data, https://github.com/microsoft/PowerStig
    # (MIT). Ref is the commit of the 4.30.0-PSGallery tag.
    PowerStig = @{
        Version = '4.30.0'
        Ref = '8c1425e9ab21a2b8aab54783e2945f16c3bb4811'
        Mirrors = @(
            'https://raw.githubusercontent.com/microsoft/PowerStig/{Ref}/source/StigData/Processed/{Path}'
            'https://cdn.jsdelivr.net/gh/microsoft/PowerStig@{Ref}/source/StigData/Processed/{Path}'
        )
        # The module package from the PowerShell Gallery holds the same files under
        # StigData/Processed.
        Package = 'https://www.powershellgallery.com/api/v2/package/PowerStig/4.30.0'
        Files = @(
            @{ Name = 'WindowsClient-11-2.7.xml'; Path = 'WindowsClient-11-2.7.xml'; Sha256 = '25958ccef507da5b51f4327c8c37ecea69c7654890ec87f89a2871dfdf92d153' }
            @{ Name = 'WindowsClient-11-2.7.org.default.xml'; Path = 'WindowsClient-11-2.7.org.default.xml'; Sha256 = '96decfa082b6d785c6e1748fcae0611c16d3b3b308fde957f78456fb1d6876bc' }
            @{ Name = 'WindowsServer-2019-MS-3.8.xml'; Path = 'WindowsServer-2019-MS-3.8.xml'; Sha256 = '8729f93cf881b2beec6ab4b0ad53c5a9d56f37653cbf5e093631ff80c31081f0' }
            @{ Name = 'WindowsServer-2019-MS-3.8.org.default.xml'; Path = 'WindowsServer-2019-MS-3.8.org.default.xml'; Sha256 = '8e132ca7799890c5ec5f8de70d29b9f096476be86b22804e47882f810e3b6a1f' }
            @{ Name = 'WindowsServer-2019-DC-3.8.xml'; Path = 'WindowsServer-2019-DC-3.8.xml'; Sha256 = '48155b880aceefbc3f7c13b4687d744bfd654907c26628b686b74e6a25b7af7e' }
            @{ Name = 'WindowsServer-2019-DC-3.8.org.default.xml'; Path = 'WindowsServer-2019-DC-3.8.org.default.xml'; Sha256 = 'd9e229f8680478a3dd7b6b756ac81b7077afee9e837bba2a58edc0897de84b04' }
            @{ Name = 'WindowsServer-2022-MS-2.8.xml'; Path = 'WindowsServer-2022-MS-2.8.xml'; Sha256 = 'f1674431abe94c25969c4bb10db5ace83ede126a0ff6e57e6d060c911eac7c36' }
            @{ Name = 'WindowsServer-2022-MS-2.8.org.default.xml'; Path = 'WindowsServer-2022-MS-2.8.org.default.xml'; Sha256 = 'fa6ff3cbb89c91cc3e3d0fd8ee4eaa18c6f625ac0a78cda43a86fcd2f6ccf5f7' }
            @{ Name = 'WindowsServer-2022-DC-2.8.xml'; Path = 'WindowsServer-2022-DC-2.8.xml'; Sha256 = '4ce7d7c8bb0b5d486a89c6173ad3c4866eb8d3509a9434166df859c3786f1d99' }
            @{ Name = 'WindowsServer-2022-DC-2.8.org.default.xml'; Path = 'WindowsServer-2022-DC-2.8.org.default.xml'; Sha256 = 'ca5c7b18febf34aaab21ce1f27aa465d68728e5c99413db3e0ccc52f1e8961b5' }
            @{ Name = 'WindowsServer-2025-MS-1.1.xml'; Path = 'WindowsServer-2025-MS-1.1.xml'; Sha256 = '5fc67bb09d7d76182d1f6b975fea567e549192e796747d3a0a561bcb6a42c31c' }
            @{ Name = 'WindowsServer-2025-MS-1.1.org.default.xml'; Path = 'WindowsServer-2025-MS-1.1.org.default.xml'; Sha256 = '6329d52bffd480b8064e5028262fb34e58eba6a4aaf9b636340568fb41434f36' }
            @{ Name = 'WindowsServer-2025-DC-1.1.xml'; Path = 'WindowsServer-2025-DC-1.1.xml'; Sha256 = 'eac0832dea19f469e3866b6662fd323860b06a93a45da8aca093df74ceb38d19' }
            @{ Name = 'WindowsServer-2025-DC-1.1.org.default.xml'; Path = 'WindowsServer-2025-DC-1.1.org.default.xml'; Sha256 = '65f51765979605950fd519f6081b418180ded42b10594373adf55728b44f853f' }
            @{ Name = 'WindowsFirewall-All-2.2.xml'; Path = 'WindowsFirewall-All-2.2.xml'; Sha256 = 'cb831d86d52bd778d7cd491d7b031897ea96c823b738b5d0b312c5f7e5657f57' }
            @{ Name = 'WindowsFirewall-All-2.2.org.default.xml'; Path = 'WindowsFirewall-All-2.2.org.default.xml'; Sha256 = 'bdbe3edfbb241d334257faffde9a3627929b3db92856211a0073418cd3d403c4' }
        )
    }

    # DISA STIG zips, matched to catalogs by the benchmark ID inside them. DISA has
    # sunset the Server 2019 STIG, so those catalogs stay on PowerStig's release.
    Disa = @(
        @{
            Benchmark = 'Microsoft_Windows_11_STIG'
            Name = 'U_MS_Windows_11_V2R11_STIG.zip'
            Sha256 = '5a1337e899f113a2482debd3ef240a867fdd205423cbf134e8961de249260d54'
            Urls = @('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip')
        }
        @{
            Benchmark = 'MS_Windows_Server_2022_STIG'
            Name = 'U_MS_Windows_Server_2022_V2R11_STIG.zip'
            Sha256 = '808e83970c4f27590f31435856be9810e02d8f72d3c0a67c0a195cae46dbf48e'
            Urls = @('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R11_STIG.zip')
        }
        @{
            Benchmark = 'MS_Windows_Server_2025_STIG'
            Name = 'U_MS_Windows_Server_2025_V1R4_STIG.zip'
            Sha256 = '0b83a3d42789577e5850d1bc60474af2e4c28b28b155f21f7b6a486ee0c1d84e'
            Urls = @('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2025_V1R4_STIG.zip')
        }
        @{
            Benchmark = 'Windows_Firewall_with_Advanced_Security'
            Name = 'U_MS_Windows_Defender_Firewall_V2R2_STIG.zip'
            Sha256 = '4fd9e65948717c06e00605b11e12958eedde409ac50040958e7c13e7146d25b3'
            Urls = @('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Defender_Firewall_V2R2_STIG.zip')
        }
        @{
            Benchmark = 'Active_Directory_Domain'
            Name = 'U_Active_Directory_Domain_V3R8_STIG.zip'
            Sha256 = '0607519b9a4d913f15ed21dd592baf62e8d186ffba8bc3c524f46f08eb858dde'
            Urls = @('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Active_Directory_Domain_V3R8_STIG.zip')
        }
        @{
            Benchmark = 'Active_Directory_Forest'
            Name = 'U_Active_Directory_Forest_V3R2_STIG.zip'
            Sha256 = 'fce2eb549574dab02c0bbde2ea5af8b59f3f1e01a0683db5d406103872defd6a'
            Urls = @('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Active_Directory_Forest_V3R2_STIG.zip')
        }
        @{
            Benchmark = 'Windows_PAW_STIG'
            Name = 'U_MS_Windows_PAW_V3R3_STIG.zip'
            Sha256 = 'b29b94a8e6daf0eb37b6100d9e3ad248d8c8155ca6c917ac5cd6b8fe09eab0be'
            Urls = @('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_PAW_V3R3_STIG.zip')
        }
    )
}
