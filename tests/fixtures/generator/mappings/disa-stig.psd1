# Fixture for tests/UpdateFrameworkCatalog.Tests.ps1: one catalog built from the
# made-up Sample STIG in ../sources, laid out as tools/mappings/disa-stig.psd1.

@{
    SecurityPolicy = @{
        'Account lockout threshold' = 'LockoutBadCount'
        'Accounts: Guest account status' = 'EnableGuestAccount'
    }

    SecurityOptionRegistry = @{}

    Thresholds = @{
        LockoutThresholdMax = 3
        MinPasswordLength = 14
    }

    NamedByText = @(
        @{ Pattern = 'A firewall provides a line of defense against attack'; Checks = @('SC-FirewallEnabled') }
    )

    Catalogs = @(
        @{
            Id = 'DISA-STIG-Sample'
            File = 'disa-stig-sample'
            PowerStig = 'Sample-1.2'
            Product = 'Westmark Sample'
            AppliesTo = @{ ProductTypes = @(1); MinBuild = 22000 }
            NamedByText = $true
            Overrides = @{
                'V-900002.b' = @{
                    Reason = 'The DISA release moved the BitLocker part to its own rule.'
                    MoveTo = 'V-900004'
                }
            }
        }
    )
}
