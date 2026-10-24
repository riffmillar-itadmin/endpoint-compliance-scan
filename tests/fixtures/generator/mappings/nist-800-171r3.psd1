# Fixture for tests/UpdateFrameworkCatalog.Tests.ps1.

@{
    Families = @{
        'Access Control' = 'AC'
        'Audit and Accountability' = 'AU'
    }
    Checks = @{
        '03.01.01' = @('AC-GuestDisabled', 'AC-NoPasswordNotRequired')
    }
}
