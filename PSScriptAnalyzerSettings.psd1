# PSScriptAnalyzer settings for endpoint-compliance-scan.
#
# Picked up automatically by the VS Code PowerShell extension, and by
#   Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
# Test-ComplianceScanLint.ps1 runs exactly that, pinned to PSScriptAnalyzer 1.25.0.

@{
    Severity     = @('Error', 'Warning', 'Information')

    ExcludeRules = @(
        # The console summary is coloured status text for a person to read;
        # the reports are the data. Write-Host is the right tool.
        'PSAvoidUsingWriteHost'
        # New-CheckResult Pass 'evidence' is the readable form for 30 checks.
        'PSAvoidUsingPositionalParameters'
    )
}
