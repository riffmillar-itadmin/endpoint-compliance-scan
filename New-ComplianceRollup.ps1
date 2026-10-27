<#
.SYNOPSIS
    Combines the scan reports in a folder into one roll-up page per framework.

.DESCRIPTION
    Reads the compliance-scan-*.json reports that Invoke-EndpointComplianceScan.ps1
    writes, typically from many machines into one shared folder, and writes for
    each framework found:

        compliance-rollup-<framework>.html  machines, and requirements by machine
        compliance-rollup-<framework>.csv   the requirements by machine grid

    Each computer counts once per framework, by its latest scan in the folder.
    Nothing is scanned or re-evaluated: the roll-up shows what the reports say.

    Like the scan, the roll-up is evidence for an assessment, not a verdict. It
    shows counts and states, never a score or a percentage.

    The page lists each machine with its counts, scan date, level and tool
    version, flagging a scan older than -MaxAge days, one run without elevation
    and one with a platform warning. Below that, a grid shows each requirement's
    state on each machine, with the requirements that fail on the most machines
    first. Machines scanned at another level or with another catalog version can
    have a different list of requirements; the page says so, and leaves a cell
    blank where a machine's scan doesn't include the requirement.

    Exit code 0 when every framework's roll-up was written; 2 when the folder holds
    no scan reports, or the roll-up could not be written.

.PARAMETER Path
    The folder of scan reports.

.PARAMETER OutputPath
    Folder for the roll-up files. Defaults to -Path.

.PARAMETER Framework
    Only roll up these framework Ids, such as CMMC or DISA-STIG-WS2025-MS.

.PARAMETER MaxAge
    Days after which a machine's latest scan is flagged as stale. Default 30.

.PARAMETER AsOf
    The date to judge scan age against, in UTC. Defaults to now.

.PARAMETER Recurse
    Also read reports in subfolders of -Path.

.EXAMPLE
    .\New-ComplianceRollup.ps1 -Path \\fileserver\scans
    One roll-up per framework scanned, written into the same folder.

.EXAMPLE
    .\New-ComplianceRollup.ps1 -Path .\Reports -Framework DISA-STIG-WS2025-MS -MaxAge 7 -OutputPath .\Rollup
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutputPath,
    [string[]]$Framework = @(),
    [int]$MaxAge = 30,
    [Nullable[datetime]]$AsOf,
    [switch]$Recurse
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The scanner's shared pieces: HTML style, date parsing, console output, version.
# Dot-sourcing it also defines its parameters here, typed as its own, and two of
# them share a name with this script's. Those two are put back afterwards.
$bound = @{} + $PSBoundParameters
. (Join-Path $PSScriptRoot 'Invoke-EndpointComplianceScan.ps1')
Remove-Variable -Name OutputPath, Framework -Scope Local -ErrorAction SilentlyContinue
$OutputPath = if ($bound.ContainsKey('OutputPath')) { "$($bound.OutputPath)" } else { '' }
# An array passed through pwsh -File arrives as one string, so commas split it too.
$Framework = @(if ($bound.ContainsKey('Framework')) { $bound.Framework | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } })

$RollupState = 'Fail', 'Error', 'Accepted', 'Skipped', 'Manual', 'Pass', 'NotApplicable'
$RollupLabel = @{ Fail = 'Fail'; Error = 'Error'; Accepted = 'Accepted'; Skipped = 'Skipped'; Manual = 'Manual'; Pass = 'Pass'; NotApplicable = 'N/A' }
$RollupMark = @{ Fail = 'F'; Error = 'E'; Accepted = 'A'; Skipped = 'S'; Manual = 'M'; Pass = 'P'; NotApplicable = '-' }

function Read-ScanReport {
    # The scan reports in a folder, as objects with the fields the roll-up uses.
    # Other JSON (records files, roll-ups, anything else) is passed over; a
    # report that can't be read is warned about and left out.
    [CmdletBinding()]
    [OutputType([array])]
    param([string]$Folder, [switch]$Recurse)
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { throw "Folder $Folder not found." }
    $files = @(Get-ChildItem -LiteralPath $Folder -File -Recurse:$Recurse |
            Where-Object { $_.Name -like 'compliance-scan-*.json' -and $_.Name -notlike '*.records.json' })
    @(foreach ($f in $files) {
        try {
            $j = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            if ("$(Get-Prop $j 'Tool')" -ne 'endpoint-compliance-scan' -or $null -eq (Get-Prop $j 'Requirements')) {
                Write-Verbose "$($f.Name) is not a scan report; passed over."
                continue
            }
            $collected = ConvertTo-DateValue (Get-Prop $j 'CollectedUtc')
            if ($null -eq $collected) { throw 'it has no CollectedUtc' }
            [pscustomobject]@{
                File            = $f.FullName
                ComputerName    = "$(Get-Prop $j 'ComputerName')"
                CollectedUtc    = $collected
                Framework       = "$(Get-Prop $j 'Framework')"
                FrameworkName   = "$(Get-Prop $j 'FrameworkName')"
                Complete        = [bool](Get-Prop $j 'Complete')
                Level           = "$(Get-Prop $j 'Level')"
                Version         = "$(Get-Prop $j 'Version')"
                IsElevated      = [bool](Get-Prop $j 'IsElevated')
                PlatformWarning = "$(Get-Prop $j 'PlatformWarning')"
                Requirements    = @(Get-Prop $j 'Requirements')
            }
        } catch {
            Write-Warning "Couldn't read $($f.Name): $($_.Exception.Message). Left out of the roll-up."
        }
    })
}

function Select-LatestScan {
    # Each computer's latest scan of each framework. Group-Object ignores case,
    # so PC01 and pc01 are one computer.
    param([object[]]$Report)
    @($Report | Group-Object { "$($_.Framework)|$($_.ComputerName)" } | ForEach-Object {
            $_.Group | Sort-Object CollectedUtc, File | Select-Object -Last 1
        })
}

function Get-StateCount {
    param([object[]]$Requirements)
    $count = [ordered]@{}
    foreach ($s in $RollupState) { $count[$s] = @($Requirements | Where-Object { $_.State -eq $s }).Count }
    $count
}

function Get-RollupGrid {
    # One row per requirement found in any of the scans, with each machine's state
    # (blank where its scan doesn't include the requirement), ordered by how many
    # machines fail it, then error on it, then by reference.
    param([object[]]$Scan)
    $rows = [ordered]@{}
    foreach ($s in $Scan) {
        foreach ($r in $s.Requirements) {
            $id = "$($r.Requirement)"
            if (-not $rows.Contains($id)) {
                $rows[$id] = [pscustomobject]@{
                    Requirement = $id; Reference = "$($r.Reference)"; Family = "$($r.Family)"; Title = "$($r.Title)"
                    State = @{}; Detail = @{}; Fail = 0; Error = 0
                }
            }
            $row = $rows[$id]
            $row.State[$s.ComputerName] = "$($r.State)"
            $parts = @("$($r.State)")
            if ((Get-Prop $r 'Findings')) { $parts += "$($r.Findings)" }
            if ((Get-Prop $r 'Note')) { $parts += "$($r.Note)" }
            $row.Detail[$s.ComputerName] = $parts -join ': '
            if ($r.State -eq 'Fail') { $row.Fail++ }
            if ($r.State -eq 'Error') { $row.Error++ }
        }
    }
    @($rows.Values | Sort-Object @{ Expression = 'Fail'; Descending = $true }, @{ Expression = 'Error'; Descending = $true }, Reference)
}

function Get-RollupNotice {
    # Banners for the page: what about these scans the reader must know.
    param([object[]]$Scan, [datetime]$AsOf, [int]$MaxAge)
    $notes = @()
    $stale = @($Scan | Where-Object { ($AsOf - $_.CollectedUtc).TotalDays -gt $MaxAge })
    if ($stale.Count) { $notes += "$($stale.Count) of $($Scan.Count) machines' latest scan is older than $MaxAge days: $(@($stale | ForEach-Object ComputerName) -join ', ')." }
    $lists = @($Scan | ForEach-Object { (@($_.Requirements | ForEach-Object { "$($_.Requirement)" }) | Sort-Object) -join '|' } | Select-Object -Unique)
    if ($lists.Count -gt 1) {
        $levels = @($Scan | ForEach-Object Level | Select-Object -Unique | Sort-Object)
        $versions = @($Scan | ForEach-Object Version | Select-Object -Unique | Sort-Object)
        $notes += "The machines' scans don't all list the same requirements (levels: $($levels -join ', '); tool versions: $($versions -join ', ')). A blank cell means that machine's scan doesn't include the requirement."
    }
    $flat = @($Scan | Where-Object { -not $_.IsElevated })
    if ($flat.Count) { $notes += "Not elevated, so checks that need elevation are Skipped: $(@($flat | ForEach-Object ComputerName) -join ', ')." }
    if (@($Scan | Where-Object { -not $_.Complete }).Count) { $notes += 'This catalog lists only the requirements an endpoint can show evidence for; the rest of the framework is assessed elsewhere.' }
    $notes
}

$RollupStyle = @'
.grid td.c { text-align: center; font-weight: 600; padding: 4px 6px; }
.grid th.m { writing-mode: vertical-rl; transform: rotate(180deg); white-space: nowrap; font-weight: 600; padding: 6px 4px; }
.grid td.sticky, .grid th.sticky { position: sticky; left: 0; background: var(--bg); }
.flag { color: var(--skipped); font-weight: 600; }
'@

$RollupScript = @'
(function () {
  var rows = Array.prototype.slice.call(document.querySelectorAll('#grid tbody tr'));
  var only = document.getElementById('only');
  var family = document.getElementById('family');
  var text = document.getElementById('text');
  var shown = document.getElementById('shown');
  function apply() {
    var q = text.value.toLowerCase();
    var n = 0;
    rows.forEach(function (r) {
      var ok = (!only.checked || r.getAttribute('data-bad') === '1') &&
        (!family.value || r.getAttribute('data-family') === family.value) &&
        (!q || r.textContent.toLowerCase().indexOf(q) >= 0);
      r.style.display = ok ? '' : 'none';
      if (ok) { n++; }
    });
    shown.textContent = n + ' of ' + rows.length + ' shown';
  }
  only.addEventListener('change', apply);
  family.addEventListener('change', apply);
  text.addEventListener('input', apply);
  apply();
})();
'@

function ConvertTo-RollupHtml {
    # A single self-contained page, like the scan's own report.
    param([object[]]$Scan, [object[]]$Grid, [string[]]$Notice, [datetime]$AsOf, [int]$MaxAge)
    $first = $Scan[0]
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $machines = @($Scan | Sort-Object @{ Expression = { @($_.Requirements | Where-Object State -eq 'Fail').Count }; Descending = $true }, ComputerName)
    $sb = [Text.StringBuilder]::new()
    $title = "$($first.FrameworkName) - roll-up"
    $null = $sb.Append('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    $null = $sb.Append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.Append("<title>$(ConvertTo-HtmlText $title)</title><style>$HtmlStyle$RollupStyle</style></head><body><main>")
    $null = $sb.Append("<h1>$(ConvertTo-HtmlText $first.FrameworkName): roll-up</h1>")
    $null = $sb.Append("<p class=""meta"">$($Scan.Count) machines &middot; each machine's latest scan &middot; as of $($AsOf.ToString('yyyy-MM-dd HH:mm', $inv)) UTC &middot; endpoint-compliance-scan $ComplianceScanVersion</p>")
    foreach ($n in $Notice) { $null = $sb.Append("<p class=""banner"">$(ConvertTo-HtmlText $n)</p>") }
    $null = $sb.Append('<p class="meta">Evidence for an assessment, not a verdict: the roll-up never states that a machine is compliant, and gives no score.</p>')

    $null = $sb.Append('<h2>Machines</h2><div class="wrap"><table><thead><tr><th>Computer</th><th>Collected (UTC)</th><th class="n">Age (days)</th><th>Level</th><th>Version</th>')
    foreach ($s in $RollupState) { $null = $sb.Append("<th class=""n"">$($RollupLabel[$s])</th>") }
    $null = $sb.Append('<th>Flags</th></tr></thead><tbody>')
    foreach ($m in $machines) {
        $age = [math]::Floor(($AsOf - $m.CollectedUtc).TotalDays)
        $count = Get-StateCount $m.Requirements
        $flags = @()
        if ($age -gt $MaxAge) { $flags += 'Stale' }
        if (-not $m.IsElevated) { $flags += 'Not elevated' }
        if ($m.PlatformWarning) { $flags += 'Platform warning' }
        $null = $sb.Append("<tr><td>$(ConvertTo-HtmlText $m.ComputerName)</td><td>$($m.CollectedUtc.ToString('yyyy-MM-dd HH:mm', $inv))</td><td class=""n"">$age</td>")
        $null = $sb.Append("<td>$(ConvertTo-HtmlText $m.Level)</td><td>$(ConvertTo-HtmlText $m.Version)</td>")
        foreach ($s in $RollupState) {
            $cls = if ($count[$s]) { " $s" } else { '' }
            $null = $sb.Append("<td class=""n$cls"">$($count[$s])</td>")
        }
        $null = $sb.Append("<td class=""flag"" title=""$(ConvertTo-HtmlText $m.PlatformWarning)"">$(ConvertTo-HtmlText ($flags -join ', '))</td></tr>")
    }
    $null = $sb.Append('</tbody></table></div>')

    $null = $sb.Append('<h2>Requirements by machine</h2><p class="meta">')
    $null = $sb.Append((@($RollupState | ForEach-Object { "<span class=""$_"">$($RollupMark[$_])</span> $($RollupLabel[$_])" }) -join ' &middot; '))
    $null = $sb.Append(' &middot; blank: not in that scan. Hover over a cell for its findings.</p><div class="filters">')
    $null = $sb.Append('<label><input type="checkbox" id="only" checked> Only requirements with a Fail or Error</label>')
    $null = $sb.Append('<select id="family" aria-label="Family"><option value="">All families</option>')
    foreach ($fam in @($Grid | ForEach-Object Family | Select-Object -Unique | Sort-Object)) { $null = $sb.Append("<option>$(ConvertTo-HtmlText $fam)</option>") }
    $null = $sb.Append('</select><input id="text" type="search" placeholder="Search" aria-label="Search"><span id="shown" class="meta"></span></div>')
    $null = $sb.Append('<div class="wrap"><table id="grid" class="grid"><thead><tr><th class="sticky">Requirement</th><th class="n">Failing</th>')
    foreach ($m in $machines) { $null = $sb.Append("<th class=""m"">$(ConvertTo-HtmlText $m.ComputerName)</th>") }
    $null = $sb.Append('</tr></thead><tbody>')
    foreach ($row in $Grid) {
        $bad = if ($row.Fail -or $row.Error) { '1' } else { '0' }
        $null = $sb.Append("<tr data-bad=""$bad"" data-family=""$(ConvertTo-HtmlText $row.Family)""><td class=""sticky""><b>$(ConvertTo-HtmlText $row.Reference)</b> $(ConvertTo-HtmlText $row.Title)</td><td class=""n"">$($row.Fail)</td>")
        foreach ($m in $machines) {
            if ($row.State.ContainsKey($m.ComputerName)) {
                $s = $row.State[$m.ComputerName]
                $null = $sb.Append("<td class=""c $s"" title=""$(ConvertTo-HtmlText $row.Detail[$m.ComputerName])"">$($RollupMark[$s])</td>")
            } else {
                $null = $sb.Append('<td class="c"></td>')
            }
        }
        $null = $sb.Append('</tr>')
    }
    $null = $sb.Append("</tbody></table></div></main><script>$RollupScript</script></body></html>")
    $sb.ToString()
}

function ConvertTo-RollupCsvRow {
    # The grid as CSV rows: one per requirement, a column per machine.
    param([object[]]$Scan, [object[]]$Grid)
    $names = @($Scan | ForEach-Object ComputerName | Sort-Object)
    @(foreach ($row in $Grid) {
        $o = [ordered]@{ Requirement = $row.Requirement; Reference = $row.Reference; Family = $row.Family; Title = $row.Title; FailingMachines = $row.Fail }
        foreach ($n in $names) { $o[$n] = if ($row.State.ContainsKey($n)) { $row.State[$n] } else { '' } }
        [pscustomobject]$o
    })
}

function Export-ComplianceRollup {
    # Writes one roll-up per framework and returns the files written.
    param([object[]]$Report, [string]$Folder, [string[]]$Framework = @(), [datetime]$AsOf, [int]$MaxAge)
    $latest = @(Select-LatestScan $Report)
    if ($Framework.Count) {
        $latest = @($latest | Where-Object { $_.Framework -in $Framework })
        if ($latest.Count -eq 0) { throw "No scan reports for $($Framework -join ', ') in the folder." }
    }
    if (-not (Test-Path -LiteralPath $Folder)) { $null = New-Item -ItemType Directory -Path $Folder }
    $utf8 = [Text.UTF8Encoding]::new($false)
    @(foreach ($g in ($latest | Group-Object Framework | Sort-Object Name)) {
        $scan = @($g.Group)
        $grid = @(Get-RollupGrid $scan)
        $notice = @(Get-RollupNotice -Scan $scan -AsOf $AsOf -MaxAge $MaxAge)
        $base = Join-Path $Folder ('compliance-rollup-' + ("$($g.Name)".ToLowerInvariant() -replace '[^a-z0-9.-]', '_'))
        [IO.File]::WriteAllText("$base.html", (ConvertTo-RollupHtml -Scan $scan -Grid $grid -Notice $notice -AsOf $AsOf -MaxAge $MaxAge), $utf8)
        ConvertTo-RollupCsvRow $scan $grid | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8
        [pscustomobject]@{ Framework = $g.Name; Machines = $scan.Count; Notice = $notice; Files = @("$base.html", "$base.csv") }
    })
}

# Dot-sourced (as the tests do): define the functions above and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    $when = if ($AsOf) { ([datetime]$AsOf).ToUniversalTime() } else { [datetime]::UtcNow }
    $folder = if ($OutputPath) { $OutputPath } else { $Path }
    $reports = @(Read-ScanReport -Folder $Path -Recurse:$Recurse)
    if ($reports.Count -eq 0) { throw "No scan reports (compliance-scan-*.json) in $Path." }
    $written = @(Export-ComplianceRollup -Report $reports -Folder $folder -Framework $Framework -AsOf $when -MaxAge $MaxAge)
    Write-Host ''
    Write-Host "Roll-up of $($reports.Count) scan reports, each machine's latest per framework:" -ForegroundColor Cyan
    foreach ($w in $written) {
        Write-Host ("  {0}: {1} machine{2}" -f $w.Framework, $w.Machines, $(if ($w.Machines -eq 1) { '' } else { 's' }))
        foreach ($n in $w.Notice) { Write-Wrapped "    $n" -Indent 4 -Colour Yellow }
    }
    Write-ReportList @($written | ForEach-Object { $_.Files })
    $code = 0
} catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    $code = 2
}
exit $code
