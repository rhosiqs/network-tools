#requires -Version 5.1
<#
.SYNOPSIS
    One-shot deep diagnosis of TCP/53 blocking, printed as a report and
    saved to a text file that can be handed to a network administrator.

.DESCRIPTION
    Where Start-Tcp53Watch.ps1 answers "is it happening right now, and
    when did it happen", this answers "what exactly is broken and who
    owns the rule". It runs the slow checks the monitor loop deliberately
    skips: a port matrix across every server, a traceroute toward the
    blocked ones, the local firewall rule set, and the truncation test
    that demonstrates real resolution failure.

.PARAMETER ConfigPath
    Path to the JSON configuration. Defaults to config\tcp53.config.json.

.PARAMETER OutputPath
    Exact path to write the report to. Overrides -LogDirectory and skips
    the interactive prompt.

.PARAMETER LogDirectory
    Directory to write the timestamped report into. If neither this nor
    -OutputPath is given, the script asks for it interactively before
    running any diagnostics.

.PARAMETER SkipTraceRoute
    Skip the traceroute stage, which is the slowest part of the run.

.EXAMPLE
    .\Invoke-Tcp53Diagnose.ps1
#>

[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$OutputPath,
    [string]$LogDirectory,
    [switch]$SkipTraceRoute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
. (Join-Path $ScriptRoot 'lib\Dns.Codec.ps1')
. (Join-Path $ScriptRoot 'lib\Net.Probe.ps1')
. (Join-Path $ScriptRoot 'lib\Host.Context.ps1')
. (Join-Path $ScriptRoot 'lib\Block.Classify.ps1')

if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptRoot 'config\tcp53.config.json' }
$config = (Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json

# Where the report goes is asked up front, before any diagnostics run, so
# the operator isn't surprised by the destination after the slow checks
# (traceroute etc.) have already finished. Pass -OutputPath or
# -LogDirectory to skip the prompt for unattended runs.
if (-not $OutputPath) {
    if (-not $LogDirectory) {
        $defaultLogDir = $config.LogDirectory
        if (-not [System.IO.Path]::IsPathRooted($defaultLogDir)) { $defaultLogDir = Join-Path $ScriptRoot $defaultLogDir }
        $answer = Read-Host "Log directory for the diagnosis report [$defaultLogDir]"
        $LogDirectory = if ($answer) { $answer } else { $defaultLogDir }
    }
    if (-not [System.IO.Path]::IsPathRooted($LogDirectory)) { $LogDirectory = Join-Path $ScriptRoot $LogDirectory }
    if (-not (Test-Path -LiteralPath $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
    $OutputPath = Join-Path $LogDirectory ("tcp53-diagnosis-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
}

$report = New-Object 'System.Collections.Generic.List[string]'
function Add-Line {
    param([string]$Text = '', [string]$Colour = 'Gray')
    $report.Add($Text)
    Write-Host $Text -ForegroundColor $Colour
}

Add-Line '=========================================================' 'Cyan'
Add-Line '  TCP/53 BLOCK DIAGNOSIS' 'Cyan'
Add-Line ("  Generated {0} on {1} by {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'), $env:COMPUTERNAME, $env:USERNAME) 'Cyan'
Add-Line '=========================================================' 'Cyan'
Add-Line

# ---------------------------------------------------------------- host
$hostCtx = Get-HostNetworkContext -TargetIp '8.8.8.8'

Add-Line '--- 1. HOST AND PATH IDENTITY ---' 'White'
Add-Line ("  Adapter        : {0} ({1})" -f $hostCtx.AdapterName, $hostCtx.AdapterDescription)
Add-Line ("  Adapter MAC    : {0}" -f $hostCtx.AdapterMac)
Add-Line ("  Local IP       : {0}/{1}" -f $hostCtx.LocalIp, $hostCtx.PrefixLength)
Add-Line ("  Default gateway: {0}" -f $hostCtx.GatewayIp)
Add-Line ("  Gateway MAC    : {0}  [{1}]" -f $hostCtx.GatewayMac, $hostCtx.GatewayMacState)
Add-Line ("  Configured DNS : {0}" -f $hostCtx.ConfiguredDns)
if ($hostCtx.IsWireless) {
    Add-Line ("  Wi-Fi SSID     : {0}" -f $hostCtx.Ssid)
    Add-Line ("  Wi-Fi BSSID    : {0}  (MAC of the access point in the path)" -f $hostCtx.Bssid)
    Add-Line ("  Signal         : {0}%" -f $hostCtx.SignalPercent)
}
Add-Line

# ------------------------------------------------------------ firewall
Add-Line '--- 2. LOCAL WINDOWS FIREWALL, PORT 53 ---' 'White'
$localRules = @(Get-LocalDnsFirewallRules)
if ($localRules.Count -eq 0) {
    Add-Line '  No enabled local block rule covers port 53.'
    Add-Line '  => Any block found below originates outside this machine.'
} else {
    Add-Line ("  {0} enabled local block rule(s) cover port 53:" -f $localRules.Count) 'Yellow'
    foreach ($r in $localRules) {
        Add-Line ("    - {0}" -f $r.DisplayName) 'Yellow'
        Add-Line ("      {0} {1}  local:{2}  remote:{3}  profile:{4}" -f $r.Direction, $r.Protocol, $r.LocalPort, $r.RemotePort, $r.Profile) 'Yellow'
    }
    Add-Line '  => The block is on THIS machine. Fix it here before looking upstream.' 'Yellow'
}
Add-Line

# ------------------------------------------------------------- targets
$gatewayRttMs = -1
if ($hostCtx.GatewayIp) {
    try {
        $avg = (Test-Connection -ComputerName $hostCtx.GatewayIp -Count 2 -ErrorAction Stop | Measure-Object -Property ResponseTime -Average).Average
        if ($null -ne $avg) { $gatewayRttMs = [int][math]::Round($avg) }
    } catch { }
}

$targets = @()
foreach ($t in $config.Targets) {
    if (-not $t.Enabled) { continue }
    $server = $t.Server
    if ($server -eq 'AUTO_GATEWAY') { $server = $hostCtx.GatewayIp }
    if (-not $server) { continue }
    $targets += [pscustomobject]@{ Name = $t.Name; Server = $server; Note = $t.Note }
}

Add-Line '--- 3. TRANSPORT MATRIX ---' 'White'
Add-Line ("  Query: {0} {1}   Control port: TCP/{2}" -f $config.ProbeType, $config.ProbeName, $config.ControlPort)
Add-Line
Add-Line ('  {0,-12} {1,-16} {2,-22} {3,-24} {4}' -f 'TARGET', 'SERVER', 'UDP/53', 'TCP/53', 'TCP/CTRL')
Add-Line ('  ' + ('-' * 92))

$findings = @()
foreach ($t in $targets) {
    $query = New-DnsQueryPacket -Name $config.ProbeName -Type $config.ProbeType
    $udp = Invoke-DnsProbeOverUdp -Server $t.Server -Query $query -TimeoutMs $config.UdpTimeoutMs
    $tcp = Invoke-DnsProbeOverTcp -Server $t.Server -Query $query -ConnectTimeoutMs $config.ConnectTimeoutMs -ReadTimeoutMs $config.ReadTimeoutMs
    $ctl = Test-TcpPortReachable -Server $t.Server -Port $config.ControlPort -TimeoutMs $config.ConnectTimeoutMs

    $findings += [pscustomobject]@{ Target = $t; Udp = $udp; Tcp = $tcp; Ctl = $ctl }

    $colour = if ($tcp.Success) { 'Green' } elseif ($udp.Success) { 'Red' } else { 'Yellow' }
    Add-Line ('  {0,-12} {1,-16} {2,-22} {3,-24} {4}' -f `
        $t.Name, $t.Server,
        ("$($udp.Outcome) $($udp.ElapsedMs)ms"),
        ("$($tcp.Outcome) $($tcp.ElapsedMs)ms"),
        ("$($ctl.Outcome)")) $colour
}
Add-Line

# ------------------------------------------------------- classification
$tcpFailures = @($findings | Where-Object { -not $_.Tcp.Success }).Count
$allBlocked  = $null
if ($findings.Count -gt 1 -and $tcpFailures -gt 0) { $allBlocked = ($tcpFailures -eq $findings.Count) }

Add-Line '--- 4. CLASSIFICATION AND IMPACT ---' 'White'
$anyRealBlock = $false

foreach ($f in $findings) {
    $impact = Invoke-ResolutionImpactTest -Server $f.Target.Server -Name $config.ImpactProbeName `
                                          -Type $config.ImpactProbeType -TimeoutMs $config.UdpTimeoutMs

    $cls = Get-BlockClassification -UdpResult $f.Udp -TcpResult $f.Tcp -ControlPortResult $f.Ctl `
                                   -ImpactResult $impact -GatewayRttMs $gatewayRttMs `
                                   -LocalFirewallRules $localRules -AllTargetsBlocked $allBlocked

    $colour = switch ($cls.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } 'Info' { 'Green' } default { 'Gray' } }
    if ($cls.Blocked -and $cls.BlockType -ne 'DnsServerUnreachable') { $anyRealBlock = $true }

    Add-Line ("  [{0}] {1}" -f $f.Target.Name, $cls.BlockType) $colour
    Add-Line ("      {0}" -f $cls.Description) $colour
    Add-Line ("      Severity   : {0}   Confidence: {1}" -f $cls.Severity, $cls.Confidence)
    Add-Line ("      Scope      : {0} ({1})" -f $cls.Scope, $cls.ScopeConfidence)
    Add-Line ("      Why        : {0}" -f $cls.ScopeReason)
    Add-Line ("      Impact     : {0}" -f $cls.ResolutionImpact)
    Add-Line ("      Evidence   : {0}" -f $cls.Evidence)
    if ($cls.Advice) { Add-Line ("      Next step  : {0}" -f $cls.Advice) }
    Add-Line
}

# ---------------------------------------------------------- traceroute
if (-not $SkipTraceRoute) {
    $blockedTargets = @($findings | Where-Object { -not $_.Tcp.Success -and $_.Udp.Success })
    if ($blockedTargets.Count -gt 0) {
        Add-Line '--- 5. PATH TO THE BLOCKED SERVERS ---' 'White'
        Add-Line '  The last hop that answers is the neighbourhood of the device holding the rule.'
        foreach ($b in $blockedTargets) {
            Add-Line ("  {0} ({1}):" -f $b.Target.Name, $b.Target.Server)
            $hops = Get-FirstHopPath -TargetIp $b.Target.Server
            if ($hops.Count -eq 0) { Add-Line '    (no hops returned)' }
            else {
                $n = 1
                foreach ($h in $hops) { Add-Line ("    {0,2}. {1}" -f $n, $h); $n++ }
            }
        }
        Add-Line
    }
}

# ------------------------------------------------------------- verdict
Add-Line '--- VERDICT ---' 'White'
if ($anyRealBlock) {
    Add-Line '  TCP/53 IS BEING BLOCKED on at least one path.' 'Red'
    Add-Line '  DNS answers larger than one UDP datagram require a TCP retry, so any' 'Red'
    Add-Line '  name with a large record set will intermittently fail to resolve.' 'Red'
} elseif ($tcpFailures -gt 0) {
    Add-Line '  No TCP/53-specific block proven. Some servers are unreachable over both' 'Yellow'
    Add-Line '  transports, which is a connectivity or server problem rather than a port filter.' 'Yellow'
} else {
    Add-Line '  TCP/53 is reachable on every server tested. No block detected.' 'Green'
}
Add-Line

[System.IO.File]::WriteAllLines($OutputPath, $report, (New-Object System.Text.UTF8Encoding $true))
Write-Host ("Report saved to: {0}" -f $OutputPath) -ForegroundColor Cyan
