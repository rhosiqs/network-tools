#requires -Version 5.1
<#
.SYNOPSIS
    Continuously watches TCP/53 for blocking and logs every block with the
    time, the MAC addresses in the path, and the classified block type.

.DESCRIPTION
    Each cycle, for every configured DNS server:

      1. a DNS transaction over UDP/53   -- the control
      2. the same transaction over TCP/53 -- the subject
      3. a bare TCP connect to a control port on the same host
      4. when TCP/53 fails, a truncation test that proves whether real
         name resolution is broken as a consequence

    The pair of results is classified into a named block type
    (TcpSilentDrop, TcpRejected, TcpResetAfterQuery, ...) and written to
    JSONL, CSV and a text session log.

    Pure Windows PowerShell 5.1. No modules to install, no interpreter to
    download, nothing outside what ships with Windows.

.PARAMETER ConfigPath
    Path to the JSON configuration. Defaults to config\tcp53.config.json
    next to this script.

.PARAMETER IntervalSeconds
    Seconds between cycles while everything is healthy.

.PARAMETER DurationMinutes
    Stop after this many minutes. 0 (the default) runs until Ctrl+C.

.PARAMETER Once
    Run exactly one cycle and exit. Useful from Task Scheduler.

.PARAMETER Target
    Probe only the named targets from the configuration.

.PARAMETER Quiet
    Suppress the per-sample console line; still writes all log files.

.EXAMPLE
    .\Start-Tcp53Watch.ps1
    Watch every configured server until Ctrl+C.

.EXAMPLE
    .\Start-Tcp53Watch.ps1 -Once -Target CampusDNS,GoogleDNS
    One pass over two servers, then exit.

.EXAMPLE
    .\Start-Tcp53Watch.ps1 -DurationMinutes 480 -IntervalSeconds 30 -Quiet
    An unattended eight-hour capture at half-minute resolution.
#>

[CmdletBinding()]
param(
    [string]$ConfigPath,
    [int]$IntervalSeconds = 0,
    [int]$DurationMinutes = 0,
    [switch]$Once,
    [string[]]$Target,
    [string]$LogDirectory,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
. (Join-Path $ScriptRoot 'lib\Dns.Codec.ps1')
. (Join-Path $ScriptRoot 'lib\Net.Probe.ps1')
. (Join-Path $ScriptRoot 'lib\Host.Context.ps1')
. (Join-Path $ScriptRoot 'lib\Block.Classify.ps1')
. (Join-Path $ScriptRoot 'lib\Log.Writer.ps1')

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

if (-not $ConfigPath) { $ConfigPath = Join-Path $ScriptRoot 'config\tcp53.config.json' }
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Configuration file not found: $ConfigPath" }

# TrimStart on U+FEFF: PowerShell 5.1 leaves a byte-order mark in the string
# when the file has one, and ConvertFrom-Json rejects it as a stray character.
$configText = (Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8).TrimStart([char]0xFEFF)
$config = $configText | ConvertFrom-Json

if ($IntervalSeconds -gt 0) { $config.IntervalSeconds = $IntervalSeconds }
if ($LogDirectory)          { $config.LogDirectory    = $LogDirectory }

$logDir = $config.LogDirectory
if (-not [System.IO.Path]::IsPathRooted($logDir)) { $logDir = Join-Path $ScriptRoot $logDir }

# ----------------------------------------------------------------------
# Target resolution
# ----------------------------------------------------------------------

function Resolve-AutoGateway {
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                 Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
                 Sort-Object RouteMetric, ifMetric | Select-Object -First 1
        if ($route) { return $route.NextHop }
    } catch { }
    return $null
}

# powershell.exe -File cannot pass an array: "-Target A,B" arrives as the
# single string "A,B". Re-split so the switch behaves the same whether the
# script is dot-sourced, called, or launched through run_tcp53.bat.
$targetFilter = @()
if ($Target) {
    $targetFilter = @($Target | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$targets = New-Object 'System.Collections.Generic.List[object]'
foreach ($t in $config.Targets) {
    if (-not $t.Enabled) { continue }
    if ($targetFilter.Count -gt 0 -and ($targetFilter -notcontains $t.Name)) { continue }

    $server = $t.Server
    if ($server -eq 'AUTO_GATEWAY') {
        $server = Resolve-AutoGateway
        if (-not $server) {
            Write-Warning "Target '$($t.Name)' skipped: no default gateway could be determined."
            continue
        }
    }
    $targets.Add([pscustomobject]@{ Name = $t.Name; Server = $server; Note = $t.Note })
}

if ($targets.Count -eq 0) { throw 'No enabled targets to probe.' }

# ----------------------------------------------------------------------
# Session-scoped context (expensive; gathered once)
# ----------------------------------------------------------------------

Write-Host ''
Write-Host '=========================================================' -ForegroundColor Cyan
Write-Host '  TCP/53 Block Watch  -  pure Windows PowerShell' -ForegroundColor Cyan
Write-Host '=========================================================' -ForegroundColor Cyan

Write-Host 'Inspecting local Windows Firewall for port 53 block rules...' -ForegroundColor DarkGray
$localFirewallRules = @(Get-LocalDnsFirewallRules)
if ($localFirewallRules.Count -gt 0) {
    Write-Host "  Found $($localFirewallRules.Count) enabled local block rule(s) covering port 53:" -ForegroundColor Yellow
    foreach ($r in $localFirewallRules) {
        Write-Host ("    - {0} [{1} {2} local:{3} remote:{4}]" -f $r.DisplayName, $r.Direction, $r.Protocol, $r.LocalPort, $r.RemotePort) -ForegroundColor Yellow
    }
} else {
    Write-Host '  No local block rule matches port 53.' -ForegroundColor DarkGray
}

# Gateway round-trip time: the yardstick for deciding whether a RST came
# from inside the LAN or from somewhere further out.
$gatewayIp    = Resolve-AutoGateway
$gatewayRttMs = -1
if ($gatewayIp) {
    try {
        $pings = Test-Connection -ComputerName $gatewayIp -Count 2 -ErrorAction Stop
        $avg = ($pings | Measure-Object -Property ResponseTime -Average).Average
        if ($null -ne $avg) { $gatewayRttMs = [int][math]::Round($avg) }
    } catch { }
}
Write-Host ("Default gateway: {0} (RTT {1})" -f ($(if ($gatewayIp) { $gatewayIp } else { 'unknown' })), $(if ($gatewayRttMs -ge 0) { "${gatewayRttMs}ms" } else { 'n/a' })) -ForegroundColor DarkGray

$log = New-LogContext -Directory $logDir -LogSuccessEveryNCycles $config.LogSuccessEveryNCycles -Quiet:$Quiet

Write-Host ''
Write-Host ("Targets   : {0}" -f (($targets | ForEach-Object { "$($_.Name)=$($_.Server)" }) -join ', ')) -ForegroundColor Gray
Write-Host ("Probe     : {0} {1}   Impact probe: {2} {3}" -f $config.ProbeType, $config.ProbeName, $config.ImpactProbeType, $config.ImpactProbeName) -ForegroundColor Gray
Write-Host ("Interval  : {0}s (drops to {1}s while a block is active)" -f $config.IntervalSeconds, $config.FastRetrySeconds) -ForegroundColor Gray
Write-Host ("Logs      : {0}" -f $log.Directory) -ForegroundColor Gray
Write-Host ''
Write-Host 'Press Ctrl+C to stop.' -ForegroundColor DarkGray
Write-Host ''

# ----------------------------------------------------------------------
# One probe cycle
# ----------------------------------------------------------------------

function Invoke-ProbeCycle {
    param($Targets, $Config, $Log, $LocalFirewallRules, [int]$GatewayRttMs, [bool]$IsFirstCycle)

    # Pass 1: gather raw evidence for every target before judging any of
    # them. Whether *all* targets are blocked is itself a classification
    # input, so no target can be classified in isolation.
    $samples = New-Object 'System.Collections.Generic.List[object]'

    foreach ($t in $Targets) {
        $query = New-DnsQueryPacket -Name $Config.ProbeName -Type $Config.ProbeType

        $udp = Invoke-DnsProbeOverUdp -Server $t.Server -Query $query -TimeoutMs $Config.UdpTimeoutMs
        $tcp = Invoke-DnsProbeOverTcp -Server $t.Server -Query $query `
                                      -ConnectTimeoutMs $Config.ConnectTimeoutMs -ReadTimeoutMs $Config.ReadTimeoutMs

        $control = $null
        if (-not $tcp.Success -and $Config.ControlPort -gt 0) {
            $control = Test-TcpPortReachable -Server $t.Server -Port $Config.ControlPort -TimeoutMs $Config.ConnectTimeoutMs
        }

        # The truncation test costs a second round trip, so it only runs
        # when there is something to prove: a failing TCP probe, or the
        # very first cycle to establish a baseline.
        $impact = $null
        if ((-not $tcp.Success) -or $IsFirstCycle) {
            $impact = Invoke-ResolutionImpactTest -Server $t.Server -Name $Config.ImpactProbeName `
                                                  -Type $Config.ImpactProbeType -TimeoutMs $Config.UdpTimeoutMs
        }

        $samples.Add([pscustomobject]@{
            Target = $t; Udp = $udp; Tcp = $tcp; Control = $control; Impact = $impact
        })
    }

    $tcpFailures = @($samples | Where-Object { -not $_.Tcp.Success }).Count
    $allBlocked  = $null
    if ($samples.Count -gt 1 -and $tcpFailures -gt 0) {
        $allBlocked = ($tcpFailures -eq $samples.Count)
    }

    # Pass 2: classify, log, render.
    foreach ($s in $samples) {
        $classification = Get-BlockClassification -UdpResult $s.Udp -TcpResult $s.Tcp `
                              -ControlPortResult $s.Control -ImpactResult $s.Impact `
                              -GatewayRttMs $GatewayRttMs -LocalFirewallRules $LocalFirewallRules `
                              -AllTargetsBlocked $allBlocked

        $event = Test-ShouldLog -Log $Log -TargetKey $s.Target.Name `
                                -BlockType $classification.BlockType -Blocked $classification.Blocked

        # Host context is resolved per target so the MAC recorded belongs to
        # the interface that actually carried this probe.
        $hostCtx = Get-HostNetworkContext -TargetIp $s.Target.Server

        $record = New-LogRecord -HostContext $hostCtx -Target $s.Target -UdpResult $s.Udp -TcpResult $s.Tcp `
                                -Classification $classification -ControlPortResult $s.Control `
                                -ImpactResult $s.Impact -Event $(if ($event) { $event } else { 'Sample' })

        Write-ConsoleSample -Log $Log -Record ([pscustomobject]$record)

        if ($event) {
            Write-LogRecord -Log $Log -Record $record
            if ($event -eq 'BlockStarted') {
                Write-SessionText -Log $Log -Text "BLOCK STARTED on $($s.Target.Name) ($($s.Target.Server)): $($classification.BlockType) - $($classification.Evidence)"
            }
            elseif ($event -eq 'BlockCleared') {
                Write-SessionText -Log $Log -Text "BLOCK CLEARED on $($s.Target.Name) ($($s.Target.Server)): now $($classification.BlockType)"
            }
        }
    }

    return ($tcpFailures -gt 0)
}

# ----------------------------------------------------------------------
# Main loop
# ----------------------------------------------------------------------

$deadline   = $null
if ($DurationMinutes -gt 0) { $deadline = (Get-Date).AddMinutes($DurationMinutes) }

$firstCycle    = $true
$lastBlockSeen = $null

try {
    while ($true) {
        $anyBlocked = Invoke-ProbeCycle -Targets $targets -Config $config -Log $log `
                                        -LocalFirewallRules $localFirewallRules `
                                        -GatewayRttMs $gatewayRttMs -IsFirstCycle $firstCycle
        $firstCycle = $false

        if ($Once) { break }
        if ($deadline -and (Get-Date) -ge $deadline) { break }

        # Mirror the main branch's behaviour: tighten the sampling rate while
        # something is wrong, and hold that rate for a while after it clears
        # so an intermittent block is captured at useful resolution.
        if ($anyBlocked) { $lastBlockSeen = Get-Date }

        $sleepSeconds = $config.IntervalSeconds
        if ($lastBlockSeen -and ((Get-Date) - $lastBlockSeen).TotalSeconds -lt $config.FastRetryHoldSeconds) {
            $sleepSeconds = $config.FastRetrySeconds
        }

        for ($i = 0; $i -lt $sleepSeconds; $i++) {
            if ($deadline -and (Get-Date) -ge $deadline) { break }
            Start-Sleep -Seconds 1
        }
    }
}
finally {
    Write-SessionSummary -Log $log
}
