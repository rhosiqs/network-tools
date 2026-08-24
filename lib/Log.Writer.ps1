#requires -Version 5.1
<#
    Log.Writer.ps1
    ------------------------------------------------------------------
    Three sinks, because three different readers need this data:

      *.jsonl  one JSON object per line, every field, nothing flattened.
               Append-only, so a crash mid-write costs one line, not the
               file.
      *.csv    a fixed column set with a UTF-8 BOM so Excel opens it
               without an import wizard.
      console  colour-coded live view.

    Write policy matters as much as format. A monitor that logs every
    healthy poll buries the six lines that matter under a hundred
    thousand that do not, so successes are sampled and failures and
    state transitions are always written. See Test-ShouldLog.
#>

Set-StrictMode -Version Latest

$script:CsvColumns = @(
    'Timestamp', 'TimestampUtc', 'Event',
    'HostName', 'UserName',
    'AdapterName', 'AdapterMac', 'LocalIp',
    'GatewayIp', 'GatewayMac',
    'Ssid', 'Bssid',
    'TargetName', 'TargetIp', 'Port',
    'BlockType', 'Blocked', 'Severity', 'Confidence',
    'Scope', 'ScopeReason',
    'TcpPhase', 'TcpOutcome', 'TcpSocketError', 'TcpConnectMs', 'TcpElapsedMs',
    'UdpOutcome', 'UdpElapsedMs', 'UdpRcode',
    'PortSpecific', 'ControlPort', 'ControlPortOutcome',
    'ResolutionImpact', 'TruncationSeen', 'TcpFallbackOk',
    'Description', 'Evidence'
)

function New-LogContext {
<#
    .SYNOPSIS
        Opens a logging session and returns the handle passed to every write.
#>
    param(
        [Parameter(Mandatory)][string]$Directory,
        [string]$SessionName = 'tcp53',
        [int]$LogSuccessEveryNCycles = 30,
        [switch]$Quiet
    )

    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    }

    $stamp   = Get-Date -Format 'yyyyMMdd'
    $session = Get-Date -Format 'yyyyMMdd-HHmmss'

    $ctx = [pscustomobject]@{
        Directory        = (Resolve-Path -LiteralPath $Directory).Path
        JsonlPath        = Join-Path $Directory "$SessionName-events-$stamp.jsonl"
        CsvPath          = Join-Path $Directory "$SessionName-events-$stamp.csv"
        TextPath         = Join-Path $Directory "$SessionName-session-$session.log"
        SessionId        = $session
        Quiet            = [bool]$Quiet
        SuccessInterval  = $LogSuccessEveryNCycles
        LastBlockType    = @{}
        CycleCount       = @{}
        Counters         = @{}
    }

    if (-not (Test-Path -LiteralPath $ctx.CsvPath)) {
        $header = ($script:CsvColumns -join ',')
        # BOM keeps Excel from mangling UTF-8 on a zh-TW system.
        [System.IO.File]::WriteAllText($ctx.CsvPath, "$header`r`n", (New-Object System.Text.UTF8Encoding $true))
    }

    Write-SessionText -Log $ctx -Text "==== TCP/53 block watch session $session started on $($env:COMPUTERNAME) ===="
    return $ctx
}

function Write-SessionText {
    param($Log, [string]$Text)
    try {
        Add-Content -LiteralPath $Log.TextPath -Value ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Text) -Encoding UTF8
    } catch { }
}

function ConvertTo-CsvField {
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    if ($s -match '[,"\r\n]') { return '"' + ($s -replace '"', '""') + '"' }
    return $s
}

function New-LogRecord {
<#
    .SYNOPSIS
        Flattens one probe cycle into the single record shape used by all sinks.
#>
    param(
        [Parameter(Mandatory)]$HostContext,
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)]$UdpResult,
        [Parameter(Mandatory)]$TcpResult,
        [Parameter(Mandatory)]$Classification,
        $ControlPortResult = $null,
        $ImpactResult = $null,
        [string]$Event = 'Sample'
    )

    $now = Get-Date

    return [ordered]@{
        Timestamp          = $now.ToString('yyyy-MM-dd HH:mm:ss.fff K')
        TimestampUtc       = $now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        Event              = $Event

        HostName           = $HostContext.HostName
        UserName           = $HostContext.UserName

        AdapterName        = $HostContext.AdapterName
        AdapterDescription = $HostContext.AdapterDescription
        AdapterMac         = $HostContext.AdapterMac
        MediaType          = $HostContext.MediaType
        InterfaceIndex     = $HostContext.InterfaceIndex
        LocalIp            = $HostContext.LocalIp
        GatewayIp          = $HostContext.GatewayIp
        GatewayMac         = $HostContext.GatewayMac
        GatewayMacState    = $HostContext.GatewayMacState
        ConfiguredDns      = $HostContext.ConfiguredDns
        Ssid               = $HostContext.Ssid
        Bssid              = $HostContext.Bssid
        SignalPercent      = $HostContext.SignalPercent

        TargetName         = $Target.Name
        TargetIp           = $Target.Server
        Port               = $TcpResult.Port

        BlockType          = $Classification.BlockType
        Blocked            = $Classification.Blocked
        Severity           = $Classification.Severity
        Confidence         = $Classification.Confidence
        Scope              = $Classification.Scope
        ScopeReason        = $Classification.ScopeReason
        Description        = $Classification.Description
        Advice             = $Classification.Advice
        Evidence           = $Classification.Evidence
        PortSpecific       = $Classification.PortSpecific

        TcpPhase           = $TcpResult.Phase
        TcpOutcome         = $TcpResult.Outcome
        TcpSocketError     = $TcpResult.SocketError
        TcpConnectMs       = $TcpResult.ConnectMs
        TcpElapsedMs       = $TcpResult.ElapsedMs
        TcpBytes           = $TcpResult.BytesReceived
        TcpDetail          = $TcpResult.Detail

        UdpOutcome         = $UdpResult.Outcome
        UdpElapsedMs       = $UdpResult.ElapsedMs
        UdpRcode           = $(if ($UdpResult.Response) { $UdpResult.Response.RcodeName } else { $null })
        UdpTruncated       = $(if ($UdpResult.Response) { $UdpResult.Response.Truncated } else { $null })

        ControlPort        = $(if ($ControlPortResult) { $ControlPortResult.Port } else { $null })
        ControlPortOutcome = $(if ($ControlPortResult) { $ControlPortResult.Outcome } else { $null })

        ResolutionImpact   = $Classification.ResolutionImpact
        TruncationSeen     = $(if ($ImpactResult) { $ImpactResult.TruncationSeen } else { $null })
        TcpFallbackOk      = $(if ($ImpactResult) { $ImpactResult.TcpFallbackOk } else { $null })
        ImpactDetail       = $(if ($ImpactResult) { $ImpactResult.Detail } else { $null })
    }
}

function Test-ShouldLog {
<#
    .SYNOPSIS
        Decides whether this sample earns a line on disk.
    .DESCRIPTION
        Always: anything blocked, and any change of block type for a target
        (the transitions are the story). Otherwise: one healthy sample every
        N cycles, so the file still proves the link was up in between.
    .OUTPUTS
        The event label to record, or $null to skip.
#>
    param($Log, [string]$TargetKey, [string]$BlockType, [bool]$Blocked)

    $previous = $null
    if ($Log.LastBlockType.ContainsKey($TargetKey)) { $previous = $Log.LastBlockType[$TargetKey] }
    $Log.LastBlockType[$TargetKey] = $BlockType

    if (-not $Log.CycleCount.ContainsKey($TargetKey)) { $Log.CycleCount[$TargetKey] = 0 }
    $Log.CycleCount[$TargetKey]++

    $key = "$TargetKey/$BlockType"
    if (-not $Log.Counters.ContainsKey($key)) { $Log.Counters[$key] = 0 }
    $Log.Counters[$key]++

    if ($null -ne $previous -and $previous -ne $BlockType) {
        return $(if ($Blocked) { 'BlockStarted' } else { 'BlockCleared' })
    }
    if ($Blocked) { return 'Blocked' }
    if ($null -eq $previous) { return 'Baseline' }
    if ($Log.SuccessInterval -gt 0 -and ($Log.CycleCount[$TargetKey] % $Log.SuccessInterval) -eq 0) { return 'Heartbeat' }
    return $null
}

function Write-LogRecord {
    param($Log, [Parameter(Mandatory)]$Record)

    try {
        $json = ([pscustomobject]$Record | ConvertTo-Json -Depth 6 -Compress)
        Add-Content -LiteralPath $Log.JsonlPath -Value $json -Encoding UTF8
    } catch {
        Write-Warning "JSONL write failed: $($_.Exception.Message)"
    }

    try {
        $fields = foreach ($col in $script:CsvColumns) {
            ConvertTo-CsvField -Value $(if ($Record.Contains($col)) { $Record[$col] } else { $null })
        }
        Add-Content -LiteralPath $Log.CsvPath -Value ($fields -join ',') -Encoding UTF8
    } catch {
        Write-Warning "CSV write failed: $($_.Exception.Message)"
    }
}

function Write-ConsoleSample {
<#
    .SYNOPSIS
        Renders one sample as a single scannable line.
#>
    param($Log, $Record, [switch]$Force)

    if ($Log.Quiet -and -not $Force) { return }

    $colour = switch ($Record.Severity) {
        'High'   { 'Red' }
        'Medium' { 'Yellow' }
        'Info'   { 'Green' }
        default  { 'Gray' }
    }

    $time   = ([datetime]::Now).ToString('HH:mm:ss')
    $target = '{0,-14}' -f $Record.TargetName
    $state  = '{0,-24}' -f $Record.BlockType

    $timing = if ($null -ne $Record.TcpElapsedMs) { '{0,5}ms' -f $Record.TcpElapsedMs } else { '     -' }

    Write-Host ("[{0}] " -f $time) -NoNewline -ForegroundColor DarkGray
    Write-Host ("{0} " -f $target) -NoNewline -ForegroundColor White
    Write-Host ("{0} " -f $state)  -NoNewline -ForegroundColor $colour
    Write-Host ("tcp:{0}/{1}  udp:{2}  {3}" -f $Record.TcpPhase, $Record.TcpOutcome, $Record.UdpOutcome, $timing) -ForegroundColor DarkGray

    if ($Record.Blocked) {
        Write-Host ("            -> {0}" -f $Record.Description) -ForegroundColor $colour
        if ($Record.ResolutionImpact -eq 'ResolutionBroken') {
            Write-Host ("            -> DNS resolution is BROKEN for answers that need the TCP fallback.") -ForegroundColor Red
        }
        Write-Host ("            -> MAC {0} / GW {1} ({2})  scope={3}" -f $Record.AdapterMac, $Record.GatewayIp, $Record.GatewayMac, $Record.Scope) -ForegroundColor DarkGray
    }
}

function Write-SessionSummary {
    param($Log)

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('')
    $lines.Add('==================== SESSION SUMMARY ====================')

    if ($Log.Counters.Count -eq 0) {
        $lines.Add('  No samples were taken.')
    }
    else {
        foreach ($key in ($Log.Counters.Keys | Sort-Object)) {
            $lines.Add(('  {0,-46} {1,6} sample(s)' -f $key, $Log.Counters[$key]))
        }
    }

    $lines.Add('')
    $lines.Add("  JSONL : $($Log.JsonlPath)")
    $lines.Add("  CSV   : $($Log.CsvPath)")
    $lines.Add("  Text  : $($Log.TextPath)")
    $lines.Add('=========================================================')

    foreach ($l in $lines) {
        Write-Host $l -ForegroundColor Cyan
        Write-SessionText -Log $Log -Text $l
    }
}
