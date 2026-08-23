#requires -Version 5.1
<#
    Net.Probe.ps1
    ------------------------------------------------------------------
    Transport-level probes for DNS over TCP/53 and UDP/53.

    Every probe reports the *phase* it died in (Connect / Send / Receive)
    together with the raw Winsock error. That pair is what separates the
    different kinds of blocking from one another:

        Connect + TimedOut          -> packets are being silently dropped
        Connect + ConnectionRefused -> something answered with a RST
        Receive + TimedOut          -> handshake allowed, payload swallowed
        Receive + ConnectionReset   -> the query itself triggered a RST

    A tool that only reports "failed" cannot tell those apart, and they
    point at completely different devices and completely different fixes.
#>

Set-StrictMode -Version Latest

function New-ProbeResult {
    param([string]$Protocol, [string]$Server, [int]$Port)
    return [ordered]@{
        Protocol      = $Protocol
        Server        = $Server
        Port          = $Port
        Success       = $false
        Phase         = 'Init'
        Outcome       = 'NotRun'
        SocketError   = $null
        SocketCode    = $null
        ConnectMs     = $null
        ElapsedMs     = $null
        BytesReceived = 0
        Response      = $null
        Detail        = $null
    }
}

function Resolve-SocketOutcome {
    <#
        Maps a Winsock error onto a stable, phase-aware outcome token.
        Keeping this in one place means the classifier never has to know
        about platform error numbers.
    #>
    param([string]$Phase, $SocketErrorCode)

    $name = [string]$SocketErrorCode
    switch ($name) {
        'ConnectionRefused' { return 'Refused' }
        'TimedOut'          { return $(if ($Phase -eq 'Connect') { 'ConnectTimeout' } else { 'ReadTimeout' }) }
        'HostUnreachable'   { return 'HostUnreachable' }
        'NetworkUnreachable'{ return 'NetworkUnreachable' }
        'ConnectionReset'   { return 'Reset' }
        'ConnectionAborted' { return 'Aborted' }
        'HostNotFound'      { return 'NameResolutionFailed' }
        'AccessDenied'      { return 'LocallyDenied' }
        default             { return "SocketError:$name" }
    }
}

function Get-InnerSocketException {
    param($Exception)
    $e = $Exception
    $guard = 0
    while ($null -ne $e -and $guard++ -lt 8) {
        if ($e -is [System.Net.Sockets.SocketException]) { return $e }
        $e = $e.InnerException
    }
    return $null
}

function Read-ExactBytes {
    <#
        NetworkStream.Read may return fewer bytes than asked for; DNS over
        TCP is length-prefixed so we must fill the buffer exactly or we
        will misparse a perfectly good answer as garbage.
        Returns $null when the peer closed the connection cleanly.
    #>
    param(
        [Parameter(Mandatory)]$Stream,
        [Parameter(Mandatory)][int]$Count,
        [int]$OverallTimeoutMs = 5000
    )

    $buffer = New-Object byte[] $Count
    $filled = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    while ($filled -lt $Count) {
        if ($sw.ElapsedMilliseconds -gt $OverallTimeoutMs) {
            throw (New-Object System.Net.Sockets.SocketException ([int][System.Net.Sockets.SocketError]::TimedOut))
        }
        $read = $Stream.Read($buffer, $filled, $Count - $filled)
        if ($read -le 0) { return $null }   # graceful FIN before we got our data
        $filled += $read
    }
    return $buffer
}

function Invoke-DnsProbeOverTcp {
<#
    .SYNOPSIS
        Performs a full DNS transaction over TCP/53 and reports where it broke.
    .DESCRIPTION
        Uses BeginConnect/EndConnect rather than Connect() so the connect
        timeout is ours to choose. The default OS connect timeout is ~21s,
        long enough that a monitoring loop would stall behind it.
#>
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)]$Query,
        [int]$Port = 53,
        [int]$ConnectTimeoutMs = 3000,
        [int]$ReadTimeoutMs = 4000
    )

    $r = New-ProbeResult -Protocol 'TCP' -Server $Server -Port $Port
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = New-Object System.Net.Sockets.TcpClient
    $client.NoDelay = $true

    try {
        # ---- Phase 1: three-way handshake -------------------------------
        $r.Phase = 'Connect'
        $async = $client.BeginConnect($Server, $Port, $null, $null)

        if (-not $async.AsyncWaitHandle.WaitOne($ConnectTimeoutMs, $false)) {
            $r.Outcome     = 'ConnectTimeout'
            $r.SocketError = 'TimedOut'
            $r.ElapsedMs   = $sw.ElapsedMilliseconds
            $r.Detail      = "No SYN-ACK within ${ConnectTimeoutMs}ms - SYN appears to be silently dropped."
            return [pscustomobject]$r
        }

        $client.EndConnect($async)          # throws SocketException on RST / unreachable
        $r.ConnectMs = $sw.ElapsedMilliseconds

        # ---- Phase 2: send the length-prefixed query --------------------
        $r.Phase  = 'Send'
        $stream   = $client.GetStream()
        $stream.ReadTimeout  = $ReadTimeoutMs
        $stream.WriteTimeout = $ReadTimeoutMs

        $payload = $Query.Bytes
        $framed  = New-Object byte[] ($payload.Length + 2)
        $framed[0] = [byte](($payload.Length -shr 8) -band 0xFF)
        $framed[1] = [byte]($payload.Length -band 0xFF)
        [System.Array]::Copy($payload, 0, $framed, 2, $payload.Length)

        $stream.Write($framed, 0, $framed.Length)
        $stream.Flush()

        # ---- Phase 3: read the length-prefixed answer -------------------
        $r.Phase = 'Receive'

        $lenBytes = Read-ExactBytes -Stream $stream -Count 2 -OverallTimeoutMs $ReadTimeoutMs
        if ($null -eq $lenBytes) {
            $r.Outcome   = 'ClosedWithoutAnswer'
            $r.ElapsedMs = $sw.ElapsedMilliseconds
            $r.Detail    = 'Peer accepted the connection then closed it without sending a DNS reply.'
            return [pscustomobject]$r
        }

        # [int] cast required: a shift keeps the left operand's type, so
        # [byte] -shl 8 discards the high byte and caps replies at 255 bytes.
        $respLen = (([int]$lenBytes[0]) -shl 8) -bor [int]$lenBytes[1]
        if ($respLen -le 0 -or $respLen -gt 65535) {
            $r.Outcome   = 'MalformedFraming'
            $r.ElapsedMs = $sw.ElapsedMilliseconds
            $r.Detail    = "Reply announced an impossible length of $respLen bytes."
            return [pscustomobject]$r
        }

        $body = Read-ExactBytes -Stream $stream -Count $respLen -OverallTimeoutMs $ReadTimeoutMs
        if ($null -eq $body) {
            $r.Outcome   = 'TruncatedStream'
            $r.ElapsedMs = $sw.ElapsedMilliseconds
            $r.Detail    = "Connection closed after $respLen-byte header but before the body arrived."
            return [pscustomobject]$r
        }

        $r.BytesReceived = $body.Length
        $r.ElapsedMs     = $sw.ElapsedMilliseconds
        $parsed          = Read-DnsResponse -Buffer $body
        $r.Response      = $parsed

        if (-not $parsed.Valid) {
            $r.Outcome = 'UnparseableResponse'
            $r.Detail  = $parsed.ParseError
        }
        elseif ($parsed.TransactionId -ne $Query.TransactionId) {
            $r.Outcome = 'TransactionIdMismatch'
            $r.Detail  = "Expected ID $($Query.TransactionId) but received $($parsed.TransactionId) - the reply did not come from the server we asked."
        }
        else {
            $r.Success = $true
            $r.Outcome = 'Answered'
            $r.Detail  = "$($parsed.RcodeName), $($parsed.AnswerCount) answer(s), $($body.Length) bytes."
        }

        return [pscustomobject]$r
    }
    catch {
        $sockEx = Get-InnerSocketException -Exception $_.Exception
        $r.ElapsedMs = $sw.ElapsedMilliseconds
        if ($null -ne $sockEx) {
            $r.SocketError = [string]$sockEx.SocketErrorCode
            $r.SocketCode  = $sockEx.ErrorCode
            $r.Outcome     = Resolve-SocketOutcome -Phase $r.Phase -SocketErrorCode $sockEx.SocketErrorCode
            $r.Detail      = $sockEx.Message
        }
        else {
            $r.Outcome = 'Exception'
            $r.Detail  = $_.Exception.Message
        }
        return [pscustomobject]$r
    }
    finally {
        try { $client.Close() } catch { }
    }
}

function Invoke-DnsProbeOverUdp {
<#
    .SYNOPSIS
        Performs a DNS transaction over UDP/53.
    .DESCRIPTION
        UDP is the control case. If UDP works and TCP does not, the fault
        is specific to TCP/53 rather than to the DNS server or the link.
        UdpClient.Connect() makes the socket see ICMP port-unreachable as
        a ConnectionReset, which is how an actively refused UDP probe is
        told apart from one that vanished.
#>
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)]$Query,
        [int]$Port = 53,
        [int]$TimeoutMs = 3000
    )

    $r = New-ProbeResult -Protocol 'UDP' -Server $Server -Port $Port
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $udp = $null

    try {
        $r.Phase = 'Send'
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Client.SendTimeout    = $TimeoutMs
        $udp.Connect($Server, $Port)
        [void]$udp.Send($Query.Bytes, $Query.Bytes.Length)

        $r.Phase = 'Receive'
        $remote  = New-Object System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Any), 0
        $body    = $udp.Receive([ref]$remote)

        $r.BytesReceived = $body.Length
        $r.ElapsedMs     = $sw.ElapsedMilliseconds
        $parsed          = Read-DnsResponse -Buffer $body
        $r.Response      = $parsed

        if (-not $parsed.Valid) {
            $r.Outcome = 'UnparseableResponse'
            $r.Detail  = $parsed.ParseError
        }
        elseif ($parsed.TransactionId -ne $Query.TransactionId) {
            $r.Outcome = 'TransactionIdMismatch'
            $r.Detail  = "Expected ID $($Query.TransactionId) but received $($parsed.TransactionId)."
        }
        else {
            $r.Success = $true
            $r.Outcome = $(if ($parsed.Truncated) { 'AnsweredTruncated' } else { 'Answered' })
            $r.Detail  = "$($parsed.RcodeName), $($parsed.AnswerCount) answer(s), TC=$($parsed.Truncated)."
        }

        return [pscustomobject]$r
    }
    catch {
        $sockEx = Get-InnerSocketException -Exception $_.Exception
        $r.ElapsedMs = $sw.ElapsedMilliseconds
        if ($null -ne $sockEx) {
            $r.SocketError = [string]$sockEx.SocketErrorCode
            $r.SocketCode  = $sockEx.ErrorCode
            $r.Outcome     = Resolve-SocketOutcome -Phase $r.Phase -SocketErrorCode $sockEx.SocketErrorCode
            $r.Detail      = $sockEx.Message
        }
        else {
            $r.Outcome = 'Exception'
            $r.Detail  = $_.Exception.Message
        }
        return [pscustomobject]$r
    }
    finally {
        if ($null -ne $udp) { try { $udp.Close() } catch { } }
    }
}

function Invoke-ResolutionImpactTest {
<#
    .SYNOPSIS
        Answers the question the user actually cares about: does name
        resolution still work for a payload that needs the TCP fallback?
    .DESCRIPTION
        Two steps, in the order a real client experiences them:
          1. Ask over UDP while advertising a 512-byte buffer. A large
             answer comes back with the TC bit set.
          2. If (and only if) TC was set, retry over TCP -- exactly what
             the Windows resolver does next. If that retry cannot complete,
             the name is unresolvable for this host even though plain UDP
             "works", which is the signature failure of a TCP/53 block.
#>
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$Name,
        [string]$Type = 'TXT',
        [int]$TimeoutMs = 3000
    )

    $query = New-DnsQueryPacket -Name $Name -Type $Type -EnableEdns -UdpPayloadSize 512
    $udp   = Invoke-DnsProbeOverUdp -Server $Server -Query $query -TimeoutMs $TimeoutMs

    $result = [ordered]@{
        Name             = $Name
        Type             = $Type
        Server           = $Server
        UdpOutcome       = $udp.Outcome
        TruncationSeen   = $false
        TcpFallbackTried = $false
        TcpFallbackOk    = $false
        Resolved         = $false
        Impact           = 'Unknown'
        Detail           = $null
    }

    if (-not $udp.Success) {
        $result.Impact = 'UdpFailed'
        $result.Detail = "UDP query failed ($($udp.Outcome)); TCP fallback cannot be assessed from this sample."
        return [pscustomobject]$result
    }

    $result.TruncationSeen = [bool]$udp.Response.Truncated

    if (-not $result.TruncationSeen) {
        $result.Resolved = ($udp.Response.AnswerCount -gt 0)
        $result.Impact   = 'NoFallbackRequired'
        $result.Detail   = "Answer fit in a single UDP datagram (TC=0); this query never needs TCP."
        return [pscustomobject]$result
    }

    # The server told us to come back over TCP. Do exactly that.
    $tcpQuery = New-DnsQueryPacket -Name $Name -Type $Type
    $tcp      = Invoke-DnsProbeOverTcp -Server $Server -Query $tcpQuery -ConnectTimeoutMs $TimeoutMs -ReadTimeoutMs ($TimeoutMs + 1000)

    $result.TcpFallbackTried = $true
    $result.TcpFallbackOk    = [bool]$tcp.Success
    $result.Resolved         = [bool]($tcp.Success -and $tcp.Response.AnswerCount -gt 0)

    if ($result.Resolved) {
        $result.Impact = 'FallbackSucceeded'
        $result.Detail = "UDP set TC=1 and the TCP retry returned $($tcp.Response.AnswerCount) answer(s)."
    }
    else {
        $result.Impact = 'ResolutionBroken'
        $result.Detail = "UDP set TC=1 but the mandatory TCP retry failed ($($tcp.Outcome)). This name is unresolvable from this host."
    }

    return [pscustomobject]$result
}

function Test-TcpPortReachable {
    <#
        Bare TCP reachability with no DNS semantics. Used to compare port 53
        against a control port on the same host: if 443 connects and 53 does
        not, the filtering is port-specific rather than host-specific.
    #>
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 3000
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Server, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return [pscustomobject]@{ Server = $Server; Port = $Port; Connected = $false; Outcome = 'ConnectTimeout'; ElapsedMs = $sw.ElapsedMilliseconds }
        }
        $client.EndConnect($async)
        return [pscustomobject]@{ Server = $Server; Port = $Port; Connected = $true; Outcome = 'Connected'; ElapsedMs = $sw.ElapsedMilliseconds }
    }
    catch {
        $sockEx = Get-InnerSocketException -Exception $_.Exception
        $outcome = if ($null -ne $sockEx) { Resolve-SocketOutcome -Phase 'Connect' -SocketErrorCode $sockEx.SocketErrorCode } else { 'Exception' }
        return [pscustomobject]@{ Server = $Server; Port = $Port; Connected = $false; Outcome = $outcome; ElapsedMs = $sw.ElapsedMilliseconds }
    }
    finally {
        try { $client.Close() } catch { }
    }
}
