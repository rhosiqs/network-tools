#requires -Version 5.1
<#
    Block.Classify.ps1
    ------------------------------------------------------------------
    Turns a pair of raw probe results (UDP/53 + TCP/53) into a named
    block type, a confidence, and a guess at which device is responsible.

    The whole design rests on one idea: UDP/53 is the control. DNS lives
    on UDP, so if UDP answers normally while TCP does not, the link, the
    route and the server are all fine and the difference is a rule that
    names the TCP protocol. Everything below is the elaboration of that
    comparison plus the Winsock evidence for *how* TCP died.

    Block types (BlockType field, stable tokens for log analysis):

      None                    healthy: TCP/53 completes a full transaction
      TcpRejected             RST on connect -- an explicit reject rule
      TcpSilentDrop           SYN vanishes -- a drop/deny rule (most common)
      TcpUnreachable          ICMP unreachable -- routing or ACL on a hop
      TcpHandshakeThenNoData  connect OK, no reply -- middlebox swallowing
      TcpResetAfterQuery      RST after the query -- DPI on DNS content
      TcpClosedWithoutAnswer  clean FIN with no reply -- proxy or no service
      TcpAnswerSuspect        a reply arrived that we did not ask for
      UdpBlockedTcpOk         inverse case: UDP filtered, TCP allowed
      DnsServerUnreachable    both transports dead -- not TCP-53-specific
      Indeterminate           evidence does not support a call

    None and DnsServerUnreachable report Blocked=$false: neither carries
    evidence of a rule against TCP/53. A host that runs no DNS service at
    all lands in the second one.
#>

Set-StrictMode -Version Latest

$script:BlockTypeInfo = @{
    'None' = @{
        Severity = 'Info'
        Summary  = 'TCP/53 completed a full DNS transaction.'
        Advice   = 'No action required.'
    }
    'TcpRejected' = @{
        Severity = 'High'
        Summary  = 'TCP/53 was actively refused with a RST.'
        Advice   = 'A device answered the SYN with a RST. Check for a REJECT-style rule on the local host, the gateway, or the DNS server itself.'
    }
    'TcpSilentDrop' = @{
        Severity = 'High'
        Summary  = 'TCP/53 got no reply to the SYN until the timeout expired.'
        Advice   = 'The SYN is being discarded with no reply, the shape a firewall DROP rule produces. Compare against a control port to see whether the rule targets port 53.'
    }
    'TcpUnreachable' = @{
        Severity = 'High'
        Summary  = 'TCP/53 returned an ICMP unreachable.'
        Advice   = 'A router returned an ICMP unreachable. Look at routing and at router ACLs rather than at a stateful firewall.'
    }
    'TcpHandshakeThenNoData' = @{
        Severity = 'High'
        Summary  = 'The TCP handshake completed but the DNS query got no reply.'
        Advice   = 'Something accepted the connection and did not answer the query. Compare with another server to see whether the payload is being dropped in the path.'
    }
    'TcpResetAfterQuery' = @{
        Severity = 'High'
        Summary  = 'The connection was reset after the DNS query was sent.'
        Advice   = 'The connection survived until the DNS query was sent, then was reset, so the selection is on payload rather than on the port number alone.'
    }
    'TcpClosedWithoutAnswer' = @{
        Severity = 'Medium'
        Summary  = 'The peer closed the connection cleanly without answering.'
        Advice   = 'A clean FIN with no answer. Either a proxy terminated the session or this server does not serve DNS over TCP; test a second server to tell them apart.'
    }
    'TcpAnswerSuspect' = @{
        Severity = 'High'
        Summary  = 'TCP/53 answered with content that does not match the query.'
        Advice   = 'A reply came back that does not match the query we sent. Check for DNS interception on this path.'
    }
    'UdpBlockedTcpOk' = @{
        Severity = 'Medium'
        Summary  = 'UDP/53 failed while TCP/53 completed normally.'
        Advice   = 'The inverse of the pattern this tool looks for. Check for UDP filtering; some captive networks force DNS over TCP.'
    }
    'DnsServerUnreachable' = @{
        Severity = 'Low'
        Summary  = 'Neither UDP/53 nor TCP/53 answered, so this sample says nothing about TCP/53.'
        Advice   = 'Both transports failed. Either this host does not serve DNS at all, or it is unreachable; check that before reading anything into the TCP result.'
    }
    'Indeterminate' = @{
        Severity = 'Low'
        Summary  = 'The evidence does not support a block type.'
        Advice   = 'Not enough signal to classify. Re-run with a longer timeout or against another server.'
    }
}

# The two types that carry no evidence of a TCP/53 block. Keeping them out
# of Blocked is what stops a router that simply does not run a DNS service
# from being reported as a filtered one.
$script:NotABlock = @('None', 'DnsServerUnreachable')

function Get-BlockTypeMetadata {
    param([string]$BlockType)
    if ($script:BlockTypeInfo.ContainsKey($BlockType)) { return $script:BlockTypeInfo[$BlockType] }
    return @{ Severity = 'Low'; Summary = $BlockType; Advice = '' }
}

function Get-BlockScope {
<#
    .SYNOPSIS
        Narrows down *where* the rule lives, from the shape of the evidence.
    .DESCRIPTION
        Three independent signals are combined:
          - a matching local Windows Firewall rule pins it to this host;
          - a refusal returned faster than the round trip to the gateway
            cannot have come from beyond the gateway;
          - whether every server is blocked or only one separates a
            network-wide policy from a server-side setting.
#>
    param(
        $TcpResult,
        [int]$GatewayRttMs = -1,
        [array]$LocalFirewallRules = @(),
        [Nullable[bool]]$AllTargetsBlocked = $null
    )

    if ($LocalFirewallRules -and $LocalFirewallRules.Count -gt 0) {
        return [pscustomobject]@{
            Scope      = 'LocalHost'
            Confidence = 'High'
            Reason     = "A local Windows Firewall block rule covering port 53 is enabled: $(($LocalFirewallRules | ForEach-Object { $_.DisplayName }) -join '; ')"
        }
    }

    if ($TcpResult.Outcome -eq 'LocallyDenied') {
        return [pscustomobject]@{ Scope = 'LocalHost'; Confidence = 'High'; Reason = 'The local socket layer denied the connection outright.' }
    }

    if ($TcpResult.Outcome -eq 'Refused' -and $null -ne $TcpResult.ElapsedMs -and $TcpResult.ElapsedMs -lt 2) {
        return [pscustomobject]@{ Scope = 'LocalHost'; Confidence = 'Medium'; Reason = "The RST came back in $($TcpResult.ElapsedMs)ms, too fast to have travelled off this machine." }
    }

    if ($TcpResult.Outcome -eq 'Refused' -and $GatewayRttMs -ge 0 -and $null -ne $TcpResult.ElapsedMs -and $TcpResult.ElapsedMs -le ($GatewayRttMs + 2)) {
        return [pscustomobject]@{ Scope = 'FirstHop'; Confidence = 'Medium'; Reason = "The RST arrived in $($TcpResult.ElapsedMs)ms against a ${GatewayRttMs}ms gateway RTT, so it originated at or before the gateway." }
    }

    if ($AllTargetsBlocked -eq $true) {
        return [pscustomobject]@{ Scope = 'NetworkEdge'; Confidence = 'Medium'; Reason = 'Every DNS server tested is blocked on TCP/53, which points at a network-wide egress policy rather than any one server.' }
    }

    if ($AllTargetsBlocked -eq $false) {
        return [pscustomobject]@{ Scope = 'ServerOrPath'; Confidence = 'Medium'; Reason = 'Only some servers are blocked on TCP/53, so the rule is specific to that server or its path, not to this host.' }
    }

    return [pscustomobject]@{ Scope = 'Unknown'; Confidence = 'Low'; Reason = 'Not enough comparative evidence to localise the block.' }
}

function Get-BlockClassification {
<#
    .SYNOPSIS
        The decision table. Returns the block type plus its evidence trail.
    .PARAMETER UdpResult
        Result of the UDP/53 control probe.
    .PARAMETER TcpResult
        Result of the TCP/53 probe under test.
    .PARAMETER ControlPortResult
        Optional bare TCP connect to a non-DNS port on the same server.
        If that port connects while 53 does not, the filter is port-based;
        this is what upgrades the confidence from Medium to High.
#>
    param(
        [Parameter(Mandatory)]$UdpResult,
        [Parameter(Mandatory)]$TcpResult,
        $ControlPortResult = $null,
        $ImpactResult = $null,
        [int]$GatewayRttMs = -1,
        [array]$LocalFirewallRules = @(),
        [Nullable[bool]]$AllTargetsBlocked = $null
    )

    $blockType = 'Indeterminate'
    $evidence  = New-Object 'System.Collections.Generic.List[string]'

    $evidence.Add("UDP/53=$($UdpResult.Outcome)$(if ($null -ne $UdpResult.ElapsedMs) { " in $($UdpResult.ElapsedMs)ms" })")
    $evidence.Add("TCP/53=$($TcpResult.Outcome) at phase $($TcpResult.Phase)$(if ($null -ne $TcpResult.ElapsedMs) { " in $($TcpResult.ElapsedMs)ms" })")
    if ($TcpResult.SocketError) { $evidence.Add("Winsock=$($TcpResult.SocketError)") }

    if ($TcpResult.Success) {
        $blockType = $(if ($UdpResult.Success) { 'None' } else { 'UdpBlockedTcpOk' })
    }
    elseif (-not $UdpResult.Success) {
        # Neither transport works: nothing here is evidence about TCP/53 alone.
        $blockType = 'DnsServerUnreachable'
    }
    else {
        # UDP fine, TCP not. Classify by the phase that failed.
        switch ($TcpResult.Phase) {
            'Connect' {
                switch ($TcpResult.Outcome) {
                    'Refused'            { $blockType = 'TcpRejected' }
                    'ConnectTimeout'     { $blockType = 'TcpSilentDrop' }
                    'HostUnreachable'    { $blockType = 'TcpUnreachable' }
                    'NetworkUnreachable' { $blockType = 'TcpUnreachable' }
                    'Reset'              { $blockType = 'TcpRejected' }
                    'LocallyDenied'      { $blockType = 'TcpRejected' }
                    default              { $blockType = 'Indeterminate' }
                }
            }
            'Send' {
                $blockType = $(if ($TcpResult.Outcome -eq 'Reset') { 'TcpResetAfterQuery' } else { 'TcpHandshakeThenNoData' })
            }
            'Receive' {
                switch ($TcpResult.Outcome) {
                    'ReadTimeout'           { $blockType = 'TcpHandshakeThenNoData' }
                    'Reset'                 { $blockType = 'TcpResetAfterQuery' }
                    'Aborted'               { $blockType = 'TcpResetAfterQuery' }
                    'ClosedWithoutAnswer'   { $blockType = 'TcpClosedWithoutAnswer' }
                    'TruncatedStream'       { $blockType = 'TcpClosedWithoutAnswer' }
                    'MalformedFraming'      { $blockType = 'TcpAnswerSuspect' }
                    'UnparseableResponse'   { $blockType = 'TcpAnswerSuspect' }
                    'TransactionIdMismatch' { $blockType = 'TcpAnswerSuspect' }
                    default                 { $blockType = 'Indeterminate' }
                }
            }
            default { $blockType = 'Indeterminate' }
        }
    }

    # The control port turns "TCP is broken" into "port 53 is filtered".
    $portSpecific = $null
    if ($null -ne $ControlPortResult) {
        $evidence.Add("Control TCP/$($ControlPortResult.Port)=$($ControlPortResult.Outcome)")
        if (-not $TcpResult.Success) {
            if ($ControlPortResult.Connected) {
                $portSpecific = $true
                $evidence.Add("TCP/$($ControlPortResult.Port) connects to the same host while TCP/53 does not, so the filter selects on port 53.")
            }
            else {
                $portSpecific = $false
                $evidence.Add("TCP/$($ControlPortResult.Port) also fails, so this host may be unreachable over TCP generally rather than filtered on port 53.")
            }
        }
    }

    $meta    = Get-BlockTypeMetadata -BlockType $blockType
    $blocked = ($script:NotABlock -notcontains $blockType)

    $confidence = 'Medium'
    if ($blockType -eq 'None') { $confidence = 'High' }
    elseif ($portSpecific -eq $true) { $confidence = 'High' }
    elseif ($portSpecific -eq $false) { $confidence = 'Low' }
    elseif ($blockType -eq 'Indeterminate') { $confidence = 'Low' }

    # Scope only means something for a target that is actually blocked.
    # Reporting "which device is filtering this" for a server that answered
    # normally -- or that never answered at all -- reads as a finding when it
    # is nothing of the sort.
    if (-not $blocked) {
        $reason = $(if ($blockType -eq 'None') { 'TCP/53 completed normally; there is no block to localise.' }
                    else { 'No transport answered, so there is no TCP/53 block to localise.' })
        $scope = [pscustomobject]@{ Scope = 'NotApplicable'; Confidence = 'High'; Reason = $reason }
    }
    else {
        $scope = Get-BlockScope -TcpResult $TcpResult -GatewayRttMs $GatewayRttMs `
                                -LocalFirewallRules $LocalFirewallRules -AllTargetsBlocked $AllTargetsBlocked
    }

    # Resolution impact is reported separately from the block type: a block
    # can be real and still harmless until something needs the TCP fallback.
    $impact = 'Unknown'
    if ($null -ne $ImpactResult) {
        $impact = $ImpactResult.Impact
        $evidence.Add("Fallback test: $($ImpactResult.Detail)")
    }
    elseif ($blockType -eq 'None') {
        $impact = 'None'
    }

    return [pscustomobject]@{
        BlockType      = $blockType
        Blocked        = $blocked
        Severity       = $meta.Severity
        Description    = $meta.Summary
        Advice         = $meta.Advice
        Confidence     = $confidence
        PortSpecific   = $portSpecific
        Scope          = $scope.Scope
        ScopeReason    = $scope.Reason
        ScopeConfidence= $scope.Confidence
        ResolutionImpact = $impact
        Evidence       = ($evidence -join ' | ')
    }
}
