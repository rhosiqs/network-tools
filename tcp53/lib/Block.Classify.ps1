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
#>

Set-StrictMode -Version Latest

$script:BlockTypeInfo = @{
    'None' = @{
        Severity = 'Info'
        Zh       = 'TCP 53 正常，可完成 DNS over TCP 交易。'
        Advice   = 'No action required.'
    }
    'TcpRejected' = @{
        Severity = 'High'
        Zh       = 'TCP 53 遭主動拒絕（收到 RST）；為明確的 reject 規則或該埠無服務。'
        Advice   = 'A device answered the SYN with a RST. Check for a REJECT-style rule on the local host, the gateway, or the DNS server itself.'
    }
    'TcpSilentDrop' = @{
        Severity = 'High'
        Zh       = 'TCP 53 遭靜默丟棄（SYN 無回應直到逾時）；典型的防火牆 DROP/DENY 規則。'
        Advice   = 'The SYN is being discarded with no reply. This is the classic firewall DROP. Compare against a control port to confirm the rule targets port 53.'
    }
    'TcpUnreachable' = @{
        Severity = 'High'
        Zh       = 'TCP 53 收到 ICMP unreachable；路由或路由器 ACL 阻擋。'
        Advice   = 'A router returned an ICMP unreachable. Look at routing and at router ACLs rather than at a stateful firewall.'
    }
    'TcpHandshakeThenNoData' = @{
        Severity = 'High'
        Zh       = 'TCP 三向交握成功但查詢無回應；中間設備接手連線後丟棄內容。'
        Advice   = 'The handshake completed with something, but the DNS query got no reply. That pattern means a transparent proxy or DPI accepted the connection on the server behalf and then dropped the payload.'
    }
    'TcpResetAfterQuery' = @{
        Severity = 'High'
        Zh       = '送出 DNS 查詢後連線被 RST；DPI 依封包內容阻擋 DNS over TCP。'
        Advice   = 'The connection survived until the DNS query was sent, then was reset. The device is inspecting payload, not just port numbers.'
    }
    'TcpClosedWithoutAnswer' = @{
        Severity = 'Medium'
        Zh       = '連線被對方正常關閉但未回應查詢；可能是代理伺服器或該伺服器未提供 TCP DNS。'
        Advice   = 'A clean FIN with no answer. Either a proxy terminated the session or this server genuinely does not serve DNS over TCP; test a second server to tell them apart.'
    }
    'TcpAnswerSuspect' = @{
        Severity = 'High'
        Zh       = 'TCP 53 有回應但內容不符（ID 不符或無法解析）；疑似 DNS 攔截/竄改。'
        Advice   = 'A reply came back that does not match the query we sent. Treat this as interception until proven otherwise.'
    }
    'UdpBlockedTcpOk' = @{
        Severity = 'Medium'
        Zh       = 'UDP 53 不通但 TCP 53 正常；與本專案假設相反，通常是 UDP 過濾或伺服器僅開放 TCP。'
        Advice   = 'The inverse of the expected pattern. Check for UDP filtering; some captive networks force DNS over TCP.'
    }
    'DnsServerUnreachable' = @{
        Severity = 'High'
        Zh       = 'UDP 與 TCP 皆不通；問題不限於 TCP 53，應先確認連線與伺服器本身。'
        Advice   = 'Both transports failed, so this is not a TCP/53-specific block. Verify link, route and that the server is alive before drawing conclusions.'
    }
    'Indeterminate' = @{
        Severity = 'Low'
        Zh       = '證據不足以判定阻擋型態。'
        Advice   = 'Not enough signal to classify. Re-run with a longer timeout or against another server.'
    }
}

function Get-BlockTypeMetadata {
    param([string]$BlockType)
    if ($script:BlockTypeInfo.ContainsKey($BlockType)) { return $script:BlockTypeInfo[$BlockType] }
    return @{ Severity = 'Low'; Zh = $BlockType; Advice = '' }
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

    $meta = Get-BlockTypeMetadata -BlockType $blockType

    $confidence = 'Medium'
    if ($blockType -eq 'None') { $confidence = 'High' }
    elseif ($portSpecific -eq $true) { $confidence = 'High' }
    elseif ($portSpecific -eq $false) { $confidence = 'Low' }
    elseif ($blockType -eq 'Indeterminate') { $confidence = 'Low' }

    # Scope only means something for a target that is actually blocked.
    # Reporting "which device is filtering this" for a healthy server reads
    # as a finding when it is nothing of the sort.
    if ($blockType -eq 'None') {
        $scope = [pscustomobject]@{ Scope = 'NotApplicable'; Confidence = 'High'; Reason = 'TCP/53 completed normally; there is no block to localise.' }
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
        Blocked        = ($blockType -ne 'None')
        Severity       = $meta.Severity
        Description    = $meta.Zh
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
