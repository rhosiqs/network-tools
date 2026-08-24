"""
block_classify.py
------------------------------------------------------------------
Turns a pair of raw probe results (UDP/53 + TCP/53) into a named block
type, a confidence, and a guess at which device is responsible.

The whole design rests on one idea: UDP/53 is the control. DNS lives on
UDP, so if UDP answers normally while TCP does not, the link, the route
and the server are all fine and the difference is a rule that names the
TCP protocol. Everything below is the elaboration of that comparison
plus the errno evidence for *how* TCP died.

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

The tokens and the wording are the same as the PowerShell classifier's:
a log line means the same thing whichever platform wrote it.
"""

from types import SimpleNamespace

BLOCK_TYPE_INFO = {
    'None': {
        'severity': 'Info',
        'zh': 'TCP 53 正常，可完成 DNS over TCP 交易。',
        'advice': 'No action required.',
    },
    'TcpRejected': {
        'severity': 'High',
        'zh': 'TCP 53 遭主動拒絕（收到 RST）；為明確的 reject 規則或該埠無服務。',
        'advice': 'A device answered the SYN with a RST. Check for a REJECT-style rule on the local host, the gateway, or the DNS server itself.',
    },
    'TcpSilentDrop': {
        'severity': 'High',
        'zh': 'TCP 53 遭靜默丟棄（SYN 無回應直到逾時）；典型的防火牆 DROP/DENY 規則。',
        'advice': 'The SYN is being discarded with no reply. This is the classic firewall DROP. Compare against a control port to confirm the rule targets port 53.',
    },
    'TcpUnreachable': {
        'severity': 'High',
        'zh': 'TCP 53 收到 ICMP unreachable；路由或路由器 ACL 阻擋。',
        'advice': 'A router returned an ICMP unreachable. Look at routing and at router ACLs rather than at a stateful firewall.',
    },
    'TcpHandshakeThenNoData': {
        'severity': 'High',
        'zh': 'TCP 三向交握成功但查詢無回應；中間設備接手連線後丟棄內容。',
        'advice': 'The handshake completed with something, but the DNS query got no reply. That pattern means a transparent proxy or DPI accepted the connection on the server behalf and then dropped the payload.',
    },
    'TcpResetAfterQuery': {
        'severity': 'High',
        'zh': '送出 DNS 查詢後連線被 RST；DPI 依封包內容阻擋 DNS over TCP。',
        'advice': 'The connection survived until the DNS query was sent, then was reset. The device is inspecting payload, not just port numbers.',
    },
    'TcpClosedWithoutAnswer': {
        'severity': 'Medium',
        'zh': '連線被對方正常關閉但未回應查詢；可能是代理伺服器或該伺服器未提供 TCP DNS。',
        'advice': 'A clean FIN with no answer. Either a proxy terminated the session or this server genuinely does not serve DNS over TCP; test a second server to tell them apart.',
    },
    'TcpAnswerSuspect': {
        'severity': 'High',
        'zh': 'TCP 53 有回應但內容不符（ID 不符或無法解析）；疑似 DNS 攔截/竄改。',
        'advice': 'A reply came back that does not match the query we sent. Treat this as interception until proven otherwise.',
    },
    'UdpBlockedTcpOk': {
        'severity': 'Medium',
        'zh': 'UDP 53 不通但 TCP 53 正常；與本專案假設相反，通常是 UDP 過濾或伺服器僅開放 TCP。',
        'advice': 'The inverse of the expected pattern. Check for UDP filtering; some captive networks force DNS over TCP.',
    },
    'DnsServerUnreachable': {
        'severity': 'High',
        'zh': 'UDP 與 TCP 皆不通；問題不限於 TCP 53，應先確認連線與伺服器本身。',
        'advice': 'Both transports failed, so this is not a TCP/53-specific block. Verify link, route and that the server is alive before drawing conclusions.',
    },
    'Indeterminate': {
        'severity': 'Low',
        'zh': '證據不足以判定阻擋型態。',
        'advice': 'Not enough signal to classify. Re-run with a longer timeout or against another server.',
    },
}

_CONNECT_PHASE = {
    'Refused': 'TcpRejected',
    'ConnectTimeout': 'TcpSilentDrop',
    'HostUnreachable': 'TcpUnreachable',
    'NetworkUnreachable': 'TcpUnreachable',
    'Reset': 'TcpRejected',
    'LocallyDenied': 'TcpRejected',
}

_RECEIVE_PHASE = {
    'ReadTimeout': 'TcpHandshakeThenNoData',
    'Reset': 'TcpResetAfterQuery',
    'Aborted': 'TcpResetAfterQuery',
    'ClosedWithoutAnswer': 'TcpClosedWithoutAnswer',
    'TruncatedStream': 'TcpClosedWithoutAnswer',
    'MalformedFraming': 'TcpAnswerSuspect',
    'UnparseableResponse': 'TcpAnswerSuspect',
    'TransactionIdMismatch': 'TcpAnswerSuspect',
}


def block_type_metadata(block_type):
    return BLOCK_TYPE_INFO.get(block_type,
                               {'severity': 'Low', 'zh': block_type, 'advice': ''})


def block_scope(tcp_result, gateway_rtt_ms=-1, local_firewall_rules=None,
                all_targets_blocked=None):
    """Narrows down *where* the rule lives, from the shape of the evidence.

    Three independent signals are combined:
      - a matching local packet-filter rule pins it to this host;
      - a refusal returned faster than the round trip to the gateway
        cannot have come from beyond the gateway;
      - whether every server is blocked or only one separates a
        network-wide policy from a server-side setting.
    """
    rules = local_firewall_rules or []

    if rules:
        names = '; '.join(r.display_name for r in rules)
        return SimpleNamespace(
            scope='LocalHost', confidence='High',
            reason='A local packet-filter rule covering port 53 is active: %s' % names)

    if tcp_result.outcome == 'LocallyDenied':
        return SimpleNamespace(scope='LocalHost', confidence='High',
                               reason='The local socket layer denied the connection outright.')

    if tcp_result.outcome == 'Refused' and tcp_result.elapsed_ms is not None \
            and tcp_result.elapsed_ms < 2:
        return SimpleNamespace(
            scope='LocalHost', confidence='Medium',
            reason='The RST came back in %dms, too fast to have travelled off this machine.'
                   % tcp_result.elapsed_ms)

    if tcp_result.outcome == 'Refused' and gateway_rtt_ms >= 0 \
            and tcp_result.elapsed_ms is not None \
            and tcp_result.elapsed_ms <= gateway_rtt_ms + 2:
        return SimpleNamespace(
            scope='FirstHop', confidence='Medium',
            reason='The RST arrived in %dms against a %dms gateway RTT, so it originated '
                   'at or before the gateway.' % (tcp_result.elapsed_ms, gateway_rtt_ms))

    if all_targets_blocked is True:
        return SimpleNamespace(
            scope='NetworkEdge', confidence='Medium',
            reason='Every DNS server tested is blocked on TCP/53, which points at a '
                   'network-wide egress policy rather than any one server.')

    if all_targets_blocked is False:
        return SimpleNamespace(
            scope='ServerOrPath', confidence='Medium',
            reason='Only some servers are blocked on TCP/53, so the rule is specific to '
                   'that server or its path, not to this host.')

    return SimpleNamespace(scope='Unknown', confidence='Low',
                           reason='Not enough comparative evidence to localise the block.')


def classify(udp_result, tcp_result, control_port_result=None, impact_result=None,
             gateway_rtt_ms=-1, local_firewall_rules=None, all_targets_blocked=None):
    """The decision table. Returns the block type plus its evidence trail.

    control_port_result is an optional bare TCP connect to a non-DNS port
    on the same server. If that port connects while 53 does not, the
    filter is port-based; this is what upgrades the confidence from
    Medium to High.
    """
    block_type = 'Indeterminate'
    evidence = []

    evidence.append('UDP/53=%s%s' % (
        udp_result.outcome,
        ' in %dms' % udp_result.elapsed_ms if udp_result.elapsed_ms is not None else ''))
    evidence.append('TCP/53=%s at phase %s%s' % (
        tcp_result.outcome, tcp_result.phase,
        ' in %dms' % tcp_result.elapsed_ms if tcp_result.elapsed_ms is not None else ''))
    if tcp_result.socket_error:
        evidence.append('errno=%s' % tcp_result.socket_error)

    if tcp_result.success:
        block_type = 'None' if udp_result.success else 'UdpBlockedTcpOk'
    elif not udp_result.success:
        # Neither transport works: nothing here is evidence about TCP/53 alone.
        block_type = 'DnsServerUnreachable'
    else:
        # UDP fine, TCP not. Classify by the phase that failed.
        if tcp_result.phase == 'Connect':
            block_type = _CONNECT_PHASE.get(tcp_result.outcome, 'Indeterminate')
        elif tcp_result.phase == 'Send':
            block_type = ('TcpResetAfterQuery' if tcp_result.outcome == 'Reset'
                          else 'TcpHandshakeThenNoData')
        elif tcp_result.phase == 'Receive':
            block_type = _RECEIVE_PHASE.get(tcp_result.outcome, 'Indeterminate')

    # The control port turns "TCP is broken" into "port 53 is filtered".
    port_specific = None
    if control_port_result is not None:
        evidence.append('Control TCP/%d=%s' % (control_port_result.port,
                                               control_port_result.outcome))
        if not tcp_result.success:
            if control_port_result.connected:
                port_specific = True
                evidence.append('TCP/%d connects to the same host while TCP/53 does not, '
                                'so the filter selects on port 53.' % control_port_result.port)
            else:
                port_specific = False
                evidence.append('TCP/%d also fails, so this host may be unreachable over '
                                'TCP generally rather than filtered on port 53.'
                                % control_port_result.port)

    meta = block_type_metadata(block_type)

    confidence = 'Medium'
    if block_type == 'None':
        confidence = 'High'
    elif port_specific is True:
        confidence = 'High'
    elif port_specific is False:
        confidence = 'Low'
    elif block_type == 'Indeterminate':
        confidence = 'Low'

    # Scope only means something for a target that is actually blocked.
    # Reporting "which device is filtering this" for a healthy server
    # reads as a finding when it is nothing of the sort.
    if block_type == 'None':
        scope = SimpleNamespace(scope='NotApplicable', confidence='High',
                                reason='TCP/53 completed normally; there is no block to localise.')
    else:
        scope = block_scope(tcp_result, gateway_rtt_ms=gateway_rtt_ms,
                            local_firewall_rules=local_firewall_rules,
                            all_targets_blocked=all_targets_blocked)

    # Resolution impact is reported separately from the block type: a
    # block can be real and still harmless until something needs the TCP
    # fallback.
    impact = 'Unknown'
    if impact_result is not None:
        impact = impact_result.impact
        evidence.append('Fallback test: %s' % impact_result.detail)
    elif block_type == 'None':
        impact = 'None'

    return SimpleNamespace(
        block_type=block_type,
        blocked=(block_type != 'None'),
        severity=meta['severity'],
        description=meta['zh'],
        advice=meta['advice'],
        confidence=confidence,
        port_specific=port_specific,
        scope=scope.scope,
        scope_reason=scope.reason,
        scope_confidence=scope.confidence,
        resolution_impact=impact,
        evidence=' | '.join(evidence),
    )
