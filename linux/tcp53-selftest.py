#!/usr/bin/env python3
"""
Self-test for the Linux TCP/53 watch: verifies the DNS codec, the block
classifier, the /proc and /sys readers and the logging pipeline without
needing a real block, a network, or root.

A monitor for a rare fault is untestable in the field -- by the time the
block happens you need to already trust the tool. So the decision table
is exercised here against synthetic probe results, one case per block
type, the platform readers are run against captured fixtures, and the
records are written through the real logger so the on-disk shape is the
same one a genuine incident would produce.

Exits non-zero if any case fails, so it can gate a scheduled rollout.

Example:
  ./tcp53-selftest.py
"""

import argparse
import errno
import json
import os
import re
import sys
import tempfile
from datetime import datetime
from types import SimpleNamespace

SCRIPT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_ROOT, 'lib'))

import block_classify                                        # noqa: E402
import host_context                                          # noqa: E402
import log_writer                                            # noqa: E402
import net_probe                                             # noqa: E402
from dns_codec import build_query, parse_response            # noqa: E402
from log_writer import write_line                            # noqa: E402

PASSED = 0
FAILED = 0


def check(case, expected, actual):
    global PASSED, FAILED
    if str(expected) == str(actual):
        PASSED += 1
        write_line('  PASS  %-42s -> %s' % (case, actual), 'Green')
    else:
        FAILED += 1
        write_line('  FAIL  %-42s expected [%s] got [%s]' % (case, expected, actual), 'Red')


def fake_probe(protocol, success, phase, outcome, socket_error=None, elapsed_ms=100,
               response=None):
    return SimpleNamespace(
        protocol=protocol, server='203.0.113.53', port=53,
        success=success, phase=phase, outcome=outcome,
        socket_error=socket_error, socket_code=None,
        connect_ms=None, elapsed_ms=elapsed_ms, bytes_received=0,
        response=response, detail='synthetic')


GOOD_UDP = fake_probe('UDP', True, 'Receive', 'Answered', response=SimpleNamespace(
    valid=True, rcode_name='NOERROR', truncated=False, answer_count=1, transaction_id=1))
DEAD_UDP = fake_probe('UDP', False, 'Receive', 'ReadTimeout', 'ETIMEDOUT')


def test_dns_codec():
    write_line('')
    write_line('=== 1. DNS codec round-trip ===', 'Cyan')

    query = build_query('www.example.com', 'A', transaction_id=0x1234)
    check('query transaction id preserved', 4660, query.transaction_id)
    check('query header byte 0', 0x12, query.data[0])
    check('query header byte 1', 0x34, query.data[1])
    check('parsed id survives 16-bit assembly', 4660,
          parse_response(query.data).transaction_id)

    # A hand-built response: same id, QR=1, one A record of 93.184.216.34.
    body = bytearray()
    body += bytes([0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    body += query.data[12:]                       # echo the question
    body += bytes([0xC0, 0x0C])                   # name pointer to offset 12
    body += bytes([0x00, 0x01, 0x00, 0x01])       # TYPE A, CLASS IN
    body += bytes([0x00, 0x00, 0x01, 0x2C])       # TTL 300
    body += bytes([0x00, 0x04])                   # RDLENGTH 4
    body += bytes([93, 184, 216, 34])
    parsed = parse_response(bytes(body))

    check('response parses as valid', True, parsed.valid)
    check('response rcode', 'NOERROR', parsed.rcode_name)
    check('response answer count', 1, parsed.answer_count)
    check('compressed name decoded', 'www.example.com', parsed.answers[0].name)
    check('A record rdata decoded', '93.184.216.34', parsed.answers[0].data)
    check('TTL survives 32-bit assembly', 300, parsed.answers[0].ttl)

    # EDNS is what makes a server set TC on a large answer, so the OPT
    # record has to actually be in the additional section.
    edns = build_query('.', 'DNSKEY', transaction_id=1, enable_edns=True)
    check('EDNS query declares one additional', 1, (edns.data[10] << 8) | edns.data[11])
    # The OPT record is the last 11 bytes: root name, type, class,
    # extended rcode/version/flags, rdlength.
    check('EDNS OPT type is 41', 41, (edns.data[-10] << 8) | edns.data[-9])

    check('short buffer is data, not a crash', 'UNPARSEABLE',
          parse_response(b'\x00\x01').rcode_name)


def test_mac_normalisation():
    write_line('')
    write_line('=== 2. MAC normalisation ===', 'Cyan')
    check('dashed input round-trips', '40-B5-C1-A2-68-53',
          host_context.normalize_mac('40-B5-C1-A2-68-53'))
    check('bare hex is formatted', 'AA-BB-CC-DD-EE-FF',
          host_context.normalize_mac('aabbccddeeff'))
    check('colon form is normalised', '01-23-45-67-89-AB',
          host_context.normalize_mac('01:23:45:67:89:ab'))


def test_socket_outcomes():
    write_line('')
    write_line('=== 3. errno to outcome mapping ===', 'Cyan')
    check('refused connect', 'Refused',
          net_probe.resolve_socket_outcome('Connect', errno.ECONNREFUSED))
    check('timeout is phase-aware (connect)', 'ConnectTimeout',
          net_probe.resolve_socket_outcome('Connect', errno.ETIMEDOUT))
    check('timeout is phase-aware (receive)', 'ReadTimeout',
          net_probe.resolve_socket_outcome('Receive', errno.ETIMEDOUT))
    check('reset', 'Reset', net_probe.resolve_socket_outcome('Receive', errno.ECONNRESET))
    check('host unreachable', 'HostUnreachable',
          net_probe.resolve_socket_outcome('Connect', errno.EHOSTUNREACH))
    check('local denial', 'LocallyDenied',
          net_probe.resolve_socket_outcome('Connect', errno.EACCES))


def test_classification():
    write_line('')
    write_line('=== 4. Block classification decision table ===', 'Cyan')

    cases = [
        ('healthy TCP/53', GOOD_UDP,
         fake_probe('TCP', True, 'Receive', 'Answered', None, 20), 'None'),
        ('RST on connect', GOOD_UDP,
         fake_probe('TCP', False, 'Connect', 'Refused', 'ECONNREFUSED', 3), 'TcpRejected'),
        ('SYN dropped', GOOD_UDP,
         fake_probe('TCP', False, 'Connect', 'ConnectTimeout', 'ETIMEDOUT', 3000),
         'TcpSilentDrop'),
        ('ICMP unreachable', GOOD_UDP,
         fake_probe('TCP', False, 'Connect', 'HostUnreachable', 'EHOSTUNREACH', 40),
         'TcpUnreachable'),
        ('handshake then silence', GOOD_UDP,
         fake_probe('TCP', False, 'Receive', 'ReadTimeout', 'ETIMEDOUT', 4000),
         'TcpHandshakeThenNoData'),
        ('RST after query (DPI)', GOOD_UDP,
         fake_probe('TCP', False, 'Receive', 'Reset', 'ECONNRESET', 60),
         'TcpResetAfterQuery'),
        ('RST while sending the query', GOOD_UDP,
         fake_probe('TCP', False, 'Send', 'Reset', 'ECONNRESET', 45),
         'TcpResetAfterQuery'),
        ('clean close, no answer', GOOD_UDP,
         fake_probe('TCP', False, 'Receive', 'ClosedWithoutAnswer', None, 55),
         'TcpClosedWithoutAnswer'),
        ('reply id mismatch', GOOD_UDP,
         fake_probe('TCP', False, 'Receive', 'TransactionIdMismatch', None, 30),
         'TcpAnswerSuspect'),
        ('UDP filtered, TCP fine', DEAD_UDP,
         fake_probe('TCP', True, 'Receive', 'Answered', None, 25), 'UdpBlockedTcpOk'),
        ('both transports dead', DEAD_UDP,
         fake_probe('TCP', False, 'Connect', 'ConnectTimeout', 'ETIMEDOUT', 3000),
         'DnsServerUnreachable'),
    ]

    for case, udp, tcp, expected in cases:
        check(case, expected, block_classify.classify(udp, tcp).block_type)


def test_control_port_confidence():
    write_line('')
    write_line('=== 5. Confidence from the control port ===', 'Cyan')

    blocked = fake_probe('TCP', False, 'Connect', 'ConnectTimeout', 'ETIMEDOUT', 3000)
    open_port = SimpleNamespace(server='203.0.113.53', port=443, connected=True,
                                outcome='Connected', elapsed_ms=12)
    shut_port = SimpleNamespace(server='203.0.113.53', port=443, connected=False,
                                outcome='ConnectTimeout', elapsed_ms=3000)

    with_open = block_classify.classify(GOOD_UDP, blocked, control_port_result=open_port)
    check('control port open => port-specific', True, with_open.port_specific)
    check('control port open => high confidence', 'High', with_open.confidence)

    with_shut = block_classify.classify(GOOD_UDP, blocked, control_port_result=shut_port)
    check('control port shut => not port-specific', False, with_shut.port_specific)
    check('control port shut => low confidence', 'Low', with_shut.confidence)


def test_scope():
    write_line('')
    write_line('=== 6. Scope attribution ===', 'Cyan')

    blocked = fake_probe('TCP', False, 'Connect', 'ConnectTimeout', 'ETIMEDOUT', 3000)
    local_rule = [SimpleNamespace(display_name='iptables OUTPUT: -A OUTPUT -p tcp --dport 53 -j DROP',
                                  direction='Outbound', protocol='TCP',
                                  local_port='Any', remote_port='53', source='iptables')]

    check('local filter rule pins scope', 'LocalHost',
          block_classify.classify(GOOD_UDP, blocked, local_firewall_rules=local_rule).scope)
    check('all servers blocked => edge', 'NetworkEdge',
          block_classify.classify(GOOD_UDP, blocked, all_targets_blocked=True).scope)
    check('one server blocked => server', 'ServerOrPath',
          block_classify.classify(GOOD_UDP, blocked, all_targets_blocked=False).scope)

    refused_fast = fake_probe('TCP', False, 'Connect', 'Refused', 'ECONNREFUSED', 0)
    check('instant RST => local host', 'LocalHost',
          block_classify.classify(GOOD_UDP, refused_fast).scope)

    refused_gw = fake_probe('TCP', False, 'Connect', 'Refused', 'ECONNREFUSED', 3)
    check('RST at gateway RTT => first hop', 'FirstHop',
          block_classify.classify(GOOD_UDP, refused_gw, gateway_rtt_ms=2).scope)

    healthy = fake_probe('TCP', True, 'Receive', 'Answered', None, 20)
    check('healthy target has no scope', 'NotApplicable',
          block_classify.classify(GOOD_UDP, healthy).scope)


PROC_ROUTE_FIXTURE = (
    'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n'
    'wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n'
    'eth0\t00000000\tFE01A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n'
    'eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n'
)

PROC_ARP_FIXTURE = (
    'IP address       HW type     Flags       HW address            Mask     Device\n'
    '192.168.1.1      0x1         0x2         a0:b1:c2:d3:e4:f5     *        wlan0\n'
    '192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n'
)

IW_LINK_FIXTURE = (
    'Connected to a0:b1:c2:d3:e4:f5 (on wlan0)\n'
    '\tSSID: CampusWiFi\n'
    '\tfreq: 5180\n'
    '\tsignal: -55 dBm\n'
)

NFT_FIXTURE = (
    'table inet filter {\n'
    '\tchain output {\n'
    '\t\ttype filter hook output priority filter; policy accept;\n'
    '\t\tudp dport 5353 accept\n'
    '\t\ttcp dport { 53, 853 } counter packets 0 bytes 0 drop\n'
    '\t}\n'
    '}\n'
)

IPTABLES_FIXTURE = (
    '-P OUTPUT ACCEPT\n'
    '-A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT\n'
    '-A OUTPUT -p tcp -m tcp --dport 53 -j DROP\n'
    '-A INPUT -p tcp -m tcp --dport 50:60 -j REJECT --reject-with tcp-reset\n'
)

TRACEROUTE_FIXTURE = (
    'traceroute to 8.8.8.8 (8.8.8.8), 8 hops max, 60 byte packets\n'
    ' 1  192.168.1.1  1.204 ms  1.150 ms\n'
    ' 2  * * *\n'
    ' 3  140.120.254.1  4.881 ms\n'
)


def test_platform_readers():
    write_line('')
    write_line('=== 7. /proc, /sys and tool output readers ===', 'Cyan')

    defaults = host_context.default_routes(PROC_ROUTE_FIXTURE)
    check('default routes found', 2, len(defaults))
    # Lowest metric first: the route the kernel would actually pick.
    check('best default route by metric', 'eth0', defaults[0].interface)
    check('gateway decoded from little-endian hex', '192.168.1.254', defaults[0].gateway)

    arp = host_context.parse_proc_arp(PROC_ARP_FIXTURE)
    check('gateway MAC from arp table', 'A0-B1-C2-D3-E4-F5', arp['192.168.1.1'][0])
    check('completed arp entry', 'Reachable', arp['192.168.1.1'][1])
    check('all-zero arp entry ignored', False, '192.168.1.9' in arp)

    check('resolv.conf nameservers', '8.8.8.8,1.1.1.1',
          ','.join(host_context.parse_resolv_conf(
              '# comment\nnameserver 8.8.8.8\noptions edns0\nnameserver 1.1.1.1\n')))

    wifi = host_context.parse_iw_link(IW_LINK_FIXTURE)
    check('SSID parsed', 'CampusWiFi', wifi.ssid)
    check('BSSID parsed', 'A0-B1-C2-D3-E4-F5', wifi.bssid)
    check('signal converted to percent', 90, host_context.dbm_to_percent(wifi.signal_dbm))

    nft = host_context.parse_nft_ruleset(NFT_FIXTURE)
    check('nft set containing 53 matched', 1, len(nft))
    check('nft rule direction from hook', 'Outbound', nft[0].direction)

    ipt = host_context.parse_iptables_rules(IPTABLES_FIXTURE)
    check('iptables rules covering 53', 2, len(ipt))
    check('iptables port range covers 53', 'Inbound', ipt[1].direction)
    check('accept rule is not a block', True,
          all('ACCEPT' not in r.display_name for r in ipt))
    check('unrelated port is ignored', 0,
          len(host_context.parse_iptables_rules(
              '-A OUTPUT -p tcp -m tcp --dport 443 -j DROP\n')))

    hops = host_context.parse_traceroute(TRACEROUTE_FIXTURE)
    check('traceroute hops parsed', 3, len(hops))
    check('unanswered hop kept as a gap', '*', hops[1])


def test_logging_pipeline(log_directory=None):
    write_line('')
    write_line('=== 8. Logging pipeline ===', 'Cyan')

    if not log_directory:
        log_directory = os.path.join(tempfile.gettempdir(),
                                     'tcp53-selftest-' + datetime.now().strftime('%Y%m%d-%H%M%S'))

    log = log_writer.new_log_context(log_directory, log_success_every_n_cycles=0, quiet=True)
    ctx = host_context.host_network_context('8.8.8.8')
    target = SimpleNamespace(name='SelfTest', server='203.0.113.53', note='synthetic')

    blocked = fake_probe('TCP', False, 'Connect', 'ConnectTimeout', 'ETIMEDOUT', 3000)
    open_port = SimpleNamespace(server='203.0.113.53', port=443, connected=True,
                                outcome='Connected', elapsed_ms=12)

    cls = block_classify.classify(GOOD_UDP, blocked, control_port_result=open_port)
    event = log_writer.should_log(log, 'SelfTest', cls.block_type, cls.blocked)
    record = log_writer.new_log_record(ctx, target, GOOD_UDP, blocked, cls,
                                       control_port_result=open_port, event=event)
    log_writer.write_log_record(log, record)

    # 'Blocked' rather than 'Baseline': a first sample that is already
    # failing is labelled by its state, since "Baseline" is reserved for
    # a clean start.
    check('first sample is logged', 'Blocked', event)
    check('jsonl file written', True, os.path.exists(log.jsonl_path))
    check('csv file written', True, os.path.exists(log.csv_path))

    with open(log.jsonl_path, 'r', encoding='utf-8') as handle:
        read_back = json.loads(handle.readlines()[-1])
    check('logged block type', 'TcpSilentDrop', read_back['BlockType'])
    check('logged target', 'SelfTest', read_back['TargetName'])
    check('timestamp present', True, bool(read_back['Timestamp']))
    check('adapter MAC in canonical form', True,
          read_back['AdapterMac'] is None or
          bool(re.match(r'^([0-9A-F]{2}-){5}[0-9A-F]{2}$', read_back['AdapterMac'])))

    # A transition must always be recorded even when successes are sampled out.
    healthy = block_classify.classify(GOOD_UDP,
                                      fake_probe('TCP', True, 'Receive', 'Answered', None, 20))
    check('recovery is recorded as a transition', 'BlockCleared',
          log_writer.should_log(log, 'SelfTest', healthy.block_type, healthy.blocked))

    with open(log.csv_path, 'r', encoding='utf-8-sig') as handle:
        csv_lines = [line for line in handle.read().splitlines() if line]
    check('csv has header + 1 row', 2, len(csv_lines))
    check('csv keeps the Windows column order', log_writer.CSV_COLUMNS[0] + ',' +
          log_writer.CSV_COLUMNS[1], ','.join(csv_lines[0].split(',')[:2]))
    check('embedded commas are quoted', True, csv_lines[1].count('"') > 0)

    return log_directory


def main(argv=None):
    parser = argparse.ArgumentParser(description='Self-test the Linux TCP/53 watch.')
    parser.add_argument('--log-directory', help='Where the test log files are written.')
    args = parser.parse_args(argv)

    test_dns_codec()
    test_mac_normalisation()
    test_socket_outcomes()
    test_classification()
    test_control_port_confidence()
    test_scope()
    test_platform_readers()
    log_directory = test_logging_pipeline(args.log_directory)

    write_line('')
    write_line('=========================================================', 'Cyan')
    write_line('  Passed: %d    Failed: %d' % (PASSED, FAILED),
               'Green' if FAILED == 0 else 'Red')
    write_line('  Test logs: %s' % log_directory, 'DarkGray')
    write_line('=========================================================', 'Cyan')

    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
