#!/usr/bin/env python3
"""
One-shot diagnosis of TCP/53 blocking, printed as a report and saved to
a log file.

Where tcp53-watch.py answers "is it happening right now, and when did it
happen", this collects the slow checks the monitor loop skips: a port
matrix across every server, a traceroute toward the blocked ones, the
local packet-filter rule set, and the truncation test that shows whether
resolution actually fails.

Python 3 standard library only. This is the Linux counterpart of
Invoke-Tcp53Diagnose.ps1.

Example:
  ./tcp53-diagnose.py --log-directory ~/tcp53-logs
"""

import argparse
import os
import sys
from datetime import datetime

SCRIPT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_ROOT, 'lib'))

import block_classify                                        # noqa: E402
import host_context                                          # noqa: E402
import net_probe                                             # noqa: E402
import tcp53_config                                          # noqa: E402
from dns_codec import build_query                            # noqa: E402
from log_writer import write_line                            # noqa: E402


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Diagnose a TCP/53 block once, in depth.')
    parser.add_argument('--config', dest='config_path',
                        help='Path to the JSON configuration. Defaults to '
                             'config/tcp53.config.json in the repository.')
    parser.add_argument('--output-path',
                        help='Exact path to write the report to. Overrides '
                             '--log-directory and skips the interactive prompt.')
    parser.add_argument('--log-directory',
                        help='Directory to write the timestamped report into.')
    parser.add_argument('--skip-traceroute', action='store_true',
                        help='Skip the traceroute stage, the slowest part of the run.')
    return parser.parse_args(argv)


class Report(object):
    """Collects the report lines while printing them as they are produced."""

    def __init__(self):
        self.lines = []

    def add(self, text='', colour='Gray'):
        self.lines.append(text)
        write_line(text, colour)

    def save(self, path):
        # BOM, so the file opens as UTF-8 in a Windows editor too.
        with open(path, 'w', encoding='utf-8-sig') as handle:
            handle.write('\n'.join(self.lines) + '\n')


def resolve_output_path(args, config):
    """Asked up front, before any diagnostics run, so the operator is not
    surprised by the destination after the slow checks have finished."""
    if args.output_path:
        return os.path.abspath(os.path.expanduser(args.output_path))

    log_dir = args.log_directory
    if not log_dir:
        default_dir = tcp53_config.resolve_log_directory(config, SCRIPT_ROOT)
        if sys.stdin.isatty():
            try:
                log_dir = input('Log directory for the diagnosis report [%s]: '
                                % default_dir).strip()
            except EOFError:
                log_dir = ''
        log_dir = log_dir or default_dir

    log_dir = tcp53_config.resolve_log_directory(config, SCRIPT_ROOT, log_dir)
    if not os.path.isdir(log_dir):
        os.makedirs(log_dir)
    return os.path.join(log_dir, 'tcp53-diagnosis-%s.log'
                        % datetime.now().strftime('%Y%m%d-%H%M%S'))


def main(argv=None):
    args = parse_args(argv)
    config = tcp53_config.load_config(args.config_path)
    output_path = resolve_output_path(args, config)

    report = Report()
    report.add('=========================================================', 'Cyan')
    report.add('  TCP/53 BLOCK DIAGNOSIS', 'Cyan')
    ctx = host_context.host_network_context('8.8.8.8')
    report.add('  Generated %s on %s by %s'
               % (datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %z'),
                  ctx.host_name, ctx.user_name), 'Cyan')
    report.add('=========================================================', 'Cyan')
    report.add()

    # ------------------------------------------------------------ host
    report.add('--- 1. HOST AND PATH IDENTITY ---', 'White')
    report.add('  Interface      : %s (%s)' % (ctx.adapter_name, ctx.adapter_description))
    report.add('  Interface MAC  : %s' % ctx.adapter_mac)
    report.add('  Local IP       : %s/%s' % (ctx.local_ip, ctx.prefix_length))
    report.add('  Default gateway: %s' % ctx.gateway_ip)
    report.add('  Gateway MAC    : %s  [%s]' % (ctx.gateway_mac, ctx.gateway_mac_state))
    report.add('  Configured DNS : %s' % ctx.configured_dns)
    if ctx.is_wireless:
        report.add('  Wi-Fi SSID     : %s' % ctx.ssid)
        report.add('  Wi-Fi BSSID    : %s  (MAC of the access point in the path)' % ctx.bssid)
        report.add('  Signal         : %s%%' % ctx.signal_percent)
    report.add()

    # -------------------------------------------------------- firewall
    report.add('--- 2. LOCAL PACKET FILTER, PORT 53 ---', 'White')
    firewall = host_context.local_dns_firewall_rules()
    if firewall.rules:
        report.add('  %d local block rule(s) cover port 53:' % len(firewall.rules), 'Yellow')
        for rule in firewall.rules:
            report.add('    - %s' % rule.display_name, 'Yellow')
            report.add('      %s %s  local:%s  remote:%s'
                       % (rule.direction, rule.protocol, rule.local_port, rule.remote_port),
                       'Yellow')
        report.add('  => A rule on this machine covers port 53. Check it before looking upstream.',
                   'Yellow')
    elif firewall.readable:
        report.add('  No enabled local block rule covers port 53.')
        report.add('  => Nothing in the local packet filter explains a block found below.')
    else:
        report.add('  Local packet filter not readable: %s' % (firewall.note or 'permission denied'),
                   'Yellow')
        report.add('  => Re-run with sudo to rule the local host in or out.', 'Yellow')
    report.add()

    # --------------------------------------------------------- targets
    gateway_rtt_ms = host_context.gateway_rtt_ms(ctx.gateway_ip)
    targets = tcp53_config.resolve_targets(config, gateway_ip=ctx.gateway_ip)
    if not targets:
        raise SystemExit('No enabled targets to probe.')

    report.add('--- 3. TRANSPORT MATRIX ---', 'White')
    report.add('  Query: %s %s   Control port: TCP/%s'
               % (config['ProbeType'], config['ProbeName'], config['ControlPort']))
    report.add()
    report.add('  %-12s %-16s %-22s %-24s %s'
               % ('TARGET', 'SERVER', 'UDP/53', 'TCP/53', 'TCP/CTRL'))
    report.add('  ' + '-' * 92)

    findings = []
    for target in targets:
        query = build_query(config['ProbeName'], config['ProbeType'])
        udp = net_probe.probe_udp(target.server, query, timeout_ms=config['UdpTimeoutMs'])
        tcp = net_probe.probe_tcp(target.server, query,
                                  connect_timeout_ms=config['ConnectTimeoutMs'],
                                  read_timeout_ms=config['ReadTimeoutMs'])
        ctl = net_probe.tcp_port_reachable(target.server, config['ControlPort'],
                                           timeout_ms=config['ConnectTimeoutMs'])
        findings.append((target, udp, tcp, ctl))

        colour = 'Green' if tcp.success else ('Red' if udp.success else 'Yellow')
        report.add('  %-12s %-16s %-22s %-24s %s'
                   % (target.name, target.server,
                      '%s %sms' % (udp.outcome, udp.elapsed_ms),
                      '%s %sms' % (tcp.outcome, tcp.elapsed_ms),
                      ctl.outcome), colour)
    report.add()

    # -------------------------------------------------- classification
    # Only a target whose UDP control answered can say anything about TCP/53.
    comparable = [f for f in findings if f[1].success]
    blocked_count = sum(1 for f in comparable if not f[2].success)
    unreachable = sum(1 for f in findings if not f[1].success and not f[2].success)
    all_blocked = None
    if len(comparable) > 1 and blocked_count > 0:
        all_blocked = (blocked_count == len(comparable))

    report.add('--- 4. CLASSIFICATION AND IMPACT ---', 'White')
    any_real_block = False

    for target, udp, tcp, ctl in findings:
        impact = net_probe.resolution_impact_test(
            target.server, config['ImpactProbeName'], config['ImpactProbeType'],
            timeout_ms=config['UdpTimeoutMs'])

        cls = block_classify.classify(udp, tcp, control_port_result=ctl, impact_result=impact,
                                      gateway_rtt_ms=gateway_rtt_ms,
                                      local_firewall_rules=firewall.rules,
                                      all_targets_blocked=all_blocked)

        colour = {'High': 'Red', 'Medium': 'Yellow', 'Info': 'Green'}.get(cls.severity, 'Gray')
        if cls.blocked:
            any_real_block = True

        report.add('  [%s] %s' % (target.name, cls.block_type), colour)
        report.add('      %s' % cls.description, colour)
        report.add('      Severity   : %s   Confidence: %s' % (cls.severity, cls.confidence))
        report.add('      Scope      : %s (%s)' % (cls.scope, cls.scope_confidence))
        report.add('      Why        : %s' % cls.scope_reason)
        report.add('      Impact     : %s' % cls.resolution_impact)
        report.add('      Evidence   : %s' % cls.evidence)
        if cls.advice:
            report.add('      Next step  : %s' % cls.advice)
        report.add()

    # ------------------------------------------------------ traceroute
    if not args.skip_traceroute:
        blocked = [f for f in findings if not f[2].success and f[1].success]
        if blocked:
            report.add('--- 5. PATH TO THE BLOCKED SERVERS ---', 'White')
            report.add('  The hop where the trace stops answering is where to look next.')
            for target, _udp, _tcp, _ctl in blocked:
                report.add('  %s (%s):' % (target.name, target.server))
                path = host_context.first_hop_path(target.server)
                if not path.hops:
                    report.add('    (no hops returned%s)'
                               % ('; ' + path.note if path.note else ''))
                else:
                    for number, hop in enumerate(path.hops, start=1):
                        report.add('    %2d. %s' % (number, hop))
            report.add()

    # --------------------------------------------------------- verdict
    report.add('--- VERDICT ---', 'White')
    if any_real_block:
        report.add('  %d of %d server(s) answered over UDP/53 but not over TCP/53.'
                   % (blocked_count, len(comparable)), 'Red')
        report.add('  Names whose answer does not fit one UDP datagram need the TCP retry, so',
                   'Red')
        report.add('  they cannot be resolved through those servers. See the Impact line above.',
                   'Red')
    elif unreachable > 0:
        report.add('  No TCP/53-specific block found. Some servers answered on neither transport,',
                   'Yellow')
        report.add('  which says they serve no DNS or are unreachable, not that port 53 is '
                   'filtered.', 'Yellow')
    else:
        report.add('  TCP/53 completed on every server tested. No block found.', 'Green')
    report.add()

    report.save(output_path)
    write_line('Report saved to: %s' % output_path, 'Cyan')
    return 0


if __name__ == '__main__':
    sys.exit(main())
