#!/usr/bin/env python3
"""
Continuously watches TCP/53 for blocking and logs every block with the
time, the MAC addresses in the path, and the classified block type.

Each cycle, for every configured DNS server:

  1. a DNS transaction over UDP/53   -- the control
  2. the same transaction over TCP/53 -- the subject
  3. a bare TCP connect to a control port on the same host
  4. when TCP/53 fails, a truncation test that proves whether real name
     resolution is broken as a consequence

The pair of results is classified into a named block type
(TcpSilentDrop, TcpRejected, TcpResetAfterQuery, ...) and written to
JSONL, CSV and a text session log.

Python 3 standard library only. Nothing to install, no interpreter to
download beyond the python3 that ships with the distribution. This is
the Linux counterpart of Start-Tcp53Watch.ps1 and writes the same logs.

Examples:
  ./tcp53-watch.py
      Watch every configured server until Ctrl+C.

  ./tcp53-watch.py --once --target CampusDNS,GoogleDNS
      One pass over two servers, then exit.

  ./tcp53-watch.py --duration-minutes 480 --interval-seconds 30 --quiet
      An unattended eight-hour capture at half-minute resolution.
"""

import argparse
import os
import sys
import time
from datetime import datetime, timedelta

SCRIPT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_ROOT, 'lib'))

import block_classify                                        # noqa: E402
import host_context                                          # noqa: E402
import log_writer                                            # noqa: E402
import net_probe                                             # noqa: E402
import tcp53_config                                          # noqa: E402
from dns_codec import build_query                            # noqa: E402
from log_writer import write_line                            # noqa: E402


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description='Watch TCP/53 for blocking and log every block.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', dest='config_path',
                        help='Path to the JSON configuration. Defaults to '
                             'config/tcp53.config.json in the repository.')
    parser.add_argument('--interval-seconds', type=int, default=0,
                        help='Seconds between cycles while everything is healthy.')
    parser.add_argument('--duration-minutes', type=int, default=0,
                        help='Stop after this many minutes. 0 (the default) runs until Ctrl+C.')
    parser.add_argument('--once', action='store_true',
                        help='Run exactly one cycle and exit. Useful from cron or a timer.')
    parser.add_argument('--target', action='append',
                        help='Probe only the named targets. Repeatable, or a comma list.')
    parser.add_argument('--log-directory',
                        help='Where JSONL/CSV/session-log files get written. If omitted, '
                             'the script asks before probing starts. Pass this explicitly '
                             'to run unattended, since a timer has no console to prompt.')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress the per-sample console line; still writes all log files.')
    return parser.parse_args(argv)


def ask_log_directory(default_dir):
    """Asked up front, before any probing starts, so the operator never has
    to guess afterwards where the evidence landed. A non-interactive run
    (cron, systemd timer) has no console and simply takes the default."""
    if not sys.stdin.isatty():
        return default_dir
    try:
        answer = input('Log directory [%s]: ' % default_dir).strip()
    except EOFError:
        return default_dir
    return answer or default_dir


def probe_cycle(targets, config, log, firewall, gateway_rtt_ms, is_first_cycle):
    """One pass over every target. Returns True if any TCP/53 probe failed."""
    # Pass 1: gather raw evidence for every target before judging any of
    # them. Whether *all* targets are blocked is itself a classification
    # input, so no target can be classified in isolation.
    samples = []

    for target in targets:
        query = build_query(config['ProbeName'], config['ProbeType'])

        udp = net_probe.probe_udp(target.server, query, timeout_ms=config['UdpTimeoutMs'])
        tcp = net_probe.probe_tcp(target.server, query,
                                  connect_timeout_ms=config['ConnectTimeoutMs'],
                                  read_timeout_ms=config['ReadTimeoutMs'])

        control = None
        if not tcp.success and config.get('ControlPort', 0) > 0:
            control = net_probe.tcp_port_reachable(target.server, config['ControlPort'],
                                                   timeout_ms=config['ConnectTimeoutMs'])

        # The truncation test costs a second round trip, so it only runs
        # when there is something to prove: a failing TCP probe, or the
        # very first cycle to establish a baseline.
        impact = None
        if not tcp.success or is_first_cycle:
            impact = net_probe.resolution_impact_test(
                target.server, config['ImpactProbeName'], config['ImpactProbeType'],
                timeout_ms=config['UdpTimeoutMs'])

        samples.append((target, udp, tcp, control, impact))

    tcp_failures = sum(1 for s in samples if not s[2].success)
    all_blocked = None
    if len(samples) > 1 and tcp_failures > 0:
        all_blocked = (tcp_failures == len(samples))

    # Pass 2: classify, log, render.
    for target, udp, tcp, control, impact in samples:
        classification = block_classify.classify(
            udp, tcp, control_port_result=control, impact_result=impact,
            gateway_rtt_ms=gateway_rtt_ms, local_firewall_rules=firewall.rules,
            all_targets_blocked=all_blocked)

        event = log_writer.should_log(log, target.name, classification.block_type,
                                      classification.blocked)

        # Host context is resolved per target so the MAC recorded belongs
        # to the interface that actually carried this probe.
        ctx = host_context.host_network_context(target.server)

        record = log_writer.new_log_record(ctx, target, udp, tcp, classification,
                                           control_port_result=control,
                                           impact_result=impact,
                                           event=event or 'Sample')

        log_writer.write_console_sample(log, record)

        if event:
            log_writer.write_log_record(log, record)
            if event == 'BlockStarted':
                log_writer.write_session_text(
                    log, 'BLOCK STARTED on %s (%s): %s - %s'
                    % (target.name, target.server, classification.block_type,
                       classification.evidence))
            elif event == 'BlockCleared':
                log_writer.write_session_text(
                    log, 'BLOCK CLEARED on %s (%s): now %s'
                    % (target.name, target.server, classification.block_type))

    return tcp_failures > 0


def main(argv=None):
    args = parse_args(argv)
    config = tcp53_config.load_config(args.config_path)

    if args.interval_seconds > 0:
        config['IntervalSeconds'] = args.interval_seconds

    default_log_dir = tcp53_config.resolve_log_directory(config, SCRIPT_ROOT)
    log_dir = args.log_directory or ask_log_directory(default_log_dir)
    log_dir = tcp53_config.resolve_log_directory(config, SCRIPT_ROOT, log_dir)

    write_line('')
    write_line('=========================================================', 'Cyan')
    write_line('  TCP/53 Block Watch  -  Linux, Python standard library', 'Cyan')
    write_line('=========================================================', 'Cyan')

    write_line('Inspecting the local packet filter for port 53 block rules...', 'DarkGray')
    firewall = host_context.local_dns_firewall_rules()
    if firewall.rules:
        write_line('  Found %d local block rule(s) covering port 53:' % len(firewall.rules),
                   'Yellow')
        for rule in firewall.rules:
            write_line('    - %s [%s %s local:%s remote:%s]'
                       % (rule.display_name, rule.direction, rule.protocol,
                          rule.local_port, rule.remote_port), 'Yellow')
    elif firewall.readable:
        write_line('  No local block rule matches port 53.', 'DarkGray')
    else:
        # Not the same statement as "no rules": nftables and iptables need
        # CAP_NET_ADMIN to list anything, so an unprivileged run knows
        # nothing about the local filter and must not imply otherwise.
        write_line('  Local packet filter not readable (%s); re-run with sudo to include it.'
                   % (firewall.note or 'permission denied'), 'Yellow')

    # Gateway round-trip time: the yardstick for deciding whether a RST
    # came from inside the LAN or from somewhere further out.
    gateway_ip = host_context.default_gateway()
    gateway_rtt_ms = host_context.gateway_rtt_ms(gateway_ip)
    write_line('Default gateway: %s (RTT %s)'
               % (gateway_ip or 'unknown',
                  '%dms' % gateway_rtt_ms if gateway_rtt_ms >= 0 else 'n/a'), 'DarkGray')

    targets = tcp53_config.resolve_targets(
        config, gateway_ip=gateway_ip,
        only=tcp53_config.split_target_filter(args.target),
        warn=lambda message: write_line('WARNING: ' + message, 'Yellow'))
    if not targets:
        raise SystemExit('No enabled targets to probe.')

    log = log_writer.new_log_context(log_dir,
                                     log_success_every_n_cycles=config['LogSuccessEveryNCycles'],
                                     quiet=args.quiet)

    write_line('')
    write_line('Targets   : %s' % ', '.join('%s=%s' % (t.name, t.server) for t in targets))
    write_line('Probe     : %s %s   Impact probe: %s %s'
               % (config['ProbeType'], config['ProbeName'],
                  config['ImpactProbeType'], config['ImpactProbeName']))
    write_line('Interval  : %ss (drops to %ss while a block is active)'
               % (config['IntervalSeconds'], config['FastRetrySeconds']))
    write_line('Logs      : %s' % log.directory)
    write_line('')
    write_line('Press Ctrl+C to stop.', 'DarkGray')
    write_line('')

    deadline = None
    if args.duration_minutes > 0:
        deadline = datetime.now() + timedelta(minutes=args.duration_minutes)

    first_cycle = True
    last_block_seen = None

    try:
        while True:
            any_blocked = probe_cycle(targets, config, log, firewall, gateway_rtt_ms,
                                      first_cycle)
            first_cycle = False

            if args.once:
                break
            if deadline and datetime.now() >= deadline:
                break

            # Tighten the sampling rate while a block is active and hold it
            # after the block clears, so intermittent blocks are captured at
            # useful resolution.
            if any_blocked:
                last_block_seen = datetime.now()

            sleep_seconds = config['IntervalSeconds']
            if last_block_seen and \
                    (datetime.now() - last_block_seen).total_seconds() < config['FastRetryHoldSeconds']:
                sleep_seconds = config['FastRetrySeconds']

            for _ in range(int(sleep_seconds)):
                if deadline and datetime.now() >= deadline:
                    break
                time.sleep(1)
    except KeyboardInterrupt:
        write_line('')
        write_line('Stopped by the operator.', 'DarkGray')
    finally:
        log_writer.write_session_summary(log)

    return 0


if __name__ == '__main__':
    sys.exit(main())
