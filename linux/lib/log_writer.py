"""
log_writer.py
------------------------------------------------------------------
Three sinks, because three different readers need this data:

  *.jsonl  one JSON object per line, every field, nothing flattened.
           Append-only, so a crash mid-write costs one line, not the
           file. This is the forensic record.
  *.csv    a fixed column set with a UTF-8 BOM and CRLF endings so
           Excel opens it without an import wizard. This is what gets
           mailed to a network administrator.
  console  colour-coded live view.

Write policy matters as much as format. A monitor that logs every
healthy poll buries the six lines that matter under a hundred thousand
that do not, so successes are sampled and failures and state
transitions are always written. See should_log.

Field names, column order and file names are identical to the
PowerShell writer's: one day of Windows samples and one day of Linux
samples concatenate into a single sheet.
"""

import json
import os
import sys
from datetime import datetime, timezone

CSV_COLUMNS = [
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
    'Description', 'Evidence',
]

# ANSI equivalents of the console colours the PowerShell version uses.
_COLOURS = {
    'Red': '\033[31m', 'Yellow': '\033[33m', 'Green': '\033[32m',
    'Cyan': '\033[36m', 'White': '\033[97m', 'Gray': '\033[37m',
    'DarkGray': '\033[90m',
}
_RESET = '\033[0m'


def colour_enabled(stream=None):
    """Colour only for an interactive terminal that has not opted out."""
    stream = stream or sys.stdout
    if os.environ.get('NO_COLOR') is not None:
        return False
    if os.environ.get('TERM') == 'dumb':
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def write_line(text='', colour='Gray', newline=True, stream=None):
    stream = stream or sys.stdout
    if colour_enabled(stream) and colour in _COLOURS:
        text = _COLOURS[colour] + text + _RESET
    stream.write(text + ('\n' if newline else ''))
    stream.flush()


def _local_timestamp(now):
    """'2026-08-24 09:15:03.417 +08:00', the shape the CSV already uses."""
    offset = now.strftime('%z')
    if offset:
        offset = '%s:%s' % (offset[:3], offset[3:])
    return '%s.%03d %s' % (now.strftime('%Y-%m-%d %H:%M:%S'),
                           now.microsecond // 1000, offset)


def new_log_context(directory, session_name='tcp53', log_success_every_n_cycles=30,
                    quiet=False):
    """Opens a logging session and returns the handle passed to every write."""
    directory = os.path.abspath(os.path.expanduser(directory))
    if not os.path.isdir(directory):
        os.makedirs(directory)

    now = datetime.now()
    stamp = now.strftime('%Y%m%d')
    session = now.strftime('%Y%m%d-%H%M%S')

    class LogContext(object):
        pass

    ctx = LogContext()
    ctx.directory = directory
    ctx.jsonl_path = os.path.join(directory, '%s-events-%s.jsonl' % (session_name, stamp))
    ctx.csv_path = os.path.join(directory, '%s-events-%s.csv' % (session_name, stamp))
    ctx.text_path = os.path.join(directory, '%s-session-%s.log' % (session_name, session))
    ctx.session_id = session
    ctx.quiet = bool(quiet)
    ctx.success_interval = int(log_success_every_n_cycles)
    ctx.last_block_type = {}
    ctx.cycle_count = {}
    ctx.counters = {}

    if not os.path.exists(ctx.csv_path):
        # BOM keeps Excel from mangling UTF-8 on a zh-TW system.
        with open(ctx.csv_path, 'w', encoding='utf-8-sig', newline='') as handle:
            handle.write(','.join(CSV_COLUMNS) + '\r\n')

    import socket as _socket
    write_session_text(ctx, '==== TCP/53 block watch session %s started on %s ===='
                       % (session, _socket.gethostname()))
    return ctx


def write_session_text(log, text):
    try:
        with open(log.text_path, 'a', encoding='utf-8') as handle:
            handle.write('[%s] %s\n' % (datetime.now().strftime('%H:%M:%S'), text))
    except OSError:
        pass


def csv_field(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        value = 'True' if value else 'False'
    text = str(value)
    if any(ch in text for ch in ',"\r\n'):
        return '"' + text.replace('"', '""') + '"'
    return text


def new_log_record(host_context, target, udp_result, tcp_result, classification,
                   control_port_result=None, impact_result=None, event='Sample'):
    """Flattens one probe cycle into the single record shape used by all sinks."""
    now = datetime.now().astimezone()
    utc = now.astimezone(timezone.utc)

    return {
        'Timestamp': _local_timestamp(now),
        'TimestampUtc': '%s.%03dZ' % (utc.strftime('%Y-%m-%dT%H:%M:%S'),
                                      utc.microsecond // 1000),
        'Event': event,

        'HostName': host_context.host_name,
        'UserName': host_context.user_name,

        'AdapterName': host_context.adapter_name,
        'AdapterDescription': host_context.adapter_description,
        'AdapterMac': host_context.adapter_mac,
        'MediaType': host_context.media_type,
        'InterfaceIndex': host_context.interface_index,
        'LocalIp': host_context.local_ip,
        'GatewayIp': host_context.gateway_ip,
        'GatewayMac': host_context.gateway_mac,
        'GatewayMacState': host_context.gateway_mac_state,
        'ConfiguredDns': host_context.configured_dns,
        'Ssid': host_context.ssid,
        'Bssid': host_context.bssid,
        'SignalPercent': host_context.signal_percent,

        'TargetName': target.name,
        'TargetIp': target.server,
        'Port': tcp_result.port,

        'BlockType': classification.block_type,
        'Blocked': classification.blocked,
        'Severity': classification.severity,
        'Confidence': classification.confidence,
        'Scope': classification.scope,
        'ScopeReason': classification.scope_reason,
        'Description': classification.description,
        'Advice': classification.advice,
        'Evidence': classification.evidence,
        'PortSpecific': classification.port_specific,

        'TcpPhase': tcp_result.phase,
        'TcpOutcome': tcp_result.outcome,
        'TcpSocketError': tcp_result.socket_error,
        'TcpConnectMs': tcp_result.connect_ms,
        'TcpElapsedMs': tcp_result.elapsed_ms,
        'TcpBytes': tcp_result.bytes_received,
        'TcpDetail': tcp_result.detail,

        'UdpOutcome': udp_result.outcome,
        'UdpElapsedMs': udp_result.elapsed_ms,
        'UdpRcode': udp_result.response.rcode_name if udp_result.response else None,
        'UdpTruncated': udp_result.response.truncated if udp_result.response else None,

        'ControlPort': control_port_result.port if control_port_result else None,
        'ControlPortOutcome': control_port_result.outcome if control_port_result else None,

        'ResolutionImpact': classification.resolution_impact,
        'TruncationSeen': impact_result.truncation_seen if impact_result else None,
        'TcpFallbackOk': impact_result.tcp_fallback_ok if impact_result else None,
        'ImpactDetail': impact_result.detail if impact_result else None,
    }


def should_log(log, target_key, block_type, blocked):
    """Decides whether this sample earns a line on disk.

    Always: anything blocked, and any change of block type for a target
    (the transitions are the story). Otherwise: one healthy sample every
    N cycles, so the file still proves the link was up in between.

    Returns the event label to record, or None to skip.
    """
    previous = log.last_block_type.get(target_key)
    log.last_block_type[target_key] = block_type

    log.cycle_count[target_key] = log.cycle_count.get(target_key, 0) + 1

    key = '%s/%s' % (target_key, block_type)
    log.counters[key] = log.counters.get(key, 0) + 1

    if previous is not None and previous != block_type:
        return 'BlockStarted' if blocked else 'BlockCleared'
    if blocked:
        return 'Blocked'
    if previous is None:
        return 'Baseline'
    if log.success_interval > 0 and (log.cycle_count[target_key] % log.success_interval) == 0:
        return 'Heartbeat'
    return None


def write_log_record(log, record):
    try:
        with open(log.jsonl_path, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + '\n')
    except OSError as exc:
        write_line('JSONL write failed: %s' % exc, 'Yellow')

    try:
        fields = [csv_field(record.get(column)) for column in CSV_COLUMNS]
        with open(log.csv_path, 'a', encoding='utf-8', newline='') as handle:
            handle.write(','.join(fields) + '\r\n')
    except OSError as exc:
        write_line('CSV write failed: %s' % exc, 'Yellow')


def write_console_sample(log, record, force=False):
    """Renders one sample as a single scannable line."""
    if log.quiet and not force:
        return

    colour = {'High': 'Red', 'Medium': 'Yellow', 'Info': 'Green'}.get(record['Severity'], 'Gray')

    timing = ('%5dms' % record['TcpElapsedMs']) if record['TcpElapsedMs'] is not None else '     -'

    write_line('[%s] ' % datetime.now().strftime('%H:%M:%S'), 'DarkGray', newline=False)
    write_line('%-14s ' % record['TargetName'], 'White', newline=False)
    write_line('%-24s ' % record['BlockType'], colour, newline=False)
    write_line('tcp:%s/%s  udp:%s  %s' % (record['TcpPhase'], record['TcpOutcome'],
                                          record['UdpOutcome'], timing), 'DarkGray')

    if record['Blocked']:
        write_line('            -> %s' % record['Description'], colour)
        if record['ResolutionImpact'] == 'ResolutionBroken':
            write_line('            -> DNS resolution is BROKEN for answers that need '
                       'the TCP fallback.', 'Red')
        write_line('            -> MAC %s / GW %s (%s)  scope=%s'
                   % (record['AdapterMac'], record['GatewayIp'], record['GatewayMac'],
                      record['Scope']), 'DarkGray')


def write_session_summary(log):
    lines = ['', '==================== SESSION SUMMARY ====================']

    if not log.counters:
        lines.append('  No samples were taken.')
    else:
        for key in sorted(log.counters):
            lines.append('  %-46s %6d sample(s)' % (key, log.counters[key]))

    lines.extend([
        '',
        '  JSONL : %s' % log.jsonl_path,
        '  CSV   : %s' % log.csv_path,
        '  Text  : %s' % log.text_path,
        '=========================================================',
    ])

    for line in lines:
        write_line(line, 'Cyan')
        write_session_text(log, line)
