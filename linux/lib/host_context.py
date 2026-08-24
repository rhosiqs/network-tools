"""
host_context.py
------------------------------------------------------------------
Collects the identity of *this machine on this network at this moment*
so that a logged block can be attributed to a place, not just a time.

The MAC addresses are the point of this file. An IP address is leased
and rotates; the NIC MAC identifies the client that was blocked and the
gateway MAC (plus the Wi-Fi BSSID) identifies the specific piece of
hardware that was in the path when the block happened. That is what
lets a network admin find the device holding the rule.

Everything is read from /proc, /sys and ioctl first, so the tool works
on a minimal system with no iproute2, no iw and no ping binary. External
commands are only ever a second opinion, and every lookup degrades to
None: a missing field must never abort a monitoring run.
"""

import fcntl
import os
import re
import socket
import struct
import subprocess
import time
from types import SimpleNamespace

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B

SYS_NET = '/sys/class/net'
PROC_ROUTE = '/proc/net/route'
PROC_ARP = '/proc/net/arp'
RESOLV_CONF = '/etc/resolv.conf'
SYSTEMD_RESOLV_CONF = '/run/systemd/resolve/resolv.conf'


# ---------------------------------------------------------------- utils

def _read_text(path):
    try:
        with open(path, 'r', errors='replace') as handle:
            return handle.read()
    except OSError:
        return None


def _run(argv, timeout=10):
    """Runs a helper binary, or returns None when it is absent or fails.

    Nothing in this module may depend on the result: these are all
    optional enrichments over what /proc and /sys already gave us.
    """
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return SimpleNamespace(
        code=proc.returncode,
        out=proc.stdout.decode('utf-8', 'replace'),
        err=proc.stderr.decode('utf-8', 'replace'),
    )


def normalize_mac(raw):
    """Renders any MAC spelling as AA-BB-CC-DD-EE-FF.

    Linux writes colons, the logs and the Windows port write dashes; one
    spelling in the log file means one grep finds every appearance of a
    device across both platforms.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    hexdigits = re.sub(r'[^0-9A-Fa-f]', '', text).upper()
    if len(hexdigits) != 12:
        return text.upper()
    return '-'.join(hexdigits[i:i + 2] for i in range(0, 12, 2))


# --------------------------------------------------------- /proc parsing

def _hex_le_to_ip(value):
    """/proc/net/route stores addresses as little-endian hex words."""
    try:
        return socket.inet_ntoa(struct.pack('<L', int(value, 16)))
    except (ValueError, struct.error):
        return None


def parse_proc_route(text):
    """Parses /proc/net/route into route records, default routes first."""
    routes = []
    if not text:
        return routes

    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        routes.append(SimpleNamespace(
            interface=fields[0],
            destination=_hex_le_to_ip(fields[1]),
            gateway=_hex_le_to_ip(fields[2]),
            flags=int(fields[3], 16),
            metric=int(fields[6]),
            mask=_hex_le_to_ip(fields[7]),
        ))
    return routes


def default_routes(text):
    """The default routes, best (lowest) metric first."""
    defaults = [r for r in parse_proc_route(text)
                if r.destination == '0.0.0.0' and r.gateway and r.gateway != '0.0.0.0']
    return sorted(defaults, key=lambda r: r.metric)


def parse_proc_arp(text):
    """Parses /proc/net/arp into {ip: (mac, state)}.

    Flag 0x2 is ATF_COM, a completed entry: the MAC was actually learned
    rather than left over as an incomplete probe.
    """
    table = {}
    if not text:
        return table

    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        ip, flags, mac = fields[0], fields[2], fields[3]
        if mac == '00:00:00:00:00:00':
            continue
        try:
            complete = bool(int(flags, 16) & 0x2)
        except ValueError:
            complete = False
        table[ip] = (normalize_mac(mac), 'Reachable' if complete else 'Incomplete')
    return table


def parse_resolv_conf(text):
    """Returns the nameserver addresses listed in a resolv.conf."""
    servers = []
    if not text:
        return servers
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('#') or line.startswith(';'):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == 'nameserver':
            servers.append(parts[1])
    return servers


def parse_iw_link(text):
    """Pulls SSID, BSSID and signal out of `iw dev <if> link` output."""
    info = SimpleNamespace(ssid=None, bssid=None, signal_dbm=None)
    if not text:
        return info

    first = text.strip().splitlines()[0] if text.strip() else ''
    match = re.search(r'Connected to ([0-9a-fA-F:]{17})', first)
    if match:
        info.bssid = normalize_mac(match.group(1))

    for line in text.splitlines():
        line = line.strip()
        if line.startswith('SSID:'):
            info.ssid = line.split(':', 1)[1].strip()
        elif line.startswith('signal:'):
            sig = re.search(r'(-?\d+)\s*dBm', line)
            if sig:
                info.signal_dbm = int(sig.group(1))
    return info


def dbm_to_percent(dbm):
    """The mapping Windows itself uses to render a signal strength.

    -50 dBm and stronger is 100%, -100 dBm is 0%, linear in between. It
    is a convention rather than a measurement, but it keeps the log
    column comparable with the one the Windows port writes.
    """
    if dbm is None:
        return None
    return max(0, min(100, int(round(2 * (dbm + 100)))))


# ------------------------------------------------------- interface facts

def _iface_ipv4(name, request):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        packed = fcntl.ioctl(sock.fileno(), request,
                             struct.pack('256s', name[:15].encode('ascii', 'replace')))
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def _netmask_to_prefix(mask):
    if not mask:
        return None
    try:
        packed = socket.inet_aton(mask)
    except OSError:
        return None
    return bin(struct.unpack('!L', packed)[0]).count('1')


def _iface_attr(name, attr):
    return (_read_text(os.path.join(SYS_NET, name, attr)) or '').strip() or None


def _is_wireless(name):
    base = os.path.join(SYS_NET, name)
    return os.path.exists(os.path.join(base, 'wireless')) or \
        os.path.exists(os.path.join(base, 'phy80211'))


def _interfaces():
    try:
        return sorted(os.listdir(SYS_NET))
    except OSError:
        return []


def egress_interface(target_ip):
    """Finds the interface the kernel would actually use to reach target_ip.

    On a multi-homed host (VPN up, docker bridge, second NIC) the
    "default" adapter is often not the one carrying the DNS traffic, and
    logging the wrong MAC would send an investigation down the wrong
    cable. A connected UDP socket makes the kernel run the real routing
    decision without a packet leaving the machine; the interface is then
    the one owning that source address.
    """
    local_ip = None

    if target_ip:
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.connect((target_ip, 53))
                local_ip = probe.getsockname()[0]
            finally:
                probe.close()
        except OSError:
            local_ip = None

    interface = None
    if local_ip:
        for name in _interfaces():
            if _iface_ipv4(name, SIOCGIFADDR) == local_ip:
                interface = name
                break

    if interface is None and target_ip:
        # Second opinion for setups the address match cannot resolve
        # (point-to-point links, unnumbered interfaces).
        result = _run(['ip', '-o', 'route', 'get', target_ip], timeout=5)
        if result and result.code == 0:
            dev = re.search(r'\bdev\s+(\S+)', result.out)
            src = re.search(r'\bsrc\s+(\S+)', result.out)
            if dev:
                interface = dev.group(1)
            if src and not local_ip:
                local_ip = src.group(1)

    if interface is None:
        routes = default_routes(_read_text(PROC_ROUTE))
        if routes:
            interface = routes[0].interface
        if local_ip is None and interface:
            local_ip = _iface_ipv4(interface, SIOCGIFADDR)

    return SimpleNamespace(interface=interface, local_ip=local_ip)


def default_gateway(interface=None):
    """The next hop for 0.0.0.0/0, preferring the given interface."""
    routes = default_routes(_read_text(PROC_ROUTE))
    if interface:
        for route in routes:
            if route.interface == interface:
                return route.gateway
    return routes[0].gateway if routes else None


def gateway_mac(gateway_ip):
    """The first-hop device's MAC, from the kernel neighbour table."""
    if not gateway_ip:
        return (None, None)

    table = parse_proc_arp(_read_text(PROC_ARP))
    if gateway_ip in table:
        return table[gateway_ip]

    # /proc/net/arp only lists IPv4 and only completed-ish entries; `ip
    # neigh` sees the full table where it is installed.
    result = _run(['ip', 'neigh', 'show', gateway_ip], timeout=5)
    if result and result.code == 0:
        match = re.search(r'lladdr\s+([0-9a-fA-F:]{17})', result.out)
        if match:
            state = re.search(r'(REACHABLE|STALE|DELAY|PROBE|PERMANENT|INCOMPLETE|FAILED)',
                              result.out)
            return (normalize_mac(match.group(1)),
                    state.group(1).capitalize() if state else None)

    return (None, None)


def configured_dns():
    """The resolvers this host is configured to use.

    A systemd-resolved stub at 127.0.0.53 says nothing about which
    server is on the far side of the block, so the real upstreams are
    added when resolved publishes them.
    """
    servers = parse_resolv_conf(_read_text(RESOLV_CONF))
    if any(s.startswith('127.0.0.5') for s in servers):
        upstream = parse_resolv_conf(_read_text(SYSTEMD_RESOLV_CONF))
        for s in upstream:
            if s not in servers:
                servers.append(s)
    return ';'.join(servers) if servers else None


def wireless_context(interface):
    """SSID, BSSID and signal for a Wi-Fi interface, where readable.

    The BSSID is the MAC of the access point actually serving us, which
    is the one piece of path identity that a roaming laptop changes
    without anything else changing.
    """
    ctx = SimpleNamespace(is_wireless=False, ssid=None, bssid=None, signal_percent=None)
    if not interface or not _is_wireless(interface):
        return ctx

    ctx.is_wireless = True

    result = _run(['iw', 'dev', interface, 'link'], timeout=5)
    if result and result.code == 0 and 'Not connected' not in result.out:
        info = parse_iw_link(result.out)
        ctx.ssid = info.ssid
        ctx.bssid = info.bssid
        ctx.signal_percent = dbm_to_percent(info.signal_dbm)
        if ctx.ssid or ctx.bssid:
            return ctx

    result = _run(['iwconfig', interface], timeout=5)
    if result and result.code == 0:
        ssid = re.search(r'ESSID:"([^"]*)"', result.out)
        bssid = re.search(r'Access Point:\s*([0-9a-fA-F:]{17})', result.out)
        level = re.search(r'Signal level[=:]\s*(-?\d+)', result.out)
        if ssid:
            ctx.ssid = ssid.group(1)
        if bssid:
            ctx.bssid = normalize_mac(bssid.group(1))
        if level:
            ctx.signal_percent = dbm_to_percent(int(level.group(1)))

    return ctx


def host_network_context(target_ip=None):
    """Builds the "where and on what" record attached to every log entry."""
    egress = egress_interface(target_ip)
    interface = egress.interface

    ctx = SimpleNamespace(
        host_name=socket.gethostname(),
        user_name=os.environ.get('SUDO_USER') or os.environ.get('USER') or str(os.getuid()),
        adapter_name=interface,
        adapter_description=None,
        adapter_mac=None,
        media_type=None,
        link_speed=None,
        interface_index=None,
        local_ip=egress.local_ip,
        prefix_length=None,
        gateway_ip=None,
        gateway_mac=None,
        gateway_mac_state=None,
        configured_dns=configured_dns(),
        dhcp_enabled=None,          # no distro-independent source for this
        is_wireless=False,
        ssid=None,
        bssid=None,
        signal_percent=None,
    )

    if interface:
        ctx.adapter_mac = normalize_mac(_iface_attr(interface, 'address'))
        ctx.media_type = 'Native 802.11' if _is_wireless(interface) else '802.3'
        ctx.adapter_description = _iface_attr(interface, 'device/modalias') or \
            _iface_attr(interface, 'uevent')
        if ctx.adapter_description:
            ctx.adapter_description = ctx.adapter_description.splitlines()[0][:80]

        speed = _iface_attr(interface, 'speed')
        if speed and speed.lstrip('-').isdigit() and int(speed) > 0:
            ctx.link_speed = '%d Mbps' % int(speed)

        try:
            ctx.interface_index = socket.if_nametoindex(interface)
        except OSError:
            ctx.interface_index = None

        if not ctx.local_ip:
            ctx.local_ip = _iface_ipv4(interface, SIOCGIFADDR)
        ctx.prefix_length = _netmask_to_prefix(_iface_ipv4(interface, SIOCGIFNETMASK))

    ctx.gateway_ip = default_gateway(interface)
    ctx.gateway_mac, ctx.gateway_mac_state = gateway_mac(ctx.gateway_ip)

    wifi = wireless_context(interface)
    ctx.is_wireless = wifi.is_wireless
    ctx.ssid = wifi.ssid
    ctx.bssid = wifi.bssid
    ctx.signal_percent = wifi.signal_percent

    return ctx


# ------------------------------------------------- local packet filter

def _port_expr_matches(expr, port=53):
    """True when an nftables or iptables port expression covers `port`.

    Handles the spellings both tools produce: a bare number, a comma
    list, an nft set in braces, and a range written either 50-60 (nft)
    or 50:60 (iptables).
    """
    if expr is None:
        return False
    text = expr.strip().strip('{}').strip()
    if not text:
        return False

    for item in text.split(','):
        item = item.strip()
        if not item:
            continue
        match = re.match(r'^(\d+)\s*[-:]\s*(\d+)$', item)
        if match:
            low, high = int(match.group(1)), int(match.group(2))
            if low <= port <= high:
                return True
            continue
        if item.isdigit() and int(item) == port:
            return True
    return False


def _direction_from_chain(name):
    key = (name or '').lower()
    if key in ('output', 'postrouting'):
        return 'Outbound'
    if key in ('input', 'prerouting'):
        return 'Inbound'
    if key == 'forward':
        return 'Forward'
    return name or 'Unknown'


def _make_rule(source, chain_path, direction, protocol, dport, sport, line):
    if direction == 'Inbound':
        local_port, remote_port = dport, sport
    else:
        local_port, remote_port = sport, dport
    return SimpleNamespace(
        display_name='%s %s: %s' % (source, chain_path, line[:120]),
        direction=direction,
        protocol=(protocol or 'any').upper(),
        local_port=local_port or 'Any',
        remote_port=remote_port or 'Any',
        source=source,
    )


def parse_nft_ruleset(text, port=53):
    """Finds drop/reject rules covering `port` in `nft list ruleset` output."""
    rules = []
    if not text:
        return rules

    table = None
    chain = None
    direction = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        match = re.match(r'^table\s+(\S+)\s+(\S+)\s*\{', line)
        if match:
            table = '%s %s' % (match.group(1), match.group(2))
            chain = None
            continue

        match = re.match(r'^chain\s+(\S+)\s*\{', line)
        if match:
            chain = match.group(1)
            direction = _direction_from_chain(chain)
            continue

        if line.startswith('}'):
            if chain is not None:
                chain = None
            else:
                table = None
            continue

        hook = re.search(r'\bhook\s+(\w+)', line)
        if hook and chain is not None:
            direction = _direction_from_chain(hook.group(1))
            continue

        if not re.search(r'\b(drop|reject)\b', line):
            continue

        dport = sport = None
        protocol = None
        for match in re.finditer(r'\b(tcp|udp)\s+(dport|sport)\s+(\{[^}]*\}|[\w:.\-,]+)', line):
            if not _port_expr_matches(match.group(3), port):
                continue
            protocol = match.group(1)
            if match.group(2) == 'dport':
                dport = match.group(3).strip()
            else:
                sport = match.group(3).strip()

        if dport or sport:
            chain_path = '%s/%s' % (table or '?', chain or '?')
            rules.append(_make_rule('nftables', chain_path, direction or 'Unknown',
                                    protocol, dport, sport, line))
    return rules


def parse_iptables_rules(text, port=53):
    """Finds DROP/REJECT rules covering `port` in `iptables -S` output."""
    rules = []
    if not text:
        return rules

    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith('-A '):
            continue
        if not re.search(r'-j\s+(DROP|REJECT)\b', line):
            continue

        chain = line.split()[1]
        protocol = None
        match = re.search(r'-p\s+(\S+)', line)
        if match:
            protocol = match.group(1)

        dport = sport = None
        for match in re.finditer(r'--(dport|dports|sport|sports)\s+(\S+)', line):
            if not _port_expr_matches(match.group(2), port):
                continue
            if match.group(1).startswith('dport'):
                dport = match.group(2)
            else:
                sport = match.group(2)

        if dport or sport:
            rules.append(_make_rule('iptables', chain, _direction_from_chain(chain),
                                    protocol, dport, sport, line))
    return rules


def local_dns_firewall_rules(port=53):
    """Looks for a *local* packet-filter rule that blocks port 53.

    Run once per session rather than per probe: shelling out to the
    filter tooling is slow. If a local rule is found, the block is on
    this machine and no amount of staring at the campus firewall will
    explain it.

    Unlike the Windows firewall, nftables and iptables refuse to list
    their rules without CAP_NET_ADMIN, so an unprivileged run reports
    "unreadable" rather than "no rules" -- the difference matters, and
    silently reporting a clean local filter would be a lie.
    """
    rules = []
    notes = []
    readable = False

    result = _run(['nft', 'list', 'ruleset'], timeout=15)
    if result is None:
        notes.append('nft not installed')
    elif result.code == 0:
        readable = True
        rules.extend(parse_nft_ruleset(result.out, port))
    else:
        notes.append('nft unreadable (%s)' % (result.err.strip().splitlines()[0]
                                              if result.err.strip() else 'exit %d' % result.code))

    result = _run(['iptables', '-S'], timeout=15)
    if result is None:
        notes.append('iptables not installed')
    elif result.code == 0:
        readable = True
        rules.extend(parse_iptables_rules(result.out, port))
    else:
        notes.append('iptables unreadable (%s)' % (result.err.strip().splitlines()[0]
                                                   if result.err.strip() else 'exit %d' % result.code))

    return SimpleNamespace(
        rules=rules,
        readable=readable,
        note='; '.join(notes) if notes else None,
    )


# ------------------------------------------------------------- the path

def _icmp_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _icmp_echo_ms(target_ip, timeout_s=1.0, sequence=1):
    """One echo request over an unprivileged ICMP datagram socket.

    Linux grants these to the group range in net.ipv4.ping_group_range,
    which is how `ping` itself works on most distributions now. Where it
    is not granted, the caller falls back to the ping binary.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return None

    try:
        sock.settimeout(timeout_s)
        header = struct.pack('!BBHHH', 8, 0, 0, 0, sequence)
        payload = b'tcp53watch'
        checksum = _icmp_checksum(header + payload)
        packet = struct.pack('!BBHHH', 8, 0, checksum, 0, sequence) + payload

        started = time.time()
        sock.sendto(packet, (target_ip, 0))
        while True:
            data, _addr = sock.recvfrom(1024)
            if len(data) >= 8 and data[0] == 0:          # echo reply
                return int(round((time.time() - started) * 1000))
            if time.time() - started > timeout_s:
                return None
    except OSError:
        return None
    finally:
        sock.close()


def gateway_rtt_ms(target_ip, count=2):
    """Average RTT to the first hop: the yardstick for deciding whether a
    RST came from inside the LAN or from somewhere further out."""
    if not target_ip:
        return -1

    samples = [ms for ms in (_icmp_echo_ms(target_ip, sequence=i + 1) for i in range(count))
               if ms is not None]
    if samples:
        return int(round(sum(samples) / float(len(samples))))

    result = _run(['ping', '-n', '-c', str(count), '-W', '1', target_ip], timeout=10)
    if result and result.code == 0:
        match = re.search(r'=\s*[\d.]+/([\d.]+)/', result.out)
        if match:
            return int(round(float(match.group(1))))

    return -1


def parse_traceroute(text):
    """Extracts the first responding address of each hop."""
    hops = []
    if not text:
        return hops
    for line in text.splitlines():
        if not re.match(r'^\s*\d+', line):
            continue
        match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        hops.append(match.group(1) if match else '*')
    return hops


def first_hop_path(target_ip, max_hops=8):
    """Records the first few hops toward the DNS server.

    Used only in the one-shot diagnostic, never in the monitor loop: it
    is slow and noisy. The value is that the hop where TTL expiry stops
    responding often sits next to the device dropping port 53.

    Both helpers are optional; a host without either simply reports no
    path, which costs nothing else in the diagnosis.
    """
    for argv in (['traceroute', '-n', '-w', '1', '-m', str(max_hops), target_ip],
                 ['tracepath', '-n', '-m', str(max_hops), target_ip]):
        result = _run(argv, timeout=60)
        if result is None or result.code != 0:
            continue
        hops = parse_traceroute(result.out)
        if hops:
            return SimpleNamespace(hops=hops, note=None)

    return SimpleNamespace(hops=[], note='neither traceroute nor tracepath is installed')
