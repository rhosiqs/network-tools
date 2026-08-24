"""
net_probe.py
------------------------------------------------------------------
Transport-level probes for DNS over TCP/53 and UDP/53.

Every probe reports the *phase* it died in (Connect / Send / Receive)
together with the raw errno. That pair is what separates the different
kinds of blocking from one another:

    Connect + ETIMEDOUT      -> nothing answered the SYN
    Connect + ECONNREFUSED   -> something answered with a RST
    Receive + ETIMEDOUT      -> handshake allowed, no reply to the query
    Receive + ECONNRESET     -> the query itself triggered a RST

The outcome tokens are identical to the PowerShell probes' tokens, so
the classifier and the logs do not care which platform produced them.
"""

import errno
import socket
import time
from types import SimpleNamespace

from dns_codec import build_query, parse_response


def _new_result(protocol, server, port):
    return SimpleNamespace(
        protocol=protocol,
        server=server,
        port=port,
        success=False,
        phase='Init',
        outcome='NotRun',
        socket_error=None,
        socket_code=None,
        connect_ms=None,
        elapsed_ms=None,
        bytes_received=0,
        response=None,
        detail=None,
    )


def resolve_socket_outcome(phase, err_no):
    """Maps an errno onto a stable, phase-aware outcome token.

    Keeping this in one place means the classifier never has to know
    about platform error numbers -- the Windows port maps Winsock codes
    onto exactly the same set.
    """
    if err_no == errno.ECONNREFUSED:
        return 'Refused'
    if err_no == errno.ETIMEDOUT:
        return 'ConnectTimeout' if phase == 'Connect' else 'ReadTimeout'
    if err_no == errno.EHOSTUNREACH:
        return 'HostUnreachable'
    if err_no == errno.ENETUNREACH:
        return 'NetworkUnreachable'
    if err_no == errno.ECONNRESET:
        return 'Reset'
    if err_no in (errno.ECONNABORTED, errno.EPIPE):
        return 'Aborted'
    if err_no in (errno.EACCES, errno.EPERM):
        return 'LocallyDenied'
    return 'SocketError:%s' % errno.errorcode.get(err_no, err_no)


def _errno_name(err_no):
    return errno.errorcode.get(err_no, str(err_no))


def _apply_exception(result, phase, exc, elapsed_ms):
    """Fills in the failure fields from whatever the socket layer raised."""
    result.elapsed_ms = elapsed_ms

    if isinstance(exc, socket.timeout):
        # A timeout raised by settimeout() carries no errno; it means the
        # same thing as ETIMEDOUT and must classify the same way.
        result.socket_error = 'ETIMEDOUT'
        result.socket_code = errno.ETIMEDOUT
        result.outcome = resolve_socket_outcome(phase, errno.ETIMEDOUT)
        result.detail = ('No reply within the timeout at phase %s.' % phase)
        return result

    if isinstance(exc, socket.gaierror):
        result.socket_error = 'EAI'
        result.outcome = 'NameResolutionFailed'
        result.detail = str(exc)
        return result

    if isinstance(exc, OSError) and exc.errno is not None:
        result.socket_error = _errno_name(exc.errno)
        result.socket_code = exc.errno
        result.outcome = resolve_socket_outcome(phase, exc.errno)
        result.detail = exc.strerror or str(exc)
        return result

    result.outcome = 'Exception'
    result.detail = str(exc)
    return result


def _connect_socket(server, port, sock_type, timeout_s):
    """Resolves the address and returns a connected socket.

    getaddrinfo is used rather than a hard-coded AF_INET so a target may
    be given as an IPv6 address or a name; the numeric addresses in the
    configuration take the fast path through it unchanged.
    """
    infos = socket.getaddrinfo(server, port, socket.AF_UNSPEC, sock_type)
    family, socktype, proto, _canon, sockaddr = infos[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout_s)
    if sock_type == socket.SOCK_STREAM:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        # UDP connect() sends nothing; it binds the peer so that an ICMP
        # port-unreachable comes back as ECONNREFUSED instead of being
        # discarded, which is how a refused UDP probe is told apart from
        # one that simply vanished.
        sock.connect(sockaddr)
    except Exception:
        sock.close()
        raise
    return sock


def _read_exact(sock, count, deadline):
    """Reads exactly count bytes, or None if the peer closed cleanly.

    recv() may return fewer bytes than asked for; DNS over TCP is
    length-prefixed, so we must fill the buffer exactly or we will
    misparse a perfectly good answer as garbage.
    """
    buf = b''
    while len(buf) < count:
        remaining = deadline - time.time()
        if remaining <= 0:
            raise socket.timeout('read timed out')
        sock.settimeout(remaining)
        chunk = sock.recv(count - len(buf))
        if not chunk:
            return None                 # graceful FIN before we got our data
        buf += chunk
    return buf


def probe_tcp(server, query, port=53, connect_timeout_ms=3000, read_timeout_ms=4000):
    """Performs a full DNS transaction over TCP/53 and reports where it broke."""
    r = _new_result('TCP', server, port)
    started = time.time()

    def elapsed():
        return int(round((time.time() - started) * 1000))

    sock = None
    try:
        # ---- Phase 1: three-way handshake ---------------------------
        r.phase = 'Connect'
        sock = _connect_socket(server, port, socket.SOCK_STREAM, connect_timeout_ms / 1000.0)
        r.connect_ms = elapsed()

        # ---- Phase 2: send the length-prefixed query ----------------
        r.phase = 'Send'
        payload = query.data
        sock.settimeout(read_timeout_ms / 1000.0)
        sock.sendall(bytes([(len(payload) >> 8) & 0xFF, len(payload) & 0xFF]) + payload)

        # ---- Phase 3: read the length-prefixed answer ---------------
        r.phase = 'Receive'
        deadline = time.time() + (read_timeout_ms / 1000.0)

        head = _read_exact(sock, 2, deadline)
        if head is None:
            r.outcome = 'ClosedWithoutAnswer'
            r.elapsed_ms = elapsed()
            r.detail = 'Peer accepted the connection then closed it without sending a DNS reply.'
            return r

        resp_len = (head[0] << 8) | head[1]
        if resp_len <= 0 or resp_len > 65535:
            r.outcome = 'MalformedFraming'
            r.elapsed_ms = elapsed()
            r.detail = 'Reply announced an impossible length of %d bytes.' % resp_len
            return r

        body = _read_exact(sock, resp_len, deadline)
        if body is None:
            r.outcome = 'TruncatedStream'
            r.elapsed_ms = elapsed()
            r.detail = ('Connection closed after a %d-byte length header but '
                        'before the body arrived.' % resp_len)
            return r

        r.bytes_received = len(body)
        r.elapsed_ms = elapsed()
        parsed = parse_response(body)
        r.response = parsed

        if not parsed.valid:
            r.outcome = 'UnparseableResponse'
            r.detail = parsed.parse_error
        elif parsed.transaction_id != query.transaction_id:
            r.outcome = 'TransactionIdMismatch'
            r.detail = ('Expected ID %d but received %d - the reply did not come '
                        'from the server we asked.' % (query.transaction_id, parsed.transaction_id))
        else:
            r.success = True
            r.outcome = 'Answered'
            r.detail = '%s, %d answer(s), %d bytes.' % (parsed.rcode_name, parsed.answer_count, len(body))

        return r

    except Exception as exc:
        return _apply_exception(r, r.phase, exc, elapsed())
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_udp(server, query, port=53, timeout_ms=3000):
    """Performs a DNS transaction over UDP/53 -- the control case.

    If UDP works and TCP does not, the fault is specific to TCP/53
    rather than to the DNS server or the link.
    """
    r = _new_result('UDP', server, port)
    started = time.time()

    def elapsed():
        return int(round((time.time() - started) * 1000))

    sock = None
    try:
        r.phase = 'Send'
        sock = _connect_socket(server, port, socket.SOCK_DGRAM, timeout_ms / 1000.0)
        sock.send(query.data)

        r.phase = 'Receive'
        body = sock.recv(65535)

        r.bytes_received = len(body)
        r.elapsed_ms = elapsed()
        parsed = parse_response(body)
        r.response = parsed

        if not parsed.valid:
            r.outcome = 'UnparseableResponse'
            r.detail = parsed.parse_error
        elif parsed.transaction_id != query.transaction_id:
            r.outcome = 'TransactionIdMismatch'
            r.detail = 'Expected ID %d but received %d.' % (query.transaction_id, parsed.transaction_id)
        else:
            r.success = True
            r.outcome = 'AnsweredTruncated' if parsed.truncated else 'Answered'
            r.detail = '%s, %d answer(s), TC=%s.' % (parsed.rcode_name, parsed.answer_count, parsed.truncated)

        return r

    except Exception as exc:
        return _apply_exception(r, r.phase, exc, elapsed())
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def resolution_impact_test(server, name, qtype='TXT', timeout_ms=3000):
    """Answers the question the user actually cares about: does name
    resolution still work for a payload that needs the TCP fallback?

    Two steps, in the order a real client experiences them:
      1. Ask over UDP while advertising a 512-byte buffer. A large answer
         comes back with the TC bit set.
      2. If (and only if) TC was set, retry over TCP -- exactly what the
         stub resolver does next. If that retry cannot complete, the name
         is unresolvable for this host even though plain UDP "works",
         which is the signature failure of a TCP/53 block.
    """
    query = build_query(name, qtype, enable_edns=True, udp_payload_size=512)
    udp = probe_udp(server, query, timeout_ms=timeout_ms)

    result = SimpleNamespace(
        name=name,
        type=str(qtype).upper(),
        server=server,
        udp_outcome=udp.outcome,
        truncation_seen=False,
        tcp_fallback_tried=False,
        tcp_fallback_ok=False,
        resolved=False,
        impact='Unknown',
        detail=None,
    )

    if not udp.success:
        result.impact = 'UdpFailed'
        result.detail = ('UDP query failed (%s); TCP fallback cannot be assessed '
                         'from this sample.' % udp.outcome)
        return result

    result.truncation_seen = bool(udp.response.truncated)

    if not result.truncation_seen:
        result.resolved = udp.response.answer_count > 0
        result.impact = 'NoFallbackRequired'
        result.detail = 'Answer fit in a single UDP datagram (TC=0); this query never needs TCP.'
        return result

    # The server told us to come back over TCP. Do exactly that.
    tcp_query = build_query(name, qtype)
    tcp = probe_tcp(server, tcp_query, connect_timeout_ms=timeout_ms,
                    read_timeout_ms=timeout_ms + 1000)

    result.tcp_fallback_tried = True
    result.tcp_fallback_ok = bool(tcp.success)
    result.resolved = bool(tcp.success and tcp.response.answer_count > 0)

    if result.resolved:
        result.impact = 'FallbackSucceeded'
        result.detail = ('UDP set TC=1 and the TCP retry returned %d answer(s).'
                         % tcp.response.answer_count)
    else:
        result.impact = 'ResolutionBroken'
        result.detail = ('UDP set TC=1 but the mandatory TCP retry failed (%s). '
                         'This name is unresolvable from this host.' % tcp.outcome)

    return result


def tcp_port_reachable(server, port, timeout_ms=3000):
    """Bare TCP reachability with no DNS semantics.

    Used to compare port 53 against a control port on the same host: if
    443 connects and 53 does not, the filtering is port-specific rather
    than host-specific.
    """
    started = time.time()

    def elapsed():
        return int(round((time.time() - started) * 1000))

    sock = None
    try:
        sock = _connect_socket(server, port, socket.SOCK_STREAM, timeout_ms / 1000.0)
        return SimpleNamespace(server=server, port=port, connected=True,
                               outcome='Connected', elapsed_ms=elapsed())
    except socket.timeout:
        return SimpleNamespace(server=server, port=port, connected=False,
                               outcome='ConnectTimeout', elapsed_ms=elapsed())
    except OSError as exc:
        outcome = (resolve_socket_outcome('Connect', exc.errno)
                   if exc.errno is not None else 'Exception')
        return SimpleNamespace(server=server, port=port, connected=False,
                               outcome=outcome, elapsed_ms=elapsed())
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
