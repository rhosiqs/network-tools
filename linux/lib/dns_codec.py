"""
dns_codec.py
------------------------------------------------------------------
Minimal DNS wire-format encoder/decoder written against the standard
library only.

Why hand-roll this instead of calling getaddrinfo() or a resolver
library?
  The libc resolver hides the transport. It retries over whichever
  protocol it likes, consults nsswitch and any local cache, and
  collapses "no answer" and "refused" into the same failure. To prove
  that *TCP* port 53 specifically is being blocked we must own the
  socket and read the raw bytes ourselves.

Only the subset of RFC 1035 needed for diagnosis is implemented:
a single question, header flag extraction, and answer walking with
label-compression support.

This is the Linux counterpart of lib/Dns.Codec.ps1 and produces the
same tokens, so logs from either platform are read the same way.
"""

import random
from types import SimpleNamespace

TYPE_BY_NAME = {
    'A': 1,
    'NS': 2,
    'CNAME': 5,
    'SOA': 6,
    'PTR': 12,
    'MX': 15,
    'TXT': 16,
    'AAAA': 28,
    'DNSKEY': 48,
    'ANY': 255,
}

TYPE_BY_CODE = dict((v, k) for k, v in TYPE_BY_NAME.items())

RCODE_BY_CODE = {
    0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
    4: 'NOTIMP', 5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET',
    8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE',
}


def type_code(type_name):
    key = str(type_name).upper()
    if key in TYPE_BY_NAME:
        return TYPE_BY_NAME[key]
    raise ValueError("Unsupported DNS record type '%s'." % type_name)


def build_query(name, qtype='A', transaction_id=None, no_recursion=False,
                enable_edns=False, udp_payload_size=512):
    """Builds a raw DNS query message (without the TCP length prefix).

    enable_edns appends an OPT pseudo-record advertising a small UDP
    payload size. Advertising 512 bytes makes servers set the TC
    (truncated) bit on large answers, which is exactly the condition
    that forces a client to retry over TCP -- the failure mode this
    project hunts for.
    """
    if transaction_id is None:
        transaction_id = random.randint(1, 65534)

    out = bytearray()

    # --- Header ---
    out.append((transaction_id >> 8) & 0xFF)
    out.append(transaction_id & 0xFF)

    flags_hi = 0x00
    if not no_recursion:
        flags_hi |= 0x01                        # RD
    out.append(flags_hi)
    out.append(0x00)

    out += b'\x00\x01'                          # QDCOUNT = 1
    out += b'\x00\x00'                          # ANCOUNT
    out += b'\x00\x00'                          # NSCOUNT
    out += b'\x00\x01' if enable_edns else b'\x00\x00'   # ARCOUNT

    # --- Question ---
    for label in name.rstrip('.').split('.'):
        if not label:
            continue
        raw = label.encode('ascii')
        if len(raw) > 63:
            raise ValueError("DNS label '%s' exceeds 63 bytes." % label)
        out.append(len(raw))
        out += raw
    out.append(0x00)

    qt = type_code(qtype)
    out.append((qt >> 8) & 0xFF)
    out.append(qt & 0xFF)
    out += b'\x00\x01'                          # QCLASS = IN

    # --- Additional: OPT pseudo-RR (RFC 6891) ---
    if enable_edns:
        out.append(0x00)                        # root name
        out += b'\x00\x29'                      # TYPE = OPT (41)
        out.append((udp_payload_size >> 8) & 0xFF)   # CLASS = UDP payload size
        out.append(udp_payload_size & 0xFF)
        out += b'\x00\x00\x00\x00'              # extended RCODE + version + flags
        out += b'\x00\x00'                      # RDLENGTH = 0

    return SimpleNamespace(
        transaction_id=transaction_id,
        query_name=name,
        query_type=str(qtype).upper(),
        data=bytes(out),
    )


def read_name(buf, offset):
    """Decodes a (possibly compressed) domain name starting at offset.

    Returns (name, consumed) where consumed counts bytes in the original
    stream, which is not the same as how far we walked once a
    compression pointer was taken.
    """
    labels = []
    pos = offset
    jumped = False
    consumed = 0
    guard = 0

    while True:
        guard += 1
        if guard > 128:
            raise ValueError('DNS name decoding aborted: compression pointer loop.')
        if pos >= len(buf):
            raise ValueError('DNS name decoding aborted: truncated message.')

        length = buf[pos]

        if length == 0:
            pos += 1
            if not jumped:
                consumed = pos - offset
            break

        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(buf):
                raise ValueError('DNS name decoding aborted: truncated pointer.')
            target = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                consumed = (pos + 2) - offset
                jumped = True
            pos = target
            continue

        pos += 1
        if pos + length > len(buf):
            raise ValueError('DNS name decoding aborted: label runs past end.')
        labels.append(buf[pos:pos + length].decode('ascii', 'replace'))
        pos += length

    return '.'.join(labels), consumed


def parse_response(buf):
    """Parses a raw DNS response message into a diagnosable object.

    Never raises on a malformed body: the header is parsed first and any
    later failure is recorded in parse_error. A mangled answer section is
    itself evidence (middlebox tampering), so it must survive as data.
    """
    buf = bytes(buf)

    if len(buf) < 12:
        return SimpleNamespace(
            valid=False,
            parse_error='Response shorter than a DNS header (%d bytes).' % len(buf),
            transaction_id=None, is_response=None, opcode=None,
            authoritative=None, truncated=None, recursion_desired=None,
            recursion_available=None, rcode=None, rcode_name='UNPARSEABLE',
            question_count=0, answer_count=0, answers=[],
            message_length=len(buf),
        )

    txid = (buf[0] << 8) | buf[1]
    flag_hi = buf[2]
    flag_lo = buf[3]
    qd = (buf[4] << 8) | buf[5]
    an = (buf[6] << 8) | buf[7]
    rcode = flag_lo & 0x0F

    result = SimpleNamespace(
        valid=True,
        parse_error=None,
        transaction_id=txid,
        is_response=bool((flag_hi >> 7) & 1),
        opcode=(flag_hi >> 3) & 0x0F,
        authoritative=bool((flag_hi >> 2) & 1),
        truncated=bool((flag_hi >> 1) & 1),
        recursion_desired=bool(flag_hi & 1),
        recursion_available=bool((flag_lo >> 7) & 1),
        rcode=rcode,
        rcode_name=RCODE_BY_CODE.get(rcode, 'RCODE%d' % rcode),
        question_count=qd,
        answer_count=an,
        answers=[],
        message_length=len(buf),
    )

    try:
        pos = 12
        for _ in range(qd):
            _, used = read_name(buf, pos)
            pos += used + 4

        answers = []
        for _ in range(an):
            if pos + 10 > len(buf):
                break

            owner, used = read_name(buf, pos)
            pos += used

            rr_type = (buf[pos] << 8) | buf[pos + 1]
            ttl = ((buf[pos + 4] << 24) | (buf[pos + 5] << 16) |
                   (buf[pos + 6] << 8) | buf[pos + 7])
            rd_len = (buf[pos + 8] << 8) | buf[pos + 9]
            pos += 10

            if pos + rd_len > len(buf):
                break

            answers.append(SimpleNamespace(
                name=owner,
                type=TYPE_BY_CODE.get(rr_type, 'TYPE%d' % rr_type),
                type_code=rr_type,
                ttl=ttl,
                data=_read_rdata(buf, pos, rr_type, rd_len),
            ))

            pos += rd_len

        result.answers = answers
    except Exception as exc:                    # a mangled section is data, not a crash
        result.parse_error = str(exc)

    return result


def _read_rdata(buf, pos, rr_type, rd_len):
    if rr_type == 1 and rd_len == 4:                        # A
        return '.'.join(str(b) for b in buf[pos:pos + 4])
    if rr_type == 28 and rd_len == 16:                      # AAAA
        return ':'.join('%x' % ((buf[pos + g] << 8) | buf[pos + g + 1])
                        for g in range(0, 16, 2))
    if rr_type in (2, 5):                                   # NS, CNAME
        return read_name(buf, pos)[0]
    if rr_type == 16:                                       # TXT
        text = ''
        p = pos
        while p < pos + rd_len:
            slen = buf[p]
            p += 1
            text += buf[p:p + slen].decode('ascii', 'replace')
            p += slen
        return text
    return '<%d bytes>' % rd_len


def answer_summary(response):
    if response is None or not response.valid:
        return ''
    if response.answer_count == 0:
        return '(%s, 0 answers)' % response.rcode_name
    shown = ['%s=%s' % (a.type, a.data) for a in response.answers[:3]]
    return ', '.join(shown)
