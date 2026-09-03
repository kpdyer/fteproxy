#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Structural realism check for the ``dns`` format, judged by an independent parser.

``dns`` is the one binary format in the release: a covertext is one DNS message
carried over TCP, which RFC 1035 section 4.2.2 frames as a two-byte big-endian
length prefix followed by that many bytes of message. There is no stdlib DNS
parser to borrow (unlike ``http``, which delegates to :mod:`http.server`) and a
third-party one is out of bounds, so this module *is* the independent parser:
a hand-written walk over the wire bytes that knows only RFC 1035, never the
format's regex. It must not import the fragment or re-apply the pattern --
grading a regex with a copy of itself proves nothing.

What :func:`check` walks, in order:

* the 2-byte length prefix, which must equal the number of bytes that follow;
* the 12-byte header -- ID (arbitrary), flags, and the QDCOUNT / ANCOUNT /
  NSCOUNT / ARCOUNT section counts -- dispatching on the QR bit to the query or
  the reply shape and requiring the counts that shape implies;
* the QNAME, label by label: each length byte must be 1..63 (never a
  compression pointer, which has no place in a question), must be followed by
  exactly that many bytes still inside the message, and the whole encoded name
  including the terminating root byte must be 255 octets or fewer (RFC 1035
  section 2.3.4). Label bytes are checked against the preferred host-name
  alphabet (letters, digits, hyphen; no leading or trailing hyphen), and the
  last label must be all letters, since no real top-level domain is numeric;
* QTYPE and QCLASS, which must be a type this format models (A, or AAAA on a
  query) in class IN;
* for a reply, the single answer record: the NAME must be the compression
  pointer ``0xc0 0x0c``, whose 14-bit target (offset 12) is *followed* back
  into the message and re-parsed, and must yield exactly the question's name;
  then TYPE A, CLASS IN, a plausible TTL, ``RDLENGTH == 4``, and four address
  bytes that are not 0.x, not 127.x loopback, and not in the 224+
  multicast/reserved space;
* nothing left over: the message must end exactly where the last field does.

Case is not folded away. A query whose labels mix upper and lower case is not a
defect: RFC 4343 makes DNS names case-insensitive but case-preserving on the
wire, and resolvers deliberately randomise the case of a query name (the
"DNS-0x20" anti-spoofing trick, draft-vixie-dnsext-dns0x20) and match the reply
against the case they sent. The format draws its labels from the mixed-case
host alphabet for exactly that reason, so this parser accepts either case.
"""

import collections


class DNSRealismError(Exception):
    """A covertext is not a structurally valid DNS-over-TCP message."""


# Alphabets, spelled out as byte sets so this check owns its own grammar rather
# than leaning on the format regex.
_DIGITS = set(b'0123456789')
_LETTERS = set(b'abcdefghijklmnopqrstuvwxyz'
               b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
#: The preferred host-name alphabet of RFC 1123: letters, digits and hyphen.
_LDH = _LETTERS | _DIGITS | set(b'-')

_HEADER_BYTES = 12
#: A question's name starts right after the header, so a reply's answer record
#: points back at this offset.
_QUESTION_OFFSET = _HEADER_BYTES

_MAX_NAME_OCTETS = 255          # RFC 1035 2.3.4
_MAX_LABEL_OCTETS = 63          # RFC 1035 2.3.4; also why 0xc0 means "pointer"
_LABEL_TYPE_MASK = 0xc0         # top two bits of a length byte
_POINTER_TAG = 0xc0
_POINTER_OFFSET_MASK = 0x3f     # the low six bits of a pointer's first byte

#: Header flag words this format models: a standard recursion-desired query,
#: and a NOERROR reply with recursion desired and available.
_FLAGS_QUERY = 0x0100
_FLAGS_REPLY = 0x8180
_QR_BIT = 0x8000

_TYPE_A = 1
_TYPE_AAAA = 28
_CLASS_IN = 1
_A_RDLENGTH = 4

#: A week. Longer would parse, but no cache keeps an A record that long, so a
#: TTL past it is a realism failure rather than a structural one.
_MAX_PLAUSIBLE_TTL = 604800

#: First address octet: 0.x is "this network", 127.x is loopback and 224+ is
#: multicast/reserved, so none of them answers a public A query.
_RESERVED_FIRST_OCTETS = {0, 127}
_MULTICAST_FIRST_OCTET = 224


#: What :func:`parse` hands back. ``name_octets`` is the *encoded* length of the
#: question name (every length byte, every label byte, and the root byte), which
#: is the quantity RFC 1035 caps at 255.
Message = collections.namedtuple(
    'Message',
    'is_response ident flags labels name_octets qtype qclass '
    'ttl address')


def _u16(data, offset, what):
    if offset + 2 > len(data):
        raise DNSRealismError('truncated before %s' % what)
    return (data[offset] << 8) | data[offset + 1]


def _check_label(label):
    if not 0 < len(label) <= _MAX_LABEL_OCTETS:
        raise DNSRealismError('label of %d bytes is out of range 1..%d'
                              % (len(label), _MAX_LABEL_OCTETS))
    for byte in label:
        if byte not in _LDH:
            raise DNSRealismError('label %r has byte 0x%02x outside the '
                                  'letter/digit/hyphen alphabet'
                                  % (label, byte))
    if label[0:1] == b'-' or label[-1:] == b'-':
        raise DNSRealismError('label %r starts or ends with a hyphen'
                              % (label,))


def _read_name(message, offset):
    """Walk an uncompressed name. Returns ``(labels, end_offset, octets)``."""
    start = offset
    labels = []
    while True:
        if offset >= len(message):
            raise DNSRealismError('name at offset %d runs off the end of the '
                                  'message' % start)
        length = message[offset]
        if length == 0:
            offset += 1
            break
        if length & _LABEL_TYPE_MASK:
            # 0xc0 is a compression pointer and 0x40/0x80 are reserved label
            # types; neither belongs in a question name.
            raise DNSRealismError('label length byte 0x%02x at offset %d is a '
                                  'pointer or a reserved label type'
                                  % (length, offset))
        end = offset + 1 + length
        if end > len(message):
            raise DNSRealismError('label at offset %d claims %d bytes but only '
                                  '%d remain' % (offset, length,
                                                 len(message) - offset - 1))
        label = message[offset + 1:end]
        _check_label(label)
        labels.append(label)
        offset = end

    octets = offset - start
    if octets > _MAX_NAME_OCTETS:
        raise DNSRealismError('encoded name is %d octets, over the %d-octet '
                              'limit' % (octets, _MAX_NAME_OCTETS))
    if len(labels) < 2:
        raise DNSRealismError('name has %d label(s); a queried name carries at '
                              'least a host and a top-level domain'
                              % len(labels))
    tld = labels[-1]
    if any(byte not in _LETTERS for byte in tld):
        raise DNSRealismError('top-level label %r is not all letters' % (tld,))
    return labels, offset, octets


def _check_answer(message, offset, question_labels):
    """Validate the single A record of a reply.

    Returns ``(ttl, address, end_offset)``.
    """
    if offset + 2 > len(message):
        raise DNSRealismError('truncated before the answer record name')
    tag, low = message[offset], message[offset + 1]
    if tag & _LABEL_TYPE_MASK != _POINTER_TAG:
        raise DNSRealismError('answer name starts with 0x%02x, not a '
                              'compression pointer' % tag)
    target = ((tag & _POINTER_OFFSET_MASK) << 8) | low
    if target != _QUESTION_OFFSET:
        raise DNSRealismError('answer name points at offset %d, not at the '
                              'question name (offset %d)'
                              % (target, _QUESTION_OFFSET))
    # Follow the pointer: the target must really be a name, and the same one.
    pointed_labels, _, _ = _read_name(message, target)
    if pointed_labels != question_labels:
        raise DNSRealismError('answer name pointer resolves to a different '
                              'name than the question')
    offset += 2

    rrtype = _u16(message, offset, 'the answer TYPE')
    rrclass = _u16(message, offset + 2, 'the answer CLASS')
    if rrtype != _TYPE_A:
        raise DNSRealismError('answer TYPE is %d, not A (%d)'
                              % (rrtype, _TYPE_A))
    if rrclass != _CLASS_IN:
        raise DNSRealismError('answer CLASS is %d, not IN (%d)'
                              % (rrclass, _CLASS_IN))
    offset += 4

    if offset + 4 > len(message):
        raise DNSRealismError('truncated before the answer TTL')
    ttl = int.from_bytes(message[offset:offset + 4], 'big')
    if ttl > _MAX_PLAUSIBLE_TTL:
        raise DNSRealismError('answer TTL %d exceeds the %d-second ceiling a '
                              'real A record stays inside'
                              % (ttl, _MAX_PLAUSIBLE_TTL))
    offset += 4

    rdlength = _u16(message, offset, 'RDLENGTH')
    if rdlength != _A_RDLENGTH:
        raise DNSRealismError('RDLENGTH is %d; an A record carries exactly %d '
                              'bytes' % (rdlength, _A_RDLENGTH))
    offset += 2

    if offset + rdlength > len(message):
        raise DNSRealismError('RDATA claims %d bytes but only %d remain'
                              % (rdlength, len(message) - offset))
    address = message[offset:offset + rdlength]
    if address[0] in _RESERVED_FIRST_OCTETS:
        raise DNSRealismError('answer address %s is in a reserved /8'
                              % '.'.join(str(b) for b in address))
    if address[0] >= _MULTICAST_FIRST_OCTET:
        raise DNSRealismError('answer address %s is multicast or reserved'
                              % '.'.join(str(b) for b in address))
    offset += rdlength
    return ttl, address, offset


def parse(covertext):
    """Parse one DNS-over-TCP covertext into a :class:`Message`.

    Raises :class:`DNSRealismError` on anything that is not a structurally valid
    message. :func:`check` is this function with the result thrown away; tests
    that want to assert something about the parsed message (the encoded name
    length, say) call this instead of writing a second parser.
    """
    if not isinstance(covertext, (bytes, bytearray)):
        raise TypeError('covertext must be bytes, got %r' % type(covertext))
    covertext = bytes(covertext)

    # -- RFC 1035 4.2.2: the two-byte length prefix ------------------------- #
    if len(covertext) < 2:
        raise DNSRealismError('covertext is %d bytes, too short for the TCP '
                              'length prefix' % len(covertext))
    declared = (covertext[0] << 8) | covertext[1]
    message = covertext[2:]
    if declared != len(message):
        raise DNSRealismError('length prefix says %d bytes but %d follow'
                              % (declared, len(message)))

    # -- the 12-byte header ------------------------------------------------- #
    if len(message) < _HEADER_BYTES:
        raise DNSRealismError('message is %d bytes, shorter than the %d-byte '
                              'header' % (len(message), _HEADER_BYTES))
    ident = _u16(message, 0, 'the ID')       # any 16-bit value is a valid ID
    flags = _u16(message, 2, 'the flags')
    qdcount = _u16(message, 4, 'QDCOUNT')
    ancount = _u16(message, 6, 'ANCOUNT')
    nscount = _u16(message, 8, 'NSCOUNT')
    arcount = _u16(message, 10, 'ARCOUNT')

    is_response = bool(flags & _QR_BIT)
    if is_response:
        expected_flags, expected_counts = _FLAGS_REPLY, (1, 1, 0, 0)
    else:
        expected_flags, expected_counts = _FLAGS_QUERY, (1, 0, 0, 0)
    if flags != expected_flags:
        raise DNSRealismError('flags 0x%04x are not the 0x%04x of a %s'
                              % (flags, expected_flags,
                                 'reply' if is_response else 'query'))
    counts = (qdcount, ancount, nscount, arcount)
    if counts != expected_counts:
        raise DNSRealismError('section counts %r are not the %r a %s carries'
                              % (counts, expected_counts,
                                 'reply' if is_response else 'query'))

    # -- the question ------------------------------------------------------- #
    labels, offset, name_octets = _read_name(message, _QUESTION_OFFSET)
    qtype = _u16(message, offset, 'QTYPE')
    qclass = _u16(message, offset + 2, 'QCLASS')
    offset += 4
    allowed = (_TYPE_A,) if is_response else (_TYPE_A, _TYPE_AAAA)
    if qtype not in allowed:
        raise DNSRealismError('QTYPE %d is not one of %r' % (qtype, allowed))
    if qclass != _CLASS_IN:
        raise DNSRealismError('QCLASS is %d, not IN (%d)'
                              % (qclass, _CLASS_IN))

    # -- the answer, for a reply -------------------------------------------- #
    ttl = address = None
    if is_response:
        ttl, address, offset = _check_answer(message, offset, labels)

    if offset != len(message):
        raise DNSRealismError('%d trailing byte(s) after the last record'
                              % (len(message) - offset))

    return Message(is_response=is_response, ident=ident, flags=flags,
                   labels=labels, name_octets=name_octets, qtype=qtype,
                   qclass=qclass, ttl=ttl, address=address)


def check(covertext):
    """Raise if ``covertext`` is not a structurally valid DNS-over-TCP message."""
    parse(covertext)
