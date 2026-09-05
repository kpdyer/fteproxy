#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The record layer: frames a byte stream as a sequence of libfte covertexts.

libfte 0.4 encrypts one message into exactly one fixed-length covertext and
has no stream framing of its own, so this module defines the wire layout.
Every record starts with a *sealed* covertext: its plaintext is
``len(4) || seq(8) || message || random pad`` filled to the format's capacity,
so it reads as random format text and only unseals at stream position
``seq``. The two modes differ in what the sealed covertext carries:

``format``
    The message itself. The stream is a sequence of covertexts, all in the
    target format.

``hybrid`` (the default)
    A 4-byte body length, followed on the wire by that many raw bytes:
    ``nonce(12) || AES-128-CTR ciphertext || HMAC-SHA256 tag(16)`` from
    :class:`fteproxy._AEADBody`, with ``seq`` bound into the tag. Only the
    header blends in with the format; the body is high-entropy ciphertext.
    A definition may give that body protocol-native framing.  HTTP uses one
    complete chunked body per record, so its formatted header and ciphertext
    are a syntactically complete HTTP/1.1 message instead of unframed bytes
    after a header that declared no body.

The message itself begins with a one-byte record type (:data:`DATA` and the
other constants below), so one connection carries application bytes, stream
control and future padding without a second framing layer. In ``format`` mode
that byte is the first byte inside the sealed covertext; in ``hybrid`` mode it
is the first byte encrypted into the body. Either way the sealed ``len`` and ``seq``
fields are unchanged, so chunking, buffering and the body-length bound are the
same as they were before types existed.

``seq`` is the record's position in its stream, counted from 0 by each
``Encoder``/``Decoder`` pair, so a record moved, replayed, or dropped within
a stream is rejected. Since 1.0 each direction of a connection has its own
header and body keys, derived per connection by :mod:`fteproxy.handshake`, so
a record cannot be replayed into another stream or the other direction either.
See SECURITY.md for what is not covered.

**Framing.** A fixed-length format frames on its length: one record is one
``length``-byte slice (plus, in hybrid mode, the authenticated body its header
announces and any protocol framing around that body).
A *variable-length* format (:class:`VariableLength`) picks one of the format's
allowed lengths per record and seals at it, and is delimited one of two ways
(``fteproxy.defs.spec_framing``):

``terminator``
    The covertext ends with a byte string its language can only produce as that
    final suffix. The decoder reads up to the next terminator and checks that
    what it found is a length this format emits.

``length-prefix``
    The covertext is preceded on the wire by a two-byte big-endian count of the
    bytes that follow -- :class:`LengthPrefixed`. The prefix is framing, not
    part of the format's language, which is precisely what DNS over TCP is
    (RFC 1035 section 4.2.2). The decoder reads the prefix, requires the wire
    length it implies to be one this format emits, and waits for that many
    bytes.

Either way the fixed-length fingerprint is gone from format-mode data records,
while hybrid headers and the two handshake records stay fixed-length. The two
handshake records are fixed at the format's ``max_length``, because the server
frames the client hello before it can decrypt anything; a hybrid header is fixed
at the *shortest* allowed length that holds :data:`HYBRID_HEADER_BYTES`, because
that is all a header carries and covertext cost grows superlinearly with length.
See ``docs/format-authoring.md``.
"""

import os
import random
import struct

import fte
from cryptography.exceptions import InvalidTag

import fteproxy.conf
import fteproxy.defs


#: Application bytes.
DATA = 0x00
#: Open a stream to the destination in the payload (see ``fteproxy.stream``).
OPEN = 0x01
#: The status of an :data:`OPEN`.
OPEN_RESULT = 0x02
#: Ignored on receipt; reserved for traffic shaping.
PADDING = 0x03
#: The sender will send no more :data:`DATA` on this connection.
CLOSE = 0x04

RECORD_TYPES = frozenset((DATA, OPEN, OPEN_RESULT, PADDING, CLOSE))

# Length prefix inside a sealed (random-padded) covertext plaintext.
_LEN = struct.Struct('>I')
# Sequence number inside a sealed covertext plaintext: the record's position in
# its stream. A sealed covertext therefore only unseals at that position, so a
# reordered, replayed, or dropped record is rejected in both modes (in hybrid
# mode the body MAC binds the same number).
_SEQ = struct.Struct('>Q')
_SEAL_OVERHEAD = _LEN.size + _SEQ.size
# The record type byte that leads every message.
_TYPE_LEN = 1
# Hybrid-mode header payload: the length of the authenticated body that follows
# it, excluding any protocol framing around that body.
_OVERFLOW_LEN = struct.Struct('>I')

#: Plaintext capacity a ``hybrid``-mode header cipher must have.
#:
#: A hybrid header carries one thing: the :data:`_OVERFLOW_LEN` count of the raw
#: body behind it. :func:`_seal` wraps that in the length and sequence fields,
#: so the whole sealed plaintext is exactly these 16 bytes and a covertext that
#: holds 16 bytes of plaintext holds a header. That is *all* it has to hold --
#: no payload rides in a hybrid header -- which is why a hybrid header does not
#: have to be sealed at the format's longest covertext the way the handshake's
#: two records are. :func:`fteproxy.hybrid_header_length` turns this number into
#: the length one format's headers go out at.
HYBRID_HEADER_BYTES = _OVERFLOW_LEN.size + _SEAL_OVERHEAD

#: The framing header of a ``length-prefix`` format: a big-endian count of the
#: message bytes that follow it (RFC 1035 4.2.2). Not part of any format's
#: language -- see :class:`LengthPrefixed`.
_PREFIX = struct.Struct('>H')
#: Width of that header, taken from the schema so the two cannot drift apart;
#: the struct's own width is checked against it at import.
PREFIX_LEN = fteproxy.defs.LENGTH_PREFIX_BYTES
assert _PREFIX.size == PREFIX_LEN


def _hybrid_body_parts(framing, body_len):
    """Return the bytes immediately before and after one hybrid body.

    ``body_len`` is authenticated inside the FTE header.  Raw framing adds
    nothing.  HTTP framing writes the ciphertext as exactly one chunk followed
    by the terminal zero chunk (RFC 9112 section 7).  Keeping this function
    deterministic lets the decoder derive and validate every framing byte from
    the authenticated length instead of trusting a second wire length.
    """
    if framing == fteproxy.defs.HYBRID_FRAMING_RAW:
        return b'', b''
    if framing == fteproxy.defs.HYBRID_FRAMING_HTTP_CHUNKED:
        if body_len < 0:
            raise ValueError('a hybrid body length cannot be negative')
        if body_len == 0:
            return b'0\r\n\r\n', b''
        return ('%x\r\n' % body_len).encode('ascii'), b'\r\n0\r\n\r\n'
    raise ValueError('unknown hybrid body framing: %r' % framing)


def _hybrid_wire_body_len(framing, body_len):
    """Bytes occupied by a hybrid body including its protocol framing."""
    prefix, suffix = _hybrid_body_parts(framing, body_len)
    return len(prefix) + body_len + len(suffix)


class UnknownRecordType(Exception):
    """An authenticated record whose type this version does not define.

    Only a peer holding the session keys can produce one, so this is a version
    mismatch rather than an attack, and the connection is closed: continuing
    would mean guessing at the meaning of the bytes that follow.
    """


class StreamFailedError(Exception):
    """Data was pushed into a :class:`Decoder` after one of its records
    failed authentication. The stream cannot resume; close the connection."""


def _seal(cipher, message, seq):
    """Encrypt ``message`` into one covertext, random-padded to the format's
    full plaintext capacity and stamped with its stream position ``seq``.

    A short message otherwise ranks low and unranks into a covertext with a long
    run of the format's lowest character (the ``GET /0000...`` padding). Filling
    the plaintext to capacity makes the covertext use its whole rank space, so it
    reads as random format text and no longer leaks the message length through
    its rank. The random pad sits inside the authenticated ciphertext, so it
    costs nothing on the wire (the covertext is a fixed length either way) and
    reveals nothing.
    """
    plaintext = _LEN.pack(len(message)) + _SEQ.pack(seq) + message
    pad = cipher.max_plaintext_bytes - len(plaintext)
    if pad > 0:
        plaintext += os.urandom(pad)
    return cipher.encrypt(plaintext)


def _unseal(plaintext, seq):
    """Recover the message from a sealed plaintext, or ``None`` if it is
    malformed or was sealed at a stream position other than ``seq``."""
    if len(plaintext) < _SEAL_OVERHEAD:
        return None
    length = _LEN.unpack_from(plaintext)[0]
    if _SEQ.unpack_from(plaintext, _LEN.size)[0] != seq:
        return None
    if length > len(plaintext) - _SEAL_OVERHEAD:
        return None
    return plaintext[_SEAL_OVERHEAD:_SEAL_OVERHEAD + length]


class _PrefixedFormat:
    """The ``output_format`` view a :class:`LengthPrefixed` cipher presents.

    Callers that frame a fixed-length record -- the client's handshake read, the
    decoder's frame size -- ask a cipher's ``output_format`` how many bytes one
    covertext is. For a length-prefix format that is the message plus its
    prefix, so this reports the wire length while the cipher underneath keeps
    ranking messages.
    """

    def __init__(self, max_length):
        self.max_length = max_length


class LengthPrefixed:
    """A libfte cipher whose covertext goes on the wire behind a length prefix.

    The prefix is *framing*, not language. A format like ``dns`` is a two-byte
    big-endian length followed by that many bytes of message (RFC 1035 section
    4.2.2), and spelling that length as a literal inside the regex -- which is
    what ``dns`` did until F7b -- pins the format to exactly one covertext
    length, because a second length would need a second literal and therefore a
    second regex. Lifting the prefix out of the regex and into this wrapper is
    what lets one ``dns`` pattern serve every length in
    ``fteproxy.defs.spec_allowed_lengths``.

    So the regex describes the message alone, the wrapped cipher is built at the
    *message* length ``W - PREFIX_LEN``, and this class adds and removes the
    prefix. It presents the same surface a bare ``fte.FTE`` does --
    ``max_plaintext_bytes``, ``output_format.max_length``, ``encrypt`` and
    ``decrypt`` -- with lengths reported on the wire, so every path that already
    handled a fixed-length cipher (``_seal``, the handshake, a hybrid header)
    handles this one without knowing it exists.

    ``decrypt`` refuses a frame whose prefix disagrees with the bytes it was
    handed, raising the same :class:`fte.InvalidCovertextError` a failed tag
    raises, so a wrong prefix fails the stream closed rather than being
    reinterpreted.
    """

    def __init__(self, cipher):
        self._cipher = cipher
        #: Plaintext one message holds. The prefix costs wire bytes, never
        #: capacity: it is not ranked and carries nothing of ours.
        self.max_plaintext_bytes = cipher.max_plaintext_bytes
        #: Bytes of message behind the prefix.
        self.message_length = cipher.output_format.max_length
        self.output_format = _PrefixedFormat(self.message_length + PREFIX_LEN)

    def encrypt(self, plaintext):
        """One wire record: ``prefix(len(message)) || message``."""
        message = self._cipher.encrypt(plaintext)
        return _PREFIX.pack(len(message)) + message

    def decrypt(self, covertext):
        """The plaintext of one wire record, prefix included in ``covertext``."""
        if len(covertext) < PREFIX_LEN:
            raise fte.InvalidCovertextError(
                'covertext of %d bytes is shorter than the %d-byte length '
                'prefix' % (len(covertext), PREFIX_LEN))
        declared = _PREFIX.unpack_from(covertext)[0]
        message = covertext[PREFIX_LEN:]
        if declared != len(message):
            raise fte.InvalidCovertextError(
                'length prefix says %d bytes but %d follow'
                % (declared, len(message)))
        return self._cipher.decrypt(message)


#: Where a record's covertext length comes from. ``os.urandom``-backed, so the
#: length sequence is not predictable from earlier records and cannot be
#: replayed out of a seeded PRNG.
_LENGTHS = random.SystemRandom()


class VariableLength:
    """The lengths one variable-length format may emit, and the ciphers for them.

    A format-mode record is sealed with a *fixed-length* cipher, as it always
    was; what changes is that there is now more than one of them and the
    encoder chooses per record. ``ciphers`` maps each allowed **wire** length to
    the cipher that produces one covertext of that length --
    :func:`fteproxy._spec_cipher` builds them, so a ``length-prefix`` format's
    entries are :class:`LengthPrefixed` wrappers around a cipher two bytes
    shorter and the arithmetic here does not change.

    ``framing`` says how the decoder tells one covertext from the next:
    ``fteproxy.defs.FRAMING_TERMINATOR``, in which case ``terminator`` is the
    byte string every covertext ends with and that the format's language cannot
    produce anywhere else (enforced by ``fteproxy.defs.validate``), or
    ``FRAMING_LENGTH_PREFIX``, in which case the wire length is read off each
    record's own prefix and no terminator is involved.

    **Why the length is chosen here and not by libfte.** ``fte.RegexFormat``
    accepts a ``min_length``/``max_length`` pair and ranks the whole range, but
    a language's string count grows exponentially with length, so a uniformly
    random rank lands in the longest length class almost every time: a 64..512
    range would emit ~512-byte covertexts and the fingerprint would survive.
    The record layer therefore picks the length itself, from a small discrete
    set, and seals at exactly that length.

    One instance serves one direction of one connection: the per-length ciphers
    are built once here rather than per record, and the expensive half of each
    (the DFA) comes from the process-wide cache in
    :func:`fteproxy._regex_format`, so the ciphers themselves cost a few
    microseconds each and hold nothing beyond this connection's key.
    """

    def __init__(self, ciphers, terminator=None,
                 framing=fteproxy.defs.FRAMING_TERMINATOR):
        if not ciphers:
            raise ValueError('a variable-length format needs at least one length')
        if framing not in (fteproxy.defs.FRAMING_TERMINATOR,
                           fteproxy.defs.FRAMING_LENGTH_PREFIX):
            raise ValueError('%r is not a variable-length framing' % (framing,))
        if framing == fteproxy.defs.FRAMING_TERMINATOR and not terminator:
            raise ValueError('a terminator-framed format needs a terminator')
        self.framing = framing
        self.terminator = bytes(terminator) if terminator else None
        self.lengths = tuple(sorted(ciphers))
        self._ciphers = dict(ciphers)
        self.min_length = self.lengths[0]
        self.max_length = self.lengths[-1]
        #: Payload bytes one record of each length carries, after the seal's
        #: length/sequence fields and the record type byte.
        self.capacities = {
            length: (cipher.max_plaintext_bytes - _SEAL_OVERHEAD - _TYPE_LEN)
            for length, cipher in self._ciphers.items()}
        smallest = min(self.capacities.values())
        if smallest < 1:
            raise ValueError('a covertext length of this format carries no '
                             'payload (capacity %d)' % smallest)
        #: The largest payload any one record can carry.
        self.capacity = max(self.capacities.values())

    def cipher(self, length):
        """The fixed-length cipher for one allowed covertext length."""
        return self._ciphers[length]

    def choose_length(self, pending):
        """A covertext length for a record with ``pending`` payload bytes queued.

        Never shorter than the shortest length that holds ``pending`` bytes, so
        a record is never split just to make it look short. Beyond that the
        choice is random, weighted so that a stream's length histogram matches
        what it is carrying: when more data is queued than the largest record
        holds the weights favour the long lengths (a bulk transfer looks like
        long messages), and when the payload fits in one record they favour the
        short ones (interactive traffic looks like short messages). Throughput
        is not what the weighting is for -- the byte rate is nearly flat across
        a format's range, see PERFORMANCE.md -- realism is.

        The weights are quadratic rather than flat so the bias is visible in a
        histogram, and rather than exponential so no single length takes a
        commanding share -- an all-shortest stream would be as much of a
        fingerprint as an all-longest one.
        """
        if pending > self.capacity:
            eligible = self.lengths
            weights = [(rank + 1) ** 2 for rank in range(len(eligible))]
        else:
            eligible = tuple(length for length in self.lengths
                             if self.capacities[length] >= pending)
            weights = [(len(eligible) - rank) ** 2
                       for rank in range(len(eligible))]
        return _LENGTHS.choices(eligible, weights)[0]


class Encoder:

    def __init__(
        self,
        cipher,
        body_cipher=None,
        variable=None,
        hybrid_framing=fteproxy.defs.HYBRID_FRAMING_RAW,
    ):
        self._cipher = cipher
        self._body_cipher = body_cipher
        self._variable = variable
        self._hybrid_framing = hybrid_framing
        if hybrid_framing not in fteproxy.defs.HYBRID_FRAMINGS:
            raise ValueError('unknown hybrid body framing: %r'
                             % hybrid_framing)
        if body_cipher is None and \
                hybrid_framing != fteproxy.defs.HYBRID_FRAMING_RAW:
            raise ValueError('hybrid body framing needs a body cipher')
        if body_cipher is not None and variable is not None:
            raise ValueError('hybrid mode frames a fixed-length header; it '
                             'cannot also carry variable-length covertexts')
        if body_cipher is None:
            # 'format' mode: one sealed covertext per chunk. Reserve the length
            # prefix, sequence number and record type; the rest of the covertext
            # capacity is real payload, random-padded when the payload does not
            # fill it. With a variable-length format the capacity depends on the
            # length chosen for the record, and this is the largest of them: the
            # most any one record can carry, which is what bounds a control
            # record and what chunking measures itself against.
            self._capacity = (
                variable.capacity if variable is not None
                else cipher.max_plaintext_bytes - _SEAL_OVERHEAD - _TYPE_LEN)
        else:
            # 'hybrid' mode: a sealed FTE header (carrying the body length)
            # followed by the authenticated body and any carrier-native framing.
            # Chunk by the body's capacity, far larger than a covertext's, so bulk
            # data pays the DFA cost once per record instead of once per ~150
            # bytes. The type byte rides on top of the body rather than coming out
            # of the payload, so the chunk boundaries are unchanged.
            self._capacity = body_cipher.max_plaintext_bytes
        if self._capacity < 1:
            raise ValueError('format is too small to carry a record')
        self._buffer = b''
        self._seq = 0

    @property
    def capacity(self):
        """The largest payload one record of this stream can carry."""
        return self._capacity

    def _emit(self, record_type, payload, length=None):
        """One complete record on the wire, advancing the stream position.

        ``length`` names the covertext length to seal at, for a variable-length
        format whose caller has already chosen one (:meth:`pop` picks the length
        first, because the chunk size follows from it). Otherwise the length is
        chosen here, from the lengths that can carry this payload.
        """
        message = bytes((record_type,)) + payload
        if self._body_cipher is None:
            cipher = self._cipher
            if self._variable is not None:
                if length is None:
                    length = self._variable.choose_length(len(payload))
                cipher = self._variable.cipher(length)
            record = _seal(cipher, message, self._seq)
        else:
            body = self._body_cipher.encrypt(message, self._seq)
            body_prefix, body_suffix = _hybrid_body_parts(
                self._hybrid_framing, len(body))
            record = (_seal(self._cipher, _OVERFLOW_LEN.pack(len(body)),
                            self._seq)
                      + body_prefix + body + body_suffix)
        self._seq += 1
        return record

    def encode(self, record_type, payload=b''):
        """Encode one record of any type. Control messages go out this way;
        :meth:`pop` is the bulk path for :data:`DATA`."""
        if record_type not in RECORD_TYPES:
            raise ValueError('unknown record type: %r' % (record_type,))
        if len(payload) > self._capacity:
            raise ValueError('payload of %d bytes exceeds the %d-byte record '
                             'capacity' % (len(payload), self._capacity))
        return self._emit(record_type, payload)

    def push(self, data):
        """Push data onto the FIFO buffer."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data

    def pop(self):
        """Pop the whole buffer, sliced into capacity-sized chunks and encrypted
        into one :data:`DATA` record each with the ``cipher`` (and, in hybrid
        mode, the ``body_cipher``) from ``__init__``.
        """
        buffer = self._buffer
        if not buffer:
            return b''

        # Encrypt each ``self._capacity`` slice via a moving offset and join the
        # records once at the end. Slicing the head off ``self._buffer`` inside
        # the loop instead would recopy the whole remaining buffer every
        # iteration, making a single large ``push`` quadratic.
        records = []
        if self._variable is None:
            for offset in range(0, len(buffer), self._capacity):
                records.append(
                    self._emit(DATA, buffer[offset:offset + self._capacity]))
        else:
            # A variable-length format chunks by the length it picked for this
            # record, not by one fixed capacity: pick the length from what is
            # still queued (so a long queue biases long), then fill it.
            offset = 0
            while offset < len(buffer):
                pending = len(buffer) - offset
                length = self._variable.choose_length(pending)
                take = min(self._variable.capacities[length], pending)
                records.append(self._emit(DATA, buffer[offset:offset + take],
                                          length=length))
                offset += take

        self._buffer = b''
        return b''.join(records)


class Decoder:

    def __init__(
        self,
        cipher,
        body_cipher=None,
        variable=None,
        hybrid_framing=fteproxy.defs.HYBRID_FRAMING_RAW,
    ):
        self._cipher = cipher
        self._body_cipher = body_cipher
        self._variable = variable
        self._hybrid_framing = hybrid_framing
        if hybrid_framing not in fteproxy.defs.HYBRID_FRAMINGS:
            raise ValueError('unknown hybrid body framing: %r'
                             % hybrid_framing)
        if body_cipher is None and \
                hybrid_framing != fteproxy.defs.HYBRID_FRAMING_RAW:
            raise ValueError('hybrid body framing needs a body cipher')
        if body_cipher is not None and variable is not None:
            raise ValueError('hybrid mode frames a fixed-length header; it '
                             'cannot also carry variable-length covertexts')
        # A fixed-length output format emits one covertext of exactly
        # ``max_length`` bytes, and ``decrypt`` consumes exactly one such value
        # (no remainder). The record layer frames the byte stream itself: in
        # 'format' mode a record is that one covertext; in 'hybrid' mode it is
        # the header covertext plus the ``body_len`` authenticated bytes and any
        # carrier framing around them. Either way a trailing partial record stays
        # buffered.
        self._frame_size = cipher.output_format.max_length
        # The largest record this decoder is ever asked to hold: one header
        # covertext plus, in hybrid mode, the largest framed body a header may
        # announce; for a variable-length format, one covertext of its longest
        # allowed length. After every pop the buffer is shorter than this, so a
        # stream that fails to authenticate cannot grow the buffer without
        # bound (see the fail-closed behavior below).
        if variable is not None:
            self.max_record_bytes = variable.max_length
        else:
            self.max_record_bytes = self._frame_size + (
                _hybrid_wire_body_len(hybrid_framing,
                                      body_cipher.max_framed_bytes)
                if body_cipher is not None else 0)
        self._buffer = b''
        self._seq = 0
        # Set once a record fails to authenticate: nothing later can decode,
        # since the sequence number cannot advance past the bad record, so the
        # stream is dead and push refuses further input.
        self._failed = False
        # Body length from a hybrid header that was decrypted and verified but
        # whose body had not fully arrived. While set, that header is the first
        # ``_frame_size`` bytes of ``_buffer`` (the buffer only grows).
        self._pending_body_len = None

    @property
    def failed(self):
        """Whether a record failed to authenticate and the stream is dead."""
        return self._failed

    def push(self, data):
        """Push data onto the FIFO buffer.

        Raises :class:`StreamFailedError` once the stream has failed: nothing
        pushed after a bad record could decode, and buffering it would let a
        peer that holds the keys grow the buffer without bound.
        """
        if self._failed:
            raise StreamFailedError('data pushed after a record failed to '
                                    'authenticate')
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._buffer += data

    def _decrypt(self, cipher, covertext):
        """Decrypt one covertext, mapping libfte errors to fteproxy semantics.

        Returns the plaintext, or ``None`` if the frame is not (yet) decodable
        and the caller should stop draining and keep it buffered.
        """
        try:
            return cipher.decrypt(covertext)
        except fte.FormatContractError:
            # The format provider broke the RankedFormat contract: a bug in the
            # format, not bad input, so no frame can be trusted. Keep libfte
            # 0.3's UnrecoverableDecryptionError semantics by propagating it to
            # the embedding application. Library code must never terminate its
            # process; the CLI may translate the exception at its boundary.
            # (In 0.4, decrypt never raises MessageTooLargeError; that is an
            # encrypt-side limit. A corrupt or oversized covertext is the
            # InvalidCovertextError below.)
            raise
        except fte.InvalidCovertextError as e:
            # A corrupt, wrong-format, or failed-MAC frame. The server's
            # first-record scan relies on this to fall through to the next
            # candidate format.
            fteproxy.debug("fteproxy.record_layer.InvalidCovertextError: "+str(e))
            return None
        except fte.FTEError as e:
            fteproxy.warn("fteproxy.record_layer exception: "+str(e))
            return None

    @staticmethod
    def _split_type(message):
        """``type || payload`` -> ``(type, payload)``, checking the type."""
        if not message:
            raise UnknownRecordType('empty record')
        record_type = message[0]
        if record_type not in RECORD_TYPES:
            raise UnknownRecordType('record type 0x%02x' % record_type)
        return record_type, message[1:]

    def pop_records(self, limit=None):
        """Pop decoded records off the FIFO buffer as ``(type, payload)``.

        Stops at ``limit`` records, or when the next record is incomplete or
        undecodable. Raises :class:`UnknownRecordType` for an authenticated
        record this version does not define; the caller closes the connection.
        """

        # Consume whole records from a local buffer and collect the messages,
        # writing ``self._buffer`` back once. The offset never advances past a
        # record that cannot (yet) be decoded, so the undecodable remainder is
        # preserved.
        if self._failed:
            return []
        if self._variable is not None:
            if self._variable.framing == fteproxy.defs.FRAMING_LENGTH_PREFIX:
                return self._pop_length_prefixed_records(limit)
            return self._pop_variable_records(limit)
        buffer = self._buffer
        records = []
        offset = 0

        while len(buffer) - offset >= self._frame_size:
            if limit is not None and len(records) >= limit:
                break
            if self._body_cipher is not None and self._pending_body_len is not None:
                # The header at the front of the buffer was decrypted and
                # verified on an earlier pop whose body had not fully arrived.
                # A large record arrives over several reads, so do not rank
                # and verify the same header again for each partial delivery.
                body_len = self._pending_body_len
            else:
                header = buffer[offset:offset + self._frame_size]
                head = self._decrypt(self._cipher, header)
                if head is None:
                    self._failed = True
                    break
                head = _unseal(head, self._seq)
                if head is None:
                    # Authenticated but not a sealed record at this stream
                    # position: a peer on a different mode, corruption, or a
                    # record replayed, reordered, or dropped. Treat it as
                    # undecodable.
                    fteproxy.debug(
                        "fteproxy.record_layer: malformed or out-of-order sealed "
                        "record at seq " + str(self._seq))
                    self._failed = True
                    break

                if self._body_cipher is None:
                    # 'format' mode: the sealed covertext carried the message.
                    self._seq += 1
                    offset += self._frame_size
                    records.append(self._split_type(head))
                    continue

                # 'hybrid' mode: the header carries the authenticated body's
                # length, excluding protocol framing. A successful header
                # decrypt means we wrote it and the length is trustworthy.
                if len(head) != _OVERFLOW_LEN.size:
                    fteproxy.debug(
                        "fteproxy.record_layer: unexpected header width "
                        + str(len(head)))
                    self._failed = True
                    break
                body_len = _OVERFLOW_LEN.unpack(head)[0]
                if body_len > self._body_cipher.max_framed_bytes:
                    # The header authenticates, so only a key holder can send
                    # this, but never buffer up to 4 GiB on its say-so.
                    fteproxy.info(
                        "fteproxy.record_layer: body length " + str(body_len)
                        + " exceeds the record limit")
                    self._failed = True
                    break

            header_end = offset + self._frame_size
            body_prefix, body_suffix = _hybrid_body_parts(
                self._hybrid_framing, body_len)

            # The header's authenticated body length uniquely determines the
            # HTTP chunk-size line.  Reject a mismatching line as soon as the
            # bytes that arrived disagree, rather than accepting two competing
            # lengths or searching forward for a plausible boundary.
            prefix_available = min(len(body_prefix), len(buffer) - header_end)
            if buffer[header_end:header_end + prefix_available] != \
                    body_prefix[:prefix_available]:
                fteproxy.debug(
                    "fteproxy.record_layer: invalid hybrid body prefix at seq "
                    + str(self._seq))
                self._failed = True
                break

            body_start = header_end + len(body_prefix)
            body_end = body_start + body_len
            record_end = body_end + len(body_suffix)
            if len(buffer) < record_end:
                # Body not fully arrived; wait for more data. The write-back
                # below leaves this header at the front of the buffer.
                self._pending_body_len = body_len
                break
            if buffer[body_end:record_end] != body_suffix:
                fteproxy.debug(
                    "fteproxy.record_layer: invalid hybrid body suffix at seq "
                    + str(self._seq))
                self._failed = True
                break
            self._pending_body_len = None
            body = buffer[body_start:body_end]
            try:
                message = self._body_cipher.decrypt(body, self._seq)
            except InvalidTag:
                # Wrong key, corruption, or a record out of its stream
                # position (reorder/drop/replay). Stop draining.
                fteproxy.debug(
                    "fteproxy.record_layer: body auth failed at seq "
                    + str(self._seq))
                self._failed = True
                break
            self._seq += 1
            offset = record_end
            records.append(self._split_type(message))

        self._buffer = b'' if self._failed else buffer[offset:]
        return records

    def _pop_variable_records(self, limit=None):
        """:meth:`pop_records` for a variable-length format: terminator framing.

        A record runs to the end of the next terminator. Its length must be one
        the format emits -- anything else is not a covertext this peer wrote, so
        the stream fails closed exactly as a bad decrypt does, rather than
        hunting for a later terminator that might line up.

        Every other guarantee is the fixed-length path's: the seal must unseal
        at the current sequence number, any authentication failure is fatal to
        the stream, and the buffer is bounded -- here by refusing to hold more
        than one longest covertext without a terminator, so a peer cannot grow
        it by simply never sending one.
        """
        buffer = self._buffer
        terminator = self._variable.terminator
        records = []
        offset = 0

        while True:
            if limit is not None and len(records) >= limit:
                break
            end = buffer.find(terminator, offset)
            if end < 0:
                if len(buffer) - offset > self._variable.max_length:
                    fteproxy.info(
                        "fteproxy.record_layer: %d bytes with no covertext "
                        "terminator, more than the %d-byte maximum"
                        % (len(buffer) - offset, self._variable.max_length))
                    self._failed = True
                # Otherwise: a partial covertext, still arriving. Wait.
                break
            end += len(terminator)
            length = end - offset
            if length not in self._variable.lengths:
                fteproxy.debug(
                    "fteproxy.record_layer: covertext of %d bytes is not a "
                    "length this format emits" % length)
                self._failed = True
                break
            plaintext = self._decrypt(self._variable.cipher(length),
                                      buffer[offset:end])
            if plaintext is None:
                self._failed = True
                break
            message = _unseal(plaintext, self._seq)
            if message is None:
                fteproxy.debug(
                    "fteproxy.record_layer: malformed or out-of-order sealed "
                    "record at seq " + str(self._seq))
                self._failed = True
                break
            self._seq += 1
            offset = end
            records.append(self._split_type(message))

        self._buffer = b'' if self._failed else buffer[offset:]
        return records

    def _pop_length_prefixed_records(self, limit=None):
        """:meth:`pop_records` for a ``length-prefix`` format.

        A record is a two-byte big-endian message length followed by that many
        bytes (RFC 1035 4.2.2). The prefix is not authenticated -- nothing on the
        wire is until the covertext decrypts -- so the *only* thing it is
        trusted for is which of the format's ciphers to try, and it is checked
        against :attr:`VariableLength.lengths` before a single byte is waited
        for. A prefix naming any other length is a peer that did not write this
        stream, so it fails the stream closed **immediately** rather than
        waiting: a 65535-byte prefix is a protocol violation, not a large record
        still arriving, and treating it as the latter is how a decoder is talked
        into buffering on a stranger's say-so.

        That check is also the buffer bound this framing needs. The terminator
        path has to impose one (a peer can simply never send a terminator);
        here, every record announces its own size up front, so the buffer never
        holds more than one longest covertext without either producing a record
        or failing.

        Every other guarantee is the fixed-length path's: the covertext must
        decrypt, the seal must unseal at the current sequence number, and any
        authentication failure is fatal to the stream.
        """
        buffer = self._buffer
        records = []
        offset = 0

        while True:
            if limit is not None and len(records) >= limit:
                break
            if len(buffer) - offset < PREFIX_LEN:
                break                       # not even a prefix yet; wait
            declared = _PREFIX.unpack_from(buffer, offset)[0]
            length = declared + PREFIX_LEN
            if length not in self._variable.lengths:
                fteproxy.debug(
                    "fteproxy.record_layer: length prefix announces a %d-byte "
                    "covertext, which is not a length this format emits"
                    % length)
                self._failed = True
                break
            if len(buffer) - offset < length:
                break                       # message still arriving; wait
            end = offset + length
            plaintext = self._decrypt(self._variable.cipher(length),
                                      buffer[offset:end])
            if plaintext is None:
                self._failed = True
                break
            message = _unseal(plaintext, self._seq)
            if message is None:
                fteproxy.debug(
                    "fteproxy.record_layer: malformed or out-of-order sealed "
                    "record at seq " + str(self._seq))
                self._failed = True
                break
            self._seq += 1
            offset = end
            records.append(self._split_type(message))

        self._buffer = b'' if self._failed else buffer[offset:]
        return records

    def pop(self, limit=None):
        """The :data:`DATA` payloads from :meth:`pop_records`, concatenated.

        For callers that carry nothing but application bytes. A control record
        raises, because silently dropping one would lose a stream's OPEN or its
        half-close.
        """
        records = self.pop_records(limit=limit)
        for record_type, _payload in records:
            if record_type != DATA:
                raise UnknownRecordType(
                    'unexpected control record 0x%02x on a data-only stream'
                    % record_type)
        return b''.join(payload for _type, payload in records)
