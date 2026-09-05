#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Frame authenticated records over a TCP byte stream.

Every FTE plaintext is message_length(4) || sequence(8) || message || random
padding to cipher capacity. Format mode carries type(1) || payload in that
seal. Hybrid mode seals a four-byte body length and follows it with an
authenticated encrypted type/payload body, optionally in HTTP chunk framing.

Variable format-mode records use either a unique terminator or an external
two-byte message-length prefix. The regex excludes that prefix. Handshakes use
maximum-length covertexts; hybrid headers use the shortest capable length.

Each session direction has its own keys and sequence counter. Framing, seal,
or authentication failures are terminal; incomplete frames wait for more bytes.
See docs/format-authoring.md and SECURITY.md for the wire and security model.
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
# Sequence number binds a record to its stream position in both modes.
# A gap is detected when a later record arrives; EOF alone cannot prove completeness.
_SEQ = struct.Struct('>Q')
_SEAL_OVERHEAD = _LEN.size + _SEQ.size
# The record type byte that leads every message.
_TYPE_LEN = 1
# Hybrid-mode header payload: the length of the authenticated body that follows
# it, excluding any protocol framing around that body.
_OVERFLOW_LEN = struct.Struct('>I')

# Minimum hybrid-header capacity: 12-byte seal plus four-byte body length.
# _seal pads this 16-byte structure to the chosen cipher's full capacity.
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
    """An authenticated record has an empty or unknown type; callers must close.

    This can indicate a version mismatch or a malformed record from a key holder.
    """


class StreamFailedError(Exception):
    """Data was pushed into a :class:`Decoder` after one of its records
    failed authentication. The stream cannot resume; close the connection."""


def _seal(cipher, message, seq):
    """Seal message length, sequence, and message, padding to cipher capacity.

    Padding avoids systematic low-rank prefixes from short unpadded messages.
    It does not promise uniform sampling of the regex's entire language.
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
    """Wrap a fixed-length cipher with a two-byte big-endian message prefix.

    The regex describes only the message. output_format.max_length reports message
    plus prefix, while max_plaintext_bytes remains the underlying cipher capacity.
    decrypt rejects a prefix that disagrees with the supplied frame length.
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


# System randomness for the payload-dependent length-selection heuristic.
_LENGTHS = random.SystemRandom()


class VariableLength:
    """Per-direction ciphers keyed by allowed wire length.

    Format mode chooses a length before encrypting, rather than ranking across a
    whole range that would favor its largest language classes. Framing uses a
    terminator or a two-byte prefix; each length must carry at least one DATA byte.
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
        """Choose a wire length using quadratic weights based on pending payload.

        If pending fits one record, use only capable lengths and favor shorter ones.
        For larger queues, permit every length and favor longer ones; the caller chunks
        to the chosen capacity. This is a heuristic, not a real-protocol distribution.
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
            # Format mode reserves the seal and type byte from cipher capacity.
            # Variable formats use this maximum to bound control records; DATA chunks
            # use the capacity of each chosen length.
            self._capacity = (
                variable.capacity if variable is not None
                else cipher.max_plaintext_bytes - _SEAL_OVERHEAD - _TYPE_LEN)
        else:
            # Hybrid mode chunks by body capacity. The type byte is additional to the
            # payload limit, and carrier framing surrounds the encrypted body.
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
        """Drain buffered data into encrypted DATA records, chunked by capacity.

        Variable formats choose a length and its corresponding capacity for each chunk.
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
        # Maximum size of an incomplete record retained after draining.
        # push() can accept more; pop_records() checks bounds and fails bad frames.
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
        """Whether framing, seal, or authentication failure made the stream unusable."""
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
        """Return authenticated plaintext, or None for an invalid covertext.

        Callers treat None as terminal failure. FormatContractError propagates because
        it indicates a provider contract violation rather than ordinary bad input.
        """
        try:
            return cipher.decrypt(covertext)
        except fte.FormatContractError:
            # Provider contract violations propagate to the caller; they indicate a
            # format implementation bug rather than an ordinary invalid covertext.
            raise
        except fte.InvalidCovertextError as e:
            # A corrupt, wrong-format, or unauthenticated frame fails the stream.
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
        """Return complete (type, payload) records, stopping after limit if supplied.

        Retain incomplete frames. Framing, seal, or authentication failure sets failed
        and discards the remainder. UnknownRecordType requires the caller to close.
        """

        # Drain complete records using an offset, then update the buffer once.
        # Preserve incomplete records; terminal failures discard the remainder.
        if self._failed:
            return []
        if self._variable is not None:
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
                    # The seal is invalid for this stream position; fail without resynchronizing.
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

                # Hybrid headers authenticate the body length, excluding carrier framing.
                # The peer may hold valid keys, so the length still needs a resource bound.
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

    def _terminated_frame_end(self, buffer, offset):
        """Return the end of the next terminator frame, or None to stop.

        An unlisted length or an unterminated remainder beyond max_length fails the
        stream. The buffer bound is checked here, after push has accepted input.
        """
        terminator = self._variable.terminator
        end = buffer.find(terminator, offset)
        if end < 0:
            if len(buffer) - offset > self._variable.max_length:
                fteproxy.info(
                    "fteproxy.record_layer: %d bytes with no covertext "
                    "terminator, more than the %d-byte maximum"
                    % (len(buffer) - offset, self._variable.max_length))
                self._failed = True
            # Otherwise: a partial covertext, still arriving. Wait.
            return None
        end += len(terminator)
        length = end - offset
        if length not in self._variable.lengths:
            fteproxy.debug(
                "fteproxy.record_layer: covertext of %d bytes is not a "
                "length this format emits" % length)
            self._failed = True
            return None
        return end

    def _length_prefixed_frame_end(self, buffer, offset):
        """Return a complete prefixed frame's end, or None to wait/fail.

        Require declared length plus the prefix width to be allowed before waiting for
        the body. The unauthenticated prefix selects a cipher, not trusted plaintext.
        """
        if len(buffer) - offset < PREFIX_LEN:
            return None                     # not even a prefix yet; wait
        declared = _PREFIX.unpack_from(buffer, offset)[0]
        length = declared + PREFIX_LEN
        if length not in self._variable.lengths:
            fteproxy.debug(
                "fteproxy.record_layer: length prefix announces a %d-byte "
                "covertext, which is not a length this format emits"
                % length)
            self._failed = True
            return None
        if len(buffer) - offset < length:
            return None                     # message still arriving; wait
        return offset + length

    def _pop_variable_records(self, limit=None):
        """Decode either variable-length framing with the same stream checks.

        The boundary finder validates and bounds each frame. Decryption, stream
        position and record types are checked here, leaving any partial frame
        buffered and discarding the remainder after an authentication failure.
        """
        frame_end = (self._length_prefixed_frame_end
                     if self._variable.framing == fteproxy.defs.FRAMING_LENGTH_PREFIX
                     else self._terminated_frame_end)
        buffer = self._buffer
        records = []
        offset = 0

        while True:
            if limit is not None and len(records) >= limit:
                break
            end = frame_end(buffer, offset)
            if end is None:
                break
            length = end - offset
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
