"""Authenticated bootstrap by permuting a batch of complete covertexts.

The sender supplies an exchangeable batch of 320 fixed-width words.  The
words are left byte-for-byte intact and only their order is changed.  The
permutation rank carries a fixed-size authenticated description, so the
receiver can discover the word width without knowing the sender's format.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import struct
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ffx import FF1


BATCH_WORDS = 320
ENVELOPE_BYTES = 256
MAX_DESCRIPTION = 226
MAX_WORD_BYTES = 512
_SCAN_BYTES = BATCH_WORDS * MAX_WORD_BYTES
_ENVELOPE_BITS = ENVELOPE_BYTES * 8
_PREFIX = b"fteproxy/permutation-bootstrap/v1/"
_U32 = struct.Struct(">I")


class BootstrapError(ValueError):
    """The bootstrap is malformed, unauthenticated, or exceeds a limit."""


@dataclass(frozen=True)
class BootstrapResult:
    """Authenticated bootstrap metadata and bytes following its prefix."""

    description: bytes
    word_bytes: int
    transcript_digest: bytes
    remainder: bytes


def _bytes(value: object, name: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise BootstrapError(f"{name} must be bytes-like")


def _derive(key: bytes, label: bytes) -> bytes:
    return hmac.digest(key, _PREFIX + label, "sha256")


def _aad(fmt: "Multiset", width: int) -> bytes:
    digest = hashlib.sha256()
    digest.update(_PREFIX)
    digest.update(struct.pack(">III", width, BATCH_WORDS, len(fmt.alphabet)))
    for symbol, count in zip(fmt.alphabet, fmt.counts):
        digest.update(symbol)
        digest.update(_U32.pack(count))
    return digest.digest()


def _validate_key(key: object) -> bytes:
    key = _bytes(key, "key")
    if len(key) != 32:
        raise BootstrapError("key must be exactly 32 bytes")
    return key


def _word_sequence(words: Sequence[bytes] | Iterable[bytes]) -> tuple[bytes, ...]:
    """Materialize at most one item past the public batch bound."""
    try:
        iterator = iter(words)
    except TypeError as exc:
        raise BootstrapError("words must be an iterable of bytes") from exc
    result = []
    for _ in range(BATCH_WORDS + 1):
        try:
            result.append(_bytes(next(iterator), "word"))
        except StopIteration:
            return tuple(result)
    raise BootstrapError(f"exactly {BATCH_WORDS} words are required")


class Multiset:
    """Lexicographic rank space for a fixed-width multiset permutation."""

    def __init__(self, data: bytes, width: int):
        data = _bytes(data, "data")
        if type(width) is not int or not 1 <= width <= MAX_WORD_BYTES:
            raise BootstrapError("word width is outside the supported range")
        if not data or len(data) % width:
            raise BootstrapError("multiset data has the wrong size")
        symbols = tuple(data[offset:offset + width]
                        for offset in range(0, len(data), width))
        counts = Counter(symbols)
        self.width = width
        self.size = len(symbols)
        self.alphabet = tuple(sorted(counts))
        self.counts = tuple(counts[symbol] for symbol in self.alphabet)
        self.cardinality = math.factorial(self.size)
        for count in self.counts:
            self.cardinality //= math.factorial(count)
        self._indexes = {symbol: index for index, symbol in enumerate(self.alphabet)}

    def rank(self, data: bytes) -> int:
        """Return the lexicographic rank of ``data`` in this multiset."""
        data = _bytes(data, "data")
        if len(data) != self.size * self.width:
            raise BootstrapError("rank data has the wrong size")
        counts = list(self.counts)
        ways = self.cardinality
        rank = 0
        remaining = self.size
        for offset in range(0, len(data), self.width):
            symbol = data[offset:offset + self.width]
            try:
                index = self._indexes[symbol]
            except KeyError as exc:
                raise BootstrapError("rank data is outside the multiset") from exc
            smaller = sum(counts[:index])
            rank += ways * smaller // remaining
            count = counts[index]
            if count == 0:
                raise BootstrapError("rank data has the wrong multiplicities")
            ways = ways * count // remaining
            counts[index] -= 1
            remaining -= 1
        if remaining or any(counts):
            raise BootstrapError("rank data has the wrong multiplicities")
        return rank

    def unrank(self, index: int) -> bytes:
        """Return the lexicographically indexed permutation."""
        if not isinstance(index, int) or not 0 <= index < self.cardinality:
            raise BootstrapError("rank outside multiset domain")
        counts = list(self.counts)
        ways = self.cardinality
        output = []
        for remaining in range(self.size, 0, -1):
            for slot, count in enumerate(counts):
                if not count:
                    continue
                block = ways * count // remaining
                if index < block:
                    output.append(self.alphabet[slot])
                    ways = block
                    counts[slot] -= 1
                    break
                index -= block
            else:  # pragma: no cover - guarded by the domain check above
                raise BootstrapError("invalid multiset rank")
        return b"".join(output)


def _encode_envelope(key: bytes, fmt: Multiset, width: int,
                     description: bytes) -> int:
    aad = _aad(fmt, width)
    plaintext = (len(description).to_bytes(2, "big") + description
                 + secrets.token_bytes(MAX_DESCRIPTION - len(description)))
    nonce = secrets.token_bytes(12)
    encrypted = ChaCha20Poly1305(_derive(key, b"aead")).encrypt(
        nonce, plaintext, aad)
    envelope = nonce + encrypted
    if len(envelope) != ENVELOPE_BYTES:  # pragma: no cover - construction invariant
        raise BootstrapError("internal envelope size error")
    return FF1(_derive(key, b"ff1")).encrypt_int(
        int.from_bytes(envelope, "big"), domain=fmt.cardinality, tweak=aad)


def encode(key: bytes, words: Sequence[bytes], description: bytes) -> bytes:
    """Encode ``description`` in the order of the supplied covertext words."""
    key = _validate_key(key)
    description = _bytes(description, "description")
    if len(description) > MAX_DESCRIPTION:
        raise BootstrapError("description is too long")
    values = _word_sequence(words)
    if len(values) != BATCH_WORDS:
        raise BootstrapError(f"exactly {BATCH_WORDS} words are required")
    width = len(values[0])
    if not 1 <= width <= MAX_WORD_BYTES:
        raise BootstrapError("word width is outside the supported range")
    if any(len(word) != width for word in values):
        raise BootstrapError("all words must have the same nonzero width")
    fmt = Multiset(b"".join(values), width)
    if fmt.cardinality < 1 << _ENVELOPE_BITS:
        raise BootstrapError("insufficient permutation capacity")
    rank = _encode_envelope(key, fmt, width, description)
    return fmt.unrank(rank)


def _decode_candidate(key: bytes, candidate: bytes, width: int,
                      ff1: FF1, aead: ChaCha20Poly1305) -> bytes | None:
    try:
        fmt = Multiset(candidate, width)
    except BootstrapError:
        return None
    if fmt.cardinality < 1 << _ENVELOPE_BITS:
        return None
    aad = _aad(fmt, width)
    try:
        rank = ff1.decrypt_int(fmt.rank(candidate), domain=fmt.cardinality,
                               tweak=aad)
    except (ValueError, OverflowError):
        return None
    if rank.bit_length() > _ENVELOPE_BITS:
        return None
    envelope = rank.to_bytes(ENVELOPE_BYTES, "big")
    try:
        plaintext = aead.decrypt(envelope[:12], envelope[12:], aad)
    except InvalidTag:
        return None
    if len(plaintext) != 2 + MAX_DESCRIPTION:
        return None
    description_size = int.from_bytes(plaintext[:2], "big")
    if description_size > MAX_DESCRIPTION:
        return None
    return plaintext[2:2 + description_size]


class Decoder:
    """Incrementally discover a bootstrap and preserve following bytes."""

    def __init__(self, key: bytes):
        self.key = _validate_key(key)
        self._buffer = bytearray()
        self._next_width = 1
        self.attempts = 0
        self._done = False
        self.remainder = b""
        self._ff1 = FF1(_derive(self.key, b"ff1"))
        self._aead = ChaCha20Poly1305(_derive(self.key, b"aead"))

    def feed(self, data: bytes) -> BootstrapResult | None:
        """Add bytes and return the authenticated result when a width matches."""
        if self._done:
            raise BootstrapError("bootstrap has already been decoded")
        data = _bytes(data, "data")
        room = _SCAN_BYTES - len(self._buffer)
        if room < 0:  # pragma: no cover - only possible after an internal bug
            raise BootstrapError("bootstrap scan limit exceeded")
        retained = data[:room]
        trailing = data[room:]
        self._buffer.extend(retained)

        while (self._next_width <= MAX_WORD_BYTES
               and len(self._buffer) >= self._next_width * BATCH_WORDS):
            width = self._next_width
            self._next_width += 1
            self.attempts += 1
            end = width * BATCH_WORDS
            candidate = bytes(self._buffer[:end])
            description = _decode_candidate(
                self.key, candidate, width, self._ff1, self._aead)
            if description is not None:
                self._done = True
                remainder = bytes(self._buffer[end:]) + trailing
                self.remainder = remainder
                return BootstrapResult(
                    description=description,
                    word_bytes=width,
                    transcript_digest=hashlib.sha256(candidate).digest(),
                    remainder=remainder,
                )

        if len(self._buffer) >= _SCAN_BYTES or trailing:
            raise BootstrapError("no authenticated bootstrap within scan limit")
        return None


__all__ = [
    "BATCH_WORDS",
    "ENVELOPE_BYTES",
    "MAX_DESCRIPTION",
    "MAX_WORD_BYTES",
    "BootstrapError",
    "BootstrapResult",
    "Decoder",
    "Multiset",
    "encode",
]
