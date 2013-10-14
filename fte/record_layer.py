#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of FTE.
#
# FTE is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# FTE is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.

import random
import time
import fte.encrypter
LOG_LEVEL = fte.conf.getValue('loglevel.fte.record_layer')
MAX_CELL_SIZE = \
    fte.conf.getValue('runtime.fte.record_layer.max_cell_size')


class PopFailedException(Exception):

    pass


class FatalPopFailedException(Exception):

    pass


class NotEngoughCapacityException(Exception):

    pass


class EndOfStreamException(Exception):

    datagram = ''


class RecordLayerEncoder:

    def __init__(
        self,
        stream_id,
        lock,
        encrypter,
        encoder,
    ):
        self.stream_id = stream_id
        self.lock = lock
        self.incoming = ''
        self.outgoing = None
        self.outgoing_bits = 0
        self.bytes_pushed = 0
        self.last_pushed = time.time()
        self.encrypter = encrypter
        self.encoder = encoder
        self.noop_mode = False
        self.to_send = ''
        self.stream_index = 0
        self.sequence_counter = 0

    def determinePartition(self, msg):
        return self.encoder.determinePartition(msg)

    def extractStreamId(self, data):
        assert False

    def waitingFor(self):
        return -1

    def push(self, data):
        self.bytes_pushed += len(data)
        self.last_pushed = time.time()
        self.incoming += data

    def bufferEmpty(self):
        return len(self.incoming) == 0 and self.outgoing_bits <= 0

    def wantsMoreData(self):
        return fte.conf.getValue('runtime.fte.record_layer.max_cell_size'
                                 ) > len(self.incoming)

    def pop(self):
        try:
            covertext_payload_len = \
                self.encoder.getNextTemplateCapacity(None)
            if fte.conf.getValue('runtime.http_proxy.enable'):
                covertext_payload_len -= \
                    self.encrypter.COVERTEXT_HEADER_ENC_LENGTH * 4
            if self.outgoing_bits <= 0:
                if len(self.incoming) == 0:
                    self.noop_mode = True
                    return ['', False, self.noop_mode]
                else:
                    self.noop_mode = False
                    tmp = self.incoming[:MAX_CELL_SIZE]
                    self.incoming = self.incoming[MAX_CELL_SIZE:]
                fte.logger.debug(LOG_LEVEL, (self.stream_id,
                                 'PRE-ENCRYPTED', tmp))
                self.outgoing = self.encrypter.encrypt(tmp)
                fte.logger.debug(
                    LOG_LEVEL, (
                        self.stream_id, 'ENCRYPTED', len(
                            hex(self.outgoing)),
                        hex(self.outgoing)))
                self.outgoing_bits = \
                    fte.encrypter.Encrypter.CTXT_EXPANSION_BITS \
                    + len(tmp) * 8
            if fte.conf.getValue('runtime.http_proxy.enable'):
                if self.outgoing_bits > covertext_payload_len:
                    covertext_payload = self.outgoing \
                        >> self.outgoing_bits - covertext_payload_len
                else:
                    padding_length = covertext_payload_len \
                        - self.outgoing_bits
                    if padding_length > 0:
                        covertext_payload = self.outgoing \
                            << padding_length
                        covertext_payload += random.randint(0, (1
                                                                << padding_length) - 1)
                    else:
                        covertext_payload = self.outgoing
                covertext_header = (self.stream_id << 16) \
                    + self.sequence_counter
                self.sequence_counter += 1
                covertext_header = \
                    self.encrypter.encryptCovertextHeader(covertext_header,
                                                          covertext_payload_len, covertext_payload)
                retval = self.encoder.encode(covertext_payload_len
                                             +
                                             self.encrypter.COVERTEXT_HEADER_ENC_LENGTH
                                             * 4, (covertext_header
                                                   << covertext_payload_len) + covertext_payload,
                                             partition)
            else:
                min_payload_len = self.encoder.capacity
                padding_length = min_payload_len - self.outgoing_bits
                if padding_length > 0:
                    self.outgoing = self.outgoing << padding_length
                    self.outgoing += random.randint(0, (1
                                                        << padding_length) - 1)
                    self.outgoing_bits += padding_length
                retval = self.encoder.encode(self.outgoing_bits,
                                             self.outgoing, None)
                covertext_payload_len = retval[1]
            fte.logger.debug(LOG_LEVEL, (self.stream_id, 'ENCODED',
                             [retval[0]]))
            if self.outgoing_bits - covertext_payload_len > 0:
                self.outgoing = \
                    fte.bit_ops.grab_slice(self.outgoing_bits
                                           - covertext_payload_len, 0, self.outgoing)
                self.outgoing_bits -= covertext_payload_len
            else:
                self.outgoing = None
                self.outgoing_bits = 0
            return [retval[0], not self.bufferEmpty(), self.noop_mode]
        except NotEngoughCapacityException:
            covertext_payload_len = \
                self.encoder.getNextTemplateCapacity(partition)
            X = random.randint(0, (1 << covertext_payload_len) - 1)
            retval = self.encoder.encode(covertext_payload_len, X,
                                         partition)
            return [retval[0], not self.bufferEmpty(), self.noop_mode]


class RecordLayerDecoder:

    def __init__(
        self,
        stream_id,
        lock,
        encrypter,
        encoder,
    ):
        self.stream_id = stream_id
        self.lock = lock
        self.incoming = ''
        self.to_send = ''
        self.encrypter = encrypter
        self.encoder = encoder
        self.outgoing_bits = 0
        self.bytes_pushed = 0
        self.last_pushed = time.time()
        self.msgLen = -1
        self.msg_len = None
        self.staging = []

        self.ctxt_len = 0
        self.ctxt = 0

    def determinePartition(self, msg):
        return self.encoder.determinePartition(msg)

    def extractStreamId(self, data):
        [n, C, data] = self.encoder.decode(data)
        return fte.bit_ops.grab_slice(n, n - 16, C)

    def waitingFor(self):
        return self.wf

    def push(self, data):
        self.bytes_pushed += len(data)
        self.last_pushed = time.time()
        self.incoming += data

    def bufferEmpty(self):
        return len(self.incoming) == 0

    def pop(self):
        retval = ''
        if len(self.incoming) < self.encoder.mtu:
            raise PopFailedException(('nothing to do', retval))
        try:
            _buf = self.incoming
            while True:
                try:
                    if self.msg_len is None:
                        self.msg_len = \
                            self.encoder.getMsgLen(_buf, '000')

                    if len(_buf) < self.msg_len:
                        raise PopFailedException('not enough bytes')

                    [_ctxt_len, _ctxt, _buf] = \
                        self.encoder.decode(_buf, '000')
                except fte.encoder.DecodeFailureException, e:
                    raise PopFailedException('can not decode yet : '
                                             + e.message)
                self.ctxt <<= _ctxt_len
                self.ctxt += _ctxt
                self.ctxt_len += _ctxt_len
                self.incoming = _buf
                self.msg_len = None
                try:
                    msgLen = self.encrypter.getMessageLen(self.ctxt_len,
                                                          self.ctxt)
                except fte.encrypter.DecryptionFailureException:
                    if _buf:
                        continue
                    else:
                        raise PopFailedException('can not decode yet 2')
                expected = msgLen * 8 \
                    + fte.encrypter.Encrypter.CTXT_EXPANSION_BYTES * 8 \
                    - 8
                if self.ctxt_len >= expected:
                    break
            if self.ctxt_len == 0:
                raise PopFailedException('not yet (ctxt_len==0)')
            padding_len = self.ctxt_len - (msgLen
                                           + fte.encrypter.Encrypter.CTXT_EXPANSION_BYTES - 1) \
                * 8
            if padding_len < 0:
                raise PopFailedException('not yet (padding_len<0)')
            self.ctxt_len = self.ctxt_len - padding_len
            self.ctxt = fte.bit_ops.grab_slice(
                self.ctxt_len, padding_len, self.ctxt)
            fte.logger.debug(LOG_LEVEL, ('DECRYPT', msgLen,
                             len(hex(self.ctxt)),
                             fte.encrypter.Encrypter.CTXT_EXPANSION_BYTES,
                             hex(self.ctxt)))
            retval = self.encrypter.decrypt(self.ctxt_len, self.ctxt)
            fte.logger.debug(LOG_LEVEL, ('SUCCESS', msgLen,
                             len(hex(self.ctxt)),
                             fte.encrypter.Encrypter.CTXT_EXPANSION_BYTES,
                             hex(self.ctxt)))
            self.incoming = _buf
            self.ctxt_len = 0
            self.ctxt = 0
        except fte.encrypter.DecryptionFailureException, e:
            fte.logger.debug(LOG_LEVEL, ('DECRYPTION FAILURE',
                             e.message))
            raise PopFailedException('decryption: ' + str(e.message))
        except fte.encrypter.UnrecoverableDecryptionFailureException, e:
            fte.logger.debug(LOG_LEVEL, ('BAD DECRYPTION FAILURE',
                             e.message))
            raise PopFailedException('decryption: ' + str(e.message))
        except fte.encrypter.NegotiateAcknowledgeExecption, e:
            pass
        return [retval, not self.bufferEmpty(), False]
