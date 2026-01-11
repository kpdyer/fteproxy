#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__version__ = "0.2.19"

import sys
import socket
import traceback

import fteproxy.conf
import fteproxy.defs
import fteproxy.record_layer

import fte


class InvalidRoleException(Exception):
    pass


class NegotiationFailedException(Exception):
    pass


class ChannelNotReadyException(Exception):
    pass


class NegotiateTimeoutException(Exception):

    """Raised when negotiation fails to complete after """ + str(fteproxy.conf.getValue('runtime.fteproxy.negotiate.timeout')) + """ seconds.
    """
    pass


def fatal_error(msg):
    if fteproxy.conf.getValue('runtime.loglevel') in [1,2,3]:
        print('ERROR:', msg)
    sys.exit(1)


def warn(msg):
    if fteproxy.conf.getValue('runtime.loglevel') in [2,3]:
        print('WARN:', msg)


def info(msg):
    if fteproxy.conf.getValue('runtime.loglevel') in [3]:
        print('INFO:', msg)


class NegotiateCell(object):
    _CELL_SIZE = 64
    _PADDING_LEN = 32
    _PADDING_CHAR = b'\x00'
    _DATE_FORMAT = b'YYYYMMDD'

    def __init__(self):
        self._def_file = b""
        self._language = b""

    def setDefFile(self, def_file):
        if isinstance(def_file, str):
            def_file = def_file.encode('utf-8')
        self._def_file = def_file

    def getDefFile(self):
        if isinstance(self._def_file, bytes):
            return self._def_file.decode('utf-8')
        return self._def_file

    def setLanguage(self, language):
        if isinstance(language, str):
            language = language.encode('utf-8')
        self._language = language

    def getLanguage(self):
        if isinstance(self._language, bytes):
            return self._language.decode('utf-8')
        return self._language

    def toBytes(self):
        retval = b''
        retval += self._def_file
        retval += self._language
        retval = retval.rjust(NegotiateCell._CELL_SIZE, NegotiateCell._PADDING_CHAR)
        assert retval[:NegotiateCell._PADDING_LEN] == NegotiateCell._PADDING_CHAR * \
            NegotiateCell._PADDING_LEN
        return retval

    def fromBytes(self, negotiate_cell_bytes):
        assert len(negotiate_cell_bytes) == NegotiateCell._CELL_SIZE
        assert negotiate_cell_bytes[
            :NegotiateCell._PADDING_LEN] == NegotiateCell._PADDING_CHAR * NegotiateCell._PADDING_LEN
        negotiate_cell_bytes = negotiate_cell_bytes.strip(
            NegotiateCell._PADDING_CHAR)
        # 8==len(YYYYMMDD)
        def_file = negotiate_cell_bytes[:len(NegotiateCell._DATE_FORMAT)]
        language = negotiate_cell_bytes[len(NegotiateCell._DATE_FORMAT):]
        negotiate_cell = NegotiateCell()
        negotiate_cell.setDefFile(def_file)
        negotiate_cell.setLanguage(language)
        return negotiate_cell


class NegotiationManager(object):

    def __init__(self, K1, K2):
        self._negotiationComplete = False
        self._K1 = K1
        self._K2 = K2

    def getNegotiationComplete(self):
        return self._negotiationComplete

    def _acceptNegotiation(self, data):

        languages = fteproxy.defs.load_definitions()
        for incoming_language in languages.keys():
            try:
                if incoming_language.endswith('response'):
                    continue

                incoming_regex = fteproxy.defs.getRegex(incoming_language)
                incoming_fixed_slice = fteproxy.defs.getFixedSlice(
                    incoming_language)

                key = (self._K1 + self._K2) if self._K1 and self._K2 else None
                incoming_decoder = fte.Encoder(incoming_regex, incoming_fixed_slice, key)
                decoder = fteproxy.record_layer.Decoder(decoder=incoming_decoder)

                decoder.push(data)
                negotiate_cell = decoder.pop(oneCell=True)
                NegotiateCell().fromBytes(negotiate_cell)

                return [negotiate_cell, decoder._buffer]
            except Exception as e:
                fteproxy.info('Failed to decode first message as '+incoming_language+': '+str(e))

        raise NegotiationFailedException()

    def _init_encoders(self,
                       outgoing_regex, outgoing_fixed_slice,
                       incoming_regex, incoming_fixed_slice):

        encoder = None
        decoder = None

        key = (self._K1 + self._K2) if self._K1 and self._K2 else None

        if outgoing_regex != None and outgoing_fixed_slice != -1:
            outgoing_encoder = fte.Encoder(outgoing_regex, outgoing_fixed_slice, key)
            encoder = fteproxy.record_layer.Encoder(encoder=outgoing_encoder)

        if incoming_regex != None and incoming_fixed_slice != -1:
            incoming_decoder = fte.Encoder(incoming_regex, incoming_fixed_slice, key)
            decoder = fteproxy.record_layer.Decoder(decoder=incoming_decoder)

        return [encoder, decoder]

    def _makeNegotiationCell(self, encoder):
        negotiate_cell = NegotiateCell()
        def_file = fteproxy.conf.getValue('fteproxy.defs.release')
        negotiate_cell.setDefFile(def_file)
        language = fteproxy.conf.getValue('runtime.state.upstream_language')
        language = language[:-len('-request')]
        negotiate_cell.setLanguage(language)
        encoder.push(negotiate_cell.toBytes())
        data = encoder.pop()
        return data

    def makeClientNegotiationCell(self,
                                  outgoing_regex, outgoing_fixed_slice,
                                  incoming_regex, incoming_fixed_slice):
        [encoder, decoder] = self._init_encoders(
            outgoing_regex, outgoing_fixed_slice, incoming_regex, incoming_fixed_slice)
        return self._makeNegotiationCell(encoder)

    def doServerSideNegotiation(self, data):
        [negotiate_cell, remaining_buffer] = self._acceptNegotiation(data)

        negotiate = NegotiateCell().fromBytes(negotiate_cell)

        outgoing_language = negotiate.getLanguage() + '-response'
        incoming_language = negotiate.getLanguage() + '-request'

        outgoing_regex = fteproxy.defs.getRegex(outgoing_language)
        outgoing_fixed_slice = fteproxy.defs.getFixedSlice(outgoing_language)
        incoming_regex = fteproxy.defs.getRegex(incoming_language)
        incoming_fixed_slice = fteproxy.defs.getFixedSlice(incoming_language)

        [encoder, decoder] = self._init_encoders(
            outgoing_regex, outgoing_fixed_slice, incoming_regex, incoming_fixed_slice)

        decoder.push(remaining_buffer)

        return [encoder, decoder]


class FTEHelper(object):

    def _processRecv(self, data):
        retval = data
        if self._isServer and not self._negotiationComplete:
            try:
                self._preNegotiationBuffer_incoming += data
                [encoder, decoder] = self._negotiation_manager.doServerSideNegotiation(
                    self._preNegotiationBuffer_incoming)
                self._encoder = encoder
                self._decoder = decoder
                self._preNegotiationBuffer_incoming = b''
                self._negotiationComplete = True
                retval = b''
            except Exception as e:
                raise ChannelNotReadyException()

        return retval

    def _processSend(self):
        retval = b''
        if self._isClient and not self._negotiationComplete:
            [encoder, decoder] = self._negotiation_manager._init_encoders(
                self._outgoing_regex,
                self._outgoing_fixed_slice,
                self._incoming_regex,
                self._incoming_fixed_slice)
            self._encoder = encoder
            self._decoder = decoder
            negotiation_cell = self._negotiation_manager.makeClientNegotiationCell(
                self._outgoing_regex, self._outgoing_fixed_slice,
                self._incoming_regex, self._incoming_fixed_slice)
            retval = negotiation_cell
            self._negotiationComplete = True
        return retval


class _FTESocketWrapper(FTEHelper, object):

    def __init__(self, _socket,
                 outgoing_regex=None, outgoing_fixed_slice=-1,
                 incoming_regex=None, incoming_fixed_slice=-1,
                 K1=None, K2=None,
                 negotiate=True):

        self._socket = _socket
        self._outgoing_regex = outgoing_regex
        self._outgoing_fixed_slice = outgoing_fixed_slice
        self._incoming_regex = incoming_regex
        self._incoming_fixed_slice = incoming_fixed_slice
        self._K1 = K1
        self._K2 = K2
        self._negotiate = negotiate

        self._negotiation_manager = NegotiationManager(K1, K2)
        self._incoming_buffer = b''
        self._preNegotiationBuffer_outgoing = b''
        self._preNegotiationBuffer_incoming = b''

        if negotiate:
            # Standard relay mode: client sends negotiation cell, server waits for it
            self._negotiationComplete = False
            self._isServer = (outgoing_regex is None and incoming_regex is None)
            self._isClient = (outgoing_regex is not None and incoming_regex is not None)
        else:
            # No negotiation: both sides know the formats, set up encoders immediately
            self._negotiationComplete = True
            self._isServer = False
            self._isClient = False
            [self._encoder, self._decoder] = self._negotiation_manager._init_encoders(
                outgoing_regex, outgoing_fixed_slice,
                incoming_regex, incoming_fixed_slice)

    def fileno(self):
        return self._socket.fileno()

    def setsockopt(self, level, optname, value):
        return self._socket.setsockopt(level, optname, value)

    def getsockopt(self, level, optname, buflen=None):
        if buflen is None:
            return self._socket.getsockopt(level, optname)
        return self._socket.getsockopt(level, optname, buflen)

    def recv(self, bufsize):
        # <HACK>
        # Required to deal with case when client attempts to recv
        # before sending. This checks to ensure that a negotiate
        # cell is sent no matter what the client does first.
        to_send = self._processSend()
        if to_send:
            numbytes = self._socket.send(to_send)
            assert numbytes == len(to_send)
        # </HACK>

        try:
            while True:
                data = self._socket.recv(bufsize)
                noData = (data == b'')
                data = self._processRecv(data)

                if noData and not self._incoming_buffer and not self._decoder._buffer:
                    return b''

                self._decoder.push(data)

                while True:
                    frag = self._decoder.pop()
                    if not frag:
                        break
                    self._incoming_buffer += frag

                if self._incoming_buffer:
                    break

            retval = self._incoming_buffer
            self._incoming_buffer = b''
        except ChannelNotReadyException:
            raise socket.timeout

        return retval
    
    def send(self, data):
        to_send = self._processSend()
        if to_send:
            self._socket.sendall(to_send)

        self._encoder.push(data)
        while True:
            to_send = self._encoder.pop()
            if not to_send:
                break
            self._socket.sendall(to_send)
        return len(data)

    def sendall(self, data):
        return self.send(data)

    def gettimeout(self):
        return self._socket.gettimeout()

    def settimeout(self, val):
        return self._socket.settimeout(val)

    def shutdown(self, flags):
        return self._socket.shutdown(flags)

    def close(self):
        return self._socket.close()

    def connect(self, addr):
        return self._socket.connect(addr)

    def accept(self):
        conn, addr = self._socket.accept()
        conn = _FTESocketWrapper(conn,
                                 self._outgoing_regex, self._outgoing_fixed_slice,
                                 self._incoming_regex, self._incoming_fixed_slice,
                                 self._K1, self._K2,
                                 self._negotiate)

        return conn, addr

    def bind(self, addr):
        return self._socket.bind(addr)

    def listen(self, N):
        return self._socket.listen(N)


def wrap_socket(sock,
                outgoing_regex=None, outgoing_fixed_slice=-1,
                incoming_regex=None, incoming_fixed_slice=-1,
                K1=None, K2=None,
                negotiate=True):
    """``fteproxy.wrap_socket`` turns an existing socket into an fteproxy socket.

    The input parameter ``sock`` is the socket to wrap.
    The parameter ``outgoing_regex`` specifies the format of the messages
    to send via the socket. The ``outgoing_fixed_slice`` parameter specifies the
    maximum length of the strings in ``outgoing_regex``.
    The parameters ``incoming_regex`` and ``incoming_fixed_slice`` are defined
    similarly.
    The optional parameters ``K1`` and ``K2`` specify 128-bit keys to be used
    in FTE's underlying AE scheme. If specified, these values must be 16-byte
    strings.
    
    The ``negotiate`` parameter controls whether the client sends a negotiation
    cell to establish the format. Set to ``False`` when both sides already know
    the formats (e.g., in symmetric client/server examples). Default is ``True``
    for backwards compatibility with the relay use case.
    """

    assert K1 == None or len(K1) == 16
    assert K2 == None or len(K2) == 16

    socket_wrapped = _FTESocketWrapper(
        sock,
        outgoing_regex, outgoing_fixed_slice,
        incoming_regex, incoming_fixed_slice,
        K1, K2,
        negotiate)
    return socket_wrapped
