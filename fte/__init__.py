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

import time
import string

import fte.io
import fte.conf
import fte.defs
import fte.encoder
import fte.encrypter
import fte.record_layer

import fte.client.managed
import fte.server.managed


class InvalidRoleException(Exception):
    pass


class NegotiateTimeoutException(Exception):

    """Raised when negotiation fails to complete after """+str(fte.conf.getValue('runtime.fte.negotiate.timeout'))+""" seconds.
    """
    pass


class NegotiateCell(object):
    _CELL_SIZE = 64
    _PADDING_LEN = 32
    _PADDING_CHAR = '\x00'
    _DATE_FORMAT = 'YYYYMMDD'
    
    def __init__(self):
        self._def_file = ""
        self._language = ""
    
    
    def setDefFile(self,def_file):
        self._def_file = def_file
    
    
    def getDefFile(self):
        return self._def_file
    
    
    def setLanguage(self,language):
        self._language = language
    
    
    def getLanguage(self):
        return self._language
    
    
    def toString(self):
        retval = ''
        retval += self._def_file
        retval += self._language
        retval = string.rjust(retval, NegotiateCell._CELL_SIZE, NegotiateCell._PADDING_CHAR)
        assert retval[:NegotiateCell._PADDING_LEN] == NegotiateCell._PADDING_CHAR*NegotiateCell._PADDING_LEN
        return retval
    
    
    def fromString(self, negotiate_cell_str):
        assert len(negotiate_cell_str) == NegotiateCell._CELL_SIZE
        assert negotiate_cell_str[:NegotiateCell._PADDING_LEN] == NegotiateCell._PADDING_CHAR*NegotiateCell._PADDING_LEN
        negotiate_cell_str = negotiate_cell_str.strip(NegotiateCell._PADDING_CHAR)
        def_file = negotiate_cell_str[:len(NegotiateCell._DATE_FORMAT)] # 8==len(YYYYMMDD)
        language = negotiate_cell_str[len(NegotiateCell._DATE_FORMAT):]
        negotiate_cell = NegotiateCell()
        negotiate_cell.setDefFile(def_file)
        negotiate_cell.setLanguage(language)
        return negotiate_cell
    


class _FTESocketWrapper(object):


    def __init__(self, socket,
                 outgoing_regex = None, outgoing_max_len = -1,
                 incoming_regex = None, incoming_max_len = -1,
                 K1 = None, K2 = None):
        
        self._socket = socket

        self._outgoing_regex = outgoing_regex
        self._outgoing_max_len = outgoing_max_len
        self._incoming_regex = incoming_regex
        self._incoming_max_len = incoming_max_len

        self._K1 = K1
        self._K2 = K2

        self._encrypter = fte.encrypter.Encrypter(K1=self._K1,
                                                  K2=self._K2)

        self._init_encoders(outgoing_regex, outgoing_max_len,
                            incoming_regex, incoming_max_len)

        self._incoming_buffer = ''
        
        # establish connection
        if self._encoder: # client
            negotiate_cell = NegotiateCell()
            def_file = fte.conf.getValue('fte.defs.release')
            negotiate_cell.setDefFile(def_file)
            language = fte.conf.getValue('runtime.state.upstream_language')
            language = language[:-len('-request')]
            negotiate_cell.setLanguage(language)
            self.send(negotiate_cell.toString())
        else: # server
            loop_start = time.time()
            while True:
                if loop_start - time.time() > fte.conf.getValue('runtime.fte.negotiate.timeout'):
                    raise NegotiateTimeoutException()
                
                [success, data] = fte.io.recvall_from_socket(self._socket)
                if data == '':
                    continue
                [negotiate_cell,remaining_buffer] = self._accept_negotiation(data)

                negotiate = NegotiateCell().fromString(negotiate_cell)
                
                outgoing_language = negotiate.getLanguage()+'-response'
                incoming_language = negotiate.getLanguage()+'-request'
        
                outgoing_regex = fte.defs.getRegex(outgoing_language)
                outgoing_max_len = fte.defs.getMaxLen(outgoing_language)
                incoming_regex = fte.defs.getRegex(incoming_language)
                incoming_max_len = fte.defs.getMaxLen(incoming_language)

                self._init_encoders(outgoing_regex, outgoing_max_len,
                                    incoming_regex, incoming_max_len)

                self._decoder.push(remaining_buffer)
                self._incoming_buffer += self._decoder.pop()
                break


    def _init_encoders(self, outgoing_regex, outgoing_max_len,
                             incoming_regex, incoming_max_len):
        self._outgoing_regex = outgoing_regex
        self._outgoing_max_len = outgoing_max_len
        self._incoming_regex = incoming_regex
        self._incoming_max_len = incoming_max_len
        
        self._outgoing_encoder = None
        self._encoder = None
        self._incoming_decoder = None
        self._decoder = None
        
        if outgoing_regex != None and outgoing_max_len != -1:
            self._outgoing_encoder = fte.encoder.RegexEncoder(self._outgoing_regex,
                                                              self._outgoing_max_len)
            self._encoder = fte.record_layer.Encoder(encrypter=self._encrypter,
                                                     encoder=self._outgoing_encoder)

        if incoming_regex != None and incoming_max_len != -1:
            self._incoming_decoder = fte.encoder.RegexEncoder(self._incoming_regex,
                                                              self._incoming_max_len)
            self._decoder = fte.record_layer.Decoder(decrypter=self._encrypter,
                                                     decoder=self._incoming_decoder)
    

    def fileno(self):
        return self._socket.fileno()


    def recv(self, bufsize):
        while True:
            data = self._socket.recv(bufsize)

            if not data and not self._incoming_buffer and not self._decoder._buffer:
                return ''

            self._decoder.push(data)

            while True:
                frag = self._decoder.pop()
                if not frag:
                    break
                self._incoming_buffer += frag

            if self._incoming_buffer:
                break

        retval = self._incoming_buffer[:bufsize]
        self._incoming_buffer = self._incoming_buffer[bufsize:]

        return retval


    def send(self, data):
        self._encoder.push(data)
        while True:
            to_send = self._encoder.pop()
            if not to_send:
                break
            self._socket.sendall(to_send)
        return len(data)


    def sendall(self, data):
        self.send(data)
        return None


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
                                 self._outgoing_regex, self._outgoing_max_len,
                                 self._incoming_regex, self._incoming_max_len,
                                 self._K1, self._K2)
        
        return conn, addr


    def bind(self, addr):
        return self._socket.bind(addr)


    def listen(self, N):
        return self._socket.listen(N)
    
    
    def _accept_negotiation(self, data):
        languages = fte.defs.load_definitions()
        for incoming_language in languages.keys():
            try:
                if incoming_language.endswith('response'): continue
        
                incoming_regex = fte.defs.getRegex(incoming_language)
                incoming_max_len = fte.defs.getMaxLen(incoming_language)
                
                incoming_decoder = fte.encoder.RegexEncoder(incoming_regex,
                                                            incoming_max_len)
                decoder = fte.record_layer.Decoder(decrypter=self._encrypter,
                                                   decoder=incoming_decoder)
                
                decoder.push(data)
                negotiate_cell = decoder.pop()
                NegotiateCell().fromString(negotiate_cell)
                
                return [negotiate_cell, decoder._buffer]
            except:
                continue
            
        return False
        

def wrap_socket(sock,
                outgoing_regex = None, outgoing_max_len = -1,
                incoming_regex = None, incoming_max_len = -1,
                K1=None, K2=None):
    """``fte.wrap_socket`` turns an existing socket into an FTE socket.

    The input parameter ``sock`` is the socket to wrap.
    The parameter ``outgoing_regex`` specifies the format of the messages
    to send via the socket. The ``outgoing_max_len`` parameter specifies the
    maximum length of the strings in ``outgoing_regex``.
    The paramters ``incoming_regex`` and ``incoming_max_len`` are defined
    similarly.
    The optional paramters ``K1`` and ``K2`` specify 128-bit keys to be used
    in FTE's underlying AE scheme. If specified, these values must be 16-byte
    hex strings.
    """

    assert K1 == None or len(K1) == 16
    assert K2 == None or len(K2) == 16

    socket_wrapped = _FTESocketWrapper(
        sock,
        outgoing_regex, outgoing_max_len,
        incoming_regex, incoming_max_len,
        K1, K2)
    return socket_wrapped














import base64

import obfsproxy.network.network as network
import obfsproxy.network.socks as socks
import obfsproxy.network.extended_orport as extended_orport
import obfsproxy.common.log as logging

from obfsproxy.transports.base import BaseTransport

from twisted.internet import reactor

log = logging.get_obfslogger()

def _get_b64_chunks_from_str(string):
    """
    Given a 'string' of concatenated base64 objects, return a list
    with the objects.

    Assumes that the objects are well-formed base64 strings. Also
    assumes that the padding character of base64 is '='.
    """
    chunks = []

    while True:
        pad_loc = string.find('=')
        if pad_loc < 0 or pad_loc == len(string)-1 or pad_loc == len(string)-2:
            # If there is no padding, or it's the last chunk: append
            # it to chunks and return.
            chunks.append(string)
            return chunks

        if pad_loc != len(string)-1 and string[pad_loc+1] == '=': # double padding
            pad_loc += 1

        # Append the object to the chunks, and prepare the string for
        # the next iteration.
        chunks.append(string[:pad_loc+1])
        string = string[pad_loc+1:]

    return chunks

class FTETransport(BaseTransport):
    """
    The BaseTransport class is a skeleton class for pluggable transports.
    It contains callbacks that your pluggable transports should
    override and customize.
    """

    def __init__(self, transport_config):
        pass
    
    def receivedDownstream(self, data, circuit):
        """
        Got data from downstream; relay them upstream.
        """

        decoded_data = ''

        # TCP is a stream protocol: the data we received might contain
        # more than one b64 chunk. We should inspect the data and
        # split it into multiple chunks.
        b64_chunks = _get_b64_chunks_from_str(data.peek())

        # Now b64 decode each chunk and append it to the our decoded
        # data.
        for chunk in b64_chunks:
            try:
                decoded_data += base64.b64decode(chunk)
            except TypeError:
                log.info("We got corrupted b64 ('%s')." % chunk)
                return

        data.drain()
        circuit.upstream.write(decoded_data)

    def receivedUpstream(self, data, circuit):
        """
        Got data from upstream; relay them downstream.
        """

        circuit.downstream.write(base64.b64encode(data.read()))
        return

class PluggableTransportError(Exception): pass
class SOCKSArgsError(Exception): pass


class FTEClientTransport(FTETransport):
    pass

class FTEServerTransport(FTETransport):
    pass


def launch_transport_listener(transport, bindaddr, role, remote_addrport, pt_config, ext_or_cookie_file=None):
        
    """
    Launch a listener for 'transport' in role 'role' (socks/client/server/ext_server).

    If 'bindaddr' is set, then listen on bindaddr. Otherwise, listen
    on an ephemeral port on localhost.
    'remote_addrport' is the TCP/IP address of the other end of the
    circuit. It's not used if we are in 'socks' role.

    'pt_config' contains configuration options (such as the state location)
    which are of interest to the pluggable transport.

    'ext_or_cookie_file' is the filesystem path where the Extended
    ORPort Authentication cookie is stored. It's only used in
    'ext_server' mode.

    Return a tuple (addr, port) representing where we managed to bind.

    Throws obfsproxy.transports.transports.TransportNotFound if the
    transport could not be found.

    Throws twisted.internet.error.CannotListenError if the listener
    could not be set up.
    """

    listen_host = bindaddr[0] if bindaddr else 'localhost'
    listen_port = int(bindaddr[1]) if bindaddr else 0
    
    if role == 'socks':
        transport_class = FTETransport
        factory = socks.SOCKSv4Factory(transport_class, pt_config)
    elif role == 'ext_server':
        assert(remote_addrport and ext_or_cookie_file)
        transport_class = FTETransport
        factory = extended_orport.ExtORPortServerFactory(remote_addrport, ext_or_cookie_file, transport, transport_class, pt_config)
    elif role == 'client':
        assert(remote_addrport)
        transport_class = FTETransport
        factory = network.StaticDestinationServerFactory(remote_addrport, role, transport_class, pt_config)
    elif role == 'server':
        assert(remote_addrport)
        transport_class = FTETransport
        factory = network.StaticDestinationServerFactory(remote_addrport, role, transport_class, pt_config)
    else:
        raise InvalidRoleException()

    addrport = reactor.listenTCP(listen_port, factory, interface=listen_host)

    return (addrport.getHost().host, addrport.getHost().port)