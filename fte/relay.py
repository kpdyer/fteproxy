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

import threading
import multiprocessing
import sys
import os
import random
import time
import copy
import select
import struct
import socket
import fte.conf
import fte.encrypter
import fte.record_layer

LOGGING_ENABLED = False
CONNECTION_LOGGING_ENABLED = False
LOG_LEVEL = fte.conf.getValue('loglevel.fte.relay')
ENCODER_BLOCK_SIZE = \
    fte.conf.getValue('runtime.fte.relay.encoder_block_size')
DECODER_BLOCK_SIZE = \
    fte.conf.getValue('runtime.fte.relay.decoder_block_size')
CLOCK_SPEED = fte.conf.getValue('runtime.fte.relay.clock_speed')
SELECT_SPEED = fte.conf.getValue('runtime.fte.relay.select_speed')
SERVER_TIMEOUT = fte.conf.getValue('runtime.fte.relay.server_timeout')
CLIENT_TIMEOUT = fte.conf.getValue('runtime.fte.relay.client_timeout')
SENDING = 0
RECEIVING = 1


class FailedToBindException(Exception):

    pass


class NotMyStreamException(Exception):

    datagram = ''
    stream_id = -1


class TerminateStreamException(Exception):

    stream_id = -1


class TCPResetException(Exception):

    pass


log_lock = threading.Lock()


def LOG(msg, stream_id=None, cycle=None):
    if LOGGING_ENABLED:
        with log_lock:
            f = open('relay-' + fte.conf.getValue('runtime.mode')
                     + '.log', 'a+')
            f.write('(' + str(time.time()) + ',')
            mode = ('C' if fte.conf.getValue('runtime.mode') == 'client'
                    else 'S')
            f.write(str(mode) + ',')
            f.write('tid=' + str(threading.currentThread().ident) + ',')
            if stream_id != None and cycle != None:
                f.write('sid=' + str(stream_id) + ',cyc=' + str(cycle)
                        + '): ' + str(msg) + '\n')
            elif stream_id != None:
                f.write('sid=' + str(stream_id) + '): ' + str(msg)
                        + '\n')
            elif cycle != None:
                f.write('cyc=' + str(cycle) + '): ' + str(msg) + '\n')
            else:
                f.write('NULL): ' + str(msg) + '\n')
            f.close()


def save_connection_information(input):
    if CONNECTION_LOGGING_ENABLED:
        with log_lock:
            with open('connections-' + fte.conf.getValue('runtime.mode'
                                                         ) + '.log', 'a+') as f:
                f.write(','.join(input) + '\n')


def sendall_to_socket(sock, msg, timeout=5):
    totalsent = 0
    fte.logger.performance('data_push', 'start')
    try:
        while totalsent < len(msg):
            sent = sock.send(msg[totalsent:])
            if sent == 0:
                break
            totalsent = totalsent + sent
    except:
        pass
    fte.logger.performance('data_push', 'stop')
    return totalsent > 0


def recvall_from_socket(sock, covertext=None, timeout=SELECT_SPEED):
    retval = ''
    success = False
    start = time.time()
    while True:
        try:
            ready = select.select([sock], [], [sock], timeout)
            if ready[0]:
                _data = sock.recv(ENCODER_BLOCK_SIZE)
                if _data:
                    retval += _data
                    success = True
                    timeout = SELECT_SPEED
                    continue
                else:
                    success = (len(retval) > 0)
                    break
            elif ready[2]:
                success = (len(retval) > 0)
                break
            else:
                success = True
                break
        except socket.error:
            success = (len(retval) > 0)
            break
        except select.error:
            success = (len(retval) > 0)
            break
    if retval:
        fte.logger.performance('data_pull', 'start', start)
        fte.logger.performance('data_pull', 'stop')
    else:
        fte.logger.performance('blocking', 'start', start)
        fte.logger.performance('blocking', 'stop')
    return [success, retval]


def extract_stream_id(decoder, encrypter, msg):
    partition = decoder.determinePartition(msg)
    [n, C, msg] = decoder.decode(msg, partition)
    stream_id = encrypter.extractStreamId(n, C)
    return stream_id


def one_off_encode(
    encrypter,
    encoder,
    msg,
    messageType,
):
    covertext_payload = encrypter.encrypt(msg, messageType)
    n = fte.encrypter.Encrypter.CTXT_EXPANSION_BITS + len(msg) * 8
    partition = '000'
    covertext_payload_len = encoder.getNextTemplateCapacity(partition)
    padding_length = covertext_payload_len - n
    if padding_length > 0:
        covertext_payload = covertext_payload << padding_length
        covertext_payload += random.randint(0, (1 << padding_length)
                                            - 1)
    else:
        covertext_payload_len = n
    covertext = encoder.encode(covertext_payload_len,
                               covertext_payload, partition)
    return covertext


def one_off_decode(encrypter, decoder, msg):
    [n, C, msg] = decoder.decode(msg, '000')
    M = encrypter.decrypt(n, C)
    assert False


def negotiate(encrypter, encoder):
    msg = fte.conf.getValue('runtime.state.upstream_language')[:-8]
    covertext = one_off_encode(encrypter, encoder, msg,
                               fte.encrypter.Encrypter.MSG_NEGOTIATE)
    return covertext[0]


def negotiate_acknowledge(encrypter, msg):
    language_upstream = None
    language_downstream = None
    covertext = ''
    for language in fte.conf.getValue('languages.regex'):
        if not language.endswith('request'):
            continue
        try:
            d = fte.encoder.RegexEncoder(language)
            one_off_decode(encrypter, d, msg)
        except fte.encrypter.NegotiateExecption, e:
            language_upstream = e.data + '-request'
            language_downstream = e.data + '-response'
            encoder = fte.encoder.RegexEncoder(language_downstream)
            covertext = one_off_encode(encrypter, encoder, '',
                                       fte.encrypter.Encrypter.MSG_NEGOTIATE_ACK)
            break
        except fte.encoder.RankFailureException, e:
            pass
        except fte.encoder.DecodeFailureException, e:
            pass
        except fte.encrypter.UnrecoverableDecryptionFailureException, e:
            pass
    return (language_upstream, language_downstream, covertext[0])


class EncoderThread(threading.Thread):

    def __init__(
        self,
        lock,
        mode,
        stream_id,
        source,
        sink,
        encoder,
        dieAfterSend=False,
    ):
        threading.Thread.__init__(self)
        self.lock = lock
        self.has_started = False
        self.source = source
        self.encoder = encoder
        self.dieAfterSend = dieAfterSend
        self.sink = sink
        self.mode = mode
        self.stream_id = stream_id
        self.data = ''
        self.exception = None
        self.sink_alive = None
        self.source_alive = None
        self.gathered = 0
        self.system_cycles = 0
        self.sent_count = 0
        self.received_count = 0
        with self.lock:
            if self.mode == 'client':
                self.default_state = SENDING
            elif self.mode == 'server':
                self.default_state = RECEIVING
            self.state = self.default_state
            self.birth = time.time()

    def shouldTerminate(self):
        fte.logger.performance('blocking', 'start')
        if self.mode == 'server':
            fte.logger.performance('blocking', 'stop')
            return self.sink_alive == False or (self.source_alive
                                                == False and self.shouldBlock())
        elif self.mode == 'client':
            inactivity_outgoing = time.time() - self.encoder.last_pushed
            inactivity_incoming = time.time() - self.peer.last_pushed
            inactivity = min(inactivity_outgoing, inactivity_incoming)
            fte.logger.performance('blocking', 'stop')
            return self.source_alive == False or self.sink_alive == False or inactivity \
                > fte.conf.getValue('runtime.tcp.timeout')

    def shouldBlock(self):
        return len(self.encoder.incoming) == 0 \
            and self.encoder.outgoing_bits == 0

    def run(self):
        fte.logger.performance('encoder_thread', 'start')
        self.has_started = True
        LOG('+++ EncoderThread Spawned', self.encoder.stream_id,
            self.system_cycles)
        while True:
            if self.source_alive != False:
                [success, self.data] = recvall_from_socket(self.source)
                self.gathered += len(self.data)
                self.source_alive = success
                if self.data:
                    self.encoder.push(self.data)
                    LOG(('encoder', 'incoming', self.data),
                        self.encoder.stream_id, self.system_cycles)
                    self.data = ''
            LOG(('encoder', 'buffer_status',
                len(self.encoder.incoming),
                self.encoder.outgoing_bits), self.encoder.stream_id,
                self.system_cycles)
            LOG((
                'encoder',
                'incoming',
                'shouldTerm=' + str(self.shouldTerminate()),
                'shouldBlock=' + str(self.shouldBlock()),
                'peer_alive=' + str(self.peer.is_alive()),
                'sink_alive=' + str(self.sink_alive),
                'source_alive=' + str(self.source_alive),
                'sent=' + str(self.sent_count),
                'recv=' + str(self.received_count),
                'incoming=' + str(len(self.encoder.incoming)),
                'outgoing_bits=' + str(self.encoder.outgoing_bits),
                self.data,
                ), self.encoder.stream_id, self.system_cycles)
            if self.shouldBlock():
                if self.shouldTerminate():
                    break
                else:
                    fte.logger.performance('blocking', 'start')
                    time.sleep(CLOCK_SPEED)
                    fte.logger.performance('blocking', 'stop')
                    continue
            try:
                msg = ''
                while True:
                    retval = self.encoder.pop()
                    if not retval[0]:
                        break
                    msg += retval[0]
            except fte.markov.DeadStateException, e:
                self.encoder.model.reset()
                LOG(('encoder', 'TCP RESET'), self.encoder.stream_id,
                    self.system_cycles)
                self.exception = TCPResetException('')
                break
            with self.lock:
                if self.sink_alive != False and len(msg) > 0:
                    success = sendall_to_socket(self.sink, msg)
                    LOG((self.mode, 'encoder', 'outgoing', success,
                        msg), self.encoder.stream_id,
                        self.system_cycles)
                    if success:
                        self.sink_alive = True
                        self.state = RECEIVING
                        self.system_cycles += 1
                        self.sent_count += len(msg)
                    else:
                        self.sink_alive = False
        LOG('--- EncoderThread Terminated', self.encoder.stream_id,
            self.system_cycles)
        fte.logger.performance('encoder_thread', 'stop')


class DecoderThread(threading.Thread):

    def __init__(
        self,
        lock,
        mode,
        stream_id,
        source,
        sink,
        decoder,
        dieAfterSend=False,
    ):
        threading.Thread.__init__(self)
        self.lock = lock
        self.has_started = False
        self.source = source
        self.sink = sink
        self.decoder = decoder
        self.mode = mode
        self.stream_id = stream_id
        self.data = ''
        self.exception = None
        self.dieAfterSend = dieAfterSend
        self.got_term = False
        self.to_send = ''
        self.last_pushed = time.time()
        self.bytes_pushed = 0

    def shouldTerminate(self):
        if self.mode == 'client':
            return self.peer.source_alive == False \
                or (self.peer.sink_alive == False and self.shouldBlock())
                # or (self.peer.has_started and not self.peer.is_alive() and self.shouldBlock())
                # or (self.peer.sink_alive == False and not self.shouldBlock())
                # \
        elif self.mode == 'server':
            return self.peer.sink_alive == False \
                or (self.peer.source_alive == False
                    and self.shouldBlock())

    def shouldBlock(self):
        return len(self.data) == 0 and len(self.decoder.incoming) == 0

    def run(self):
        fte.logger.performance('decoder_thread', 'start')
        self.has_started = True
        LOG('+++ DecoderThread Spawned', self.decoder.stream_id,
            self.peer.system_cycles)
        while True:
            if self.peer.sink_alive != False:
                [success, data] = recvall_from_socket(self.sink, True)
                self.peer.sink_alive = success
                self.data += data
            LOG((
                'decoder',
                'incoming',
                'shouldTerm=' + str(self.shouldTerminate()),
                'peer_alive=' + str(self.peer.is_alive()),
                'sink_alive=' + str(self.peer.sink_alive),
                'source_alive=' + str(self.peer.source_alive),
                'shouldBlock=' + str(self.shouldBlock()),
                'sent=' + str(self.peer.sent_count),
                'recv=' + str(self.peer.received_count),
                'len(self.data)=' + str(len(self.data)),
                'len(self.decoder.incoming)=' +
                str(len(self.decoder.incoming)),
                self.data,
                ), self.decoder.stream_id, self.peer.system_cycles)
            if self.shouldBlock():
                if self.shouldTerminate():
                    break
                else:
                    fte.logger.performance('blocking', 'start')
                    time.sleep(CLOCK_SPEED)
                    fte.logger.performance('blocking', 'stop')
                    continue
            with self.lock:
                if self.mode == 'server':
                    if fte.conf.getValue('runtime.http_proxy.enable'):
                        stream_id = \
                            extract_stream_id(self.decoder.encoder,
                                              self.decoder.encrypter, self.data)
                    else:
                        stream_id = self.stream_id
                    if stream_id != self.decoder.stream_id:
                        e = NotMyStreamException('Change streams.')
                        e.datagram = self.data
                        e.stream_id = stream_id
                        self.data = ''
                        self.exception = e
                        break
                LOG(('decoder', 'incoming',
                    'incrementing received_count', self.data[:64]),
                    self.decoder.stream_id, self.peer.system_cycles)
                self.decoder.push(self.data)
                self.data = ''
                self.peer.state = SENDING
                self.peer.received_count += 1
                self.peer.system_cycles += 1
            msg = ''
            while True:
                try:
                    retval = self.decoder.pop()
                except fte.record_layer.PopFailedException, e:
                    break
                except fte.record_layer.EndOfStreamException, e:
                    excp = TerminateStreamException('Terminate.')
                    if fte.conf.getValue('runtime.http_proxy.enable'):
                        excp.stream_id = \
                            extract_stream_id(self.decoder,
                                              self.encrypter, e.datagram)
                    else:
                        excp.stream_id = self.stream_id
                    self.exception = excp
                    break
                msg += retval[0]
                if retval[1] == False:
                    break

            if not msg and self.peer.sink_alive == False:
                break

            if self.peer.source_alive != False:
                if msg:
                    self.bytes_pushed += len(msg)
                    success = sendall_to_socket(self.source, msg)
                    if fte.conf.getValue('runtime.console.debug'):
                        print (('<' if self.mode == 'client' else '>'),
                               success, self.decoder.stream_id,
                               [msg[:64]])
                    LOG(('decoder', 'outgoing', success, msg),
                        self.decoder.stream_id, self.peer.system_cycles)
                    if success:
                        self.peer.source_alive = True
                        self.last_pushed = time.time()
                    else:
                        self.peer.source_alive = False

            if self.shouldTerminate():
                break
            if self.peer.state == SENDING and self.dieAfterSend:
                break
        LOG('--- DecoderThread Terminated', self.decoder.stream_id,
            self.peer.system_cycles)
        fte.logger.performance('decoder_thread', 'stop')


class ServerDemuxer(threading.Thread):

    def __init__(
        self,
        fte_client_socket,
        fte_client_address,
        fte_stream_factory,
        encoder_cache_lock,
        encoder_cache,
    ):
        threading.Thread.__init__(self)
        self.fte_client_socket = fte_client_socket
        self.fte_client_address = fte_client_address
        self.fte_stream_factory = fte_stream_factory

    def run(self):
        fte_stream = None
        [success, data] = recvall_from_socket(self.fte_client_socket,
                                              True, 5)
        if not success or not data:
            return
        if fte.conf.getValue('runtime.http_proxy.enable'):
            stream_id = \
                extract_stream_id(self.fte_stream_factory.decoder,
                                  self.fte_stream_factory.encrypter,
                                  data)
        else:
            stream_id = self.fte_client_address[1]
        LOG(('ServerDemuxer got', [data]), stream_id, 0)
        fte_stream = self.fte_stream_factory.createStream(stream_id)
        if fte_stream.encoder.encoder == None:
            (lang_up, lang_down, covertext) = \
                negotiate_acknowledge(fte_stream.encoder.encrypter,
                                      data)
            fte_stream.encoder.encoder = \
                fte.encoder.RegexEncoder(lang_down)
            fte_stream.decoder.encoder = \
                fte.encoder.RegexEncoder(lang_up)
            sendall_to_socket(self.fte_client_socket, covertext)
            data = ''
        try:
            fte_stream.startTCPConnection()
            shouldDieAfterSend = \
                fte.conf.getValue('runtime.http_proxy.enable')
            lock = threading.Lock()
            encoder = EncoderThread(
                lock,
                'server',
                stream_id=stream_id,
                source=fte_stream.socket,
                sink=self.fte_client_socket,
                encoder=fte_stream.encoder,
                dieAfterSend=shouldDieAfterSend,
            )
            decoder = DecoderThread(
                lock,
                'server',
                stream_id=stream_id,
                source=fte_stream.socket,
                sink=self.fte_client_socket,
                decoder=fte_stream.decoder,
                dieAfterSend=shouldDieAfterSend,
            )
            decoder.data += data
            encoder.peer = decoder
            decoder.peer = encoder
            encoder.start()
            decoder.start()
            decoder.join()
            encoder.join()
            fte.logger.performance_write()
            if decoder.exception:
                LOG(('ServerDemuxer', 'decoder.exception',
                    decoder.exception), stream_id, -1)
                raise decoder.exception
            if encoder.exception:
                LOG(('ServerDemuxer', 'encoder.exception',
                    encoder.exception), stream_id, -1)
                raise encoder.exception
            socksConnectionDead = encoder.source_alive == False
            if socksConnectionDead:
                LOG(('ServerDemuxer', 'socksConnectionDead'),
                    stream_id, -1)
                if fte.conf.getValue('runtime.http_proxy.enable'):
                    pass
                else:
                    fte_stream.stopTCPConnection()
                    pass
            fteClientConnectionDead = encoder.sink_alive == False
            if fteClientConnectionDead:
                LOG(('ServerDemuxer', 'fteClientConnectionDead'),
                    stream_id, -1)
                fte_stream.stopTCPConnection()
        except TerminateStreamException, e:
            with self.encoder_cache_lock:
                fte_stream.stopTCPConnection()
        except NotMyStreamException, e:
            pass
        except TCPResetException, e:
            pass
        if fte_stream:
            fte_stream.stopTCPConnection()

        if fte.conf.getValue('runtime.fte.relay.forceful_shutdown'):
            try:
                self.fte_client_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
        try:
            self.fte_client_socket.close()
        except:
            pass


class ClientMuxer(threading.Thread):

    def __init__(self, socks_client_socket, fte_stream):
        threading.Thread.__init__(self)
        self.socks_client_socket = socks_client_socket
        self.fte_stream = fte_stream

    def run(self):
        try:
            self.fte_stream.startTCPConnection()
            covertext = negotiate(self.fte_stream.encoder.encrypter,
                                  self.fte_stream.encoder.encoder)
            sendall_to_socket(self.fte_stream.socket, covertext)
            try:
                while True:
                    [success, data] = \
                        recvall_from_socket(self.fte_stream.socket,
                                            True)
                    if data:
                        break
                    if not success:
                        self.fte_stream.stopTCPConnection()
                        return
                one_off_decode(self.fte_stream.encoder.encrypter,
                               self.fte_stream.decoder.encoder, data)
            except fte.encrypter.NegotiateAcknowledgeExecption:
                pass
            else:
                self.fte_stream.stopTCPConnection()
                return
            lock = threading.Lock()
            encoder = EncoderThread(
                lock,
                'client',
                stream_id=self.fte_stream.stream_id,
                source=self.socks_client_socket,
                sink=self.fte_stream.socket,
                encoder=self.fte_stream.encoder,
            )
            decoder = DecoderThread(
                lock,
                'client',
                stream_id=self.fte_stream.stream_id,
                source=self.socks_client_socket,
                sink=self.fte_stream.socket,
                decoder=self.fte_stream.decoder,
            )
            encoder.peer = decoder
            decoder.peer = encoder
            encoder.start()
            decoder.start()
            encoder.join()
            decoder.join()
            fte.logger.performance_write()
            if decoder.exception:
                raise decoder.exception
            if encoder.exception:
                raise encoder.exception
            self.fte_stream.terminateFTEStream()
            self.fte_stream.stopTCPConnection()
        except TCPResetException:
            self.fte_stream.stopTCPConnection()
        self.fte_stream.stopTCPConnection()
        if fte.conf.getValue('runtime.fte.relay.forceful_shutdown'):
            try:
                self.socks_client_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
        try:
            self.socks_client_socket.close()
        except:
            pass


class FTEDispatcher(multiprocessing.Process):

    def __init__(
        self,
        listen_ip,
        listen_port,
        fwd_ip,
        fwd_port,
        encrypter,
        encoder,
        decoder,
        mode,
    ):
        multiprocessing.Process.__init__(self)
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.fwd_ip = fwd_ip
        self.fwd_port = fwd_port
        self.encrypter = encrypter
        self.encoder = encoder
        self.decoder = decoder
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if mode == 'server':
            self.sock.settimeout(SERVER_TIMEOUT)
        elif mode == 'client':
            self.sock.settimeout(CLIENT_TIMEOUT)
        if fte.conf.getValue('runtime.fte.relay.nolinger'):
            l_onoff = 1
            l_linger = 0
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack('ii', l_onoff, l_linger))
        self.sock.bind((listen_ip, listen_port))
        self.sock.listen(fte.conf.getValue('runtime.fte.relay.backlog'))
        self.encoder_cache = {}
        self.encoder_cache_lock = threading.Lock()
        self.pid_file = None
        self.ready = False

    def run(self):
        if fte.conf.getValue('runtime.mode') == 'client':
            fte.encoder.RegexEncoder(fte.conf.getValue('runtime.state.upstream_language'
                                                       ))
            fte.encoder.RegexEncoder(fte.conf.getValue('runtime.state.downstream_language'
                                                       ))
        else:
            for lang in fte.conf.getValue('languages.regex'):
                if fte.conf.getValue('runtime.console.debug'):
                    print ('building...', lang)
                fte.encoder.RegexEncoder(lang)
        pid_file = os.path.join(fte.conf.getValue('general.pid_dir'),
                                '.' + fte.conf.getValue('runtime.mode')
                                + '-' + str(os.getpid()) + '.pid')
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
        self.pid_file = pid_file
        if fte.conf.getValue('runtime.console.debug'):
            print (fte.conf.getValue('runtime.mode'), '(pid='
                   + str(os.getpid()) + ')', 'READY!')
        while True:
            try:
                self.ready = True
                (incoming_socket, address) = self.sock.accept()
                fte_stream_factory = FTEStreamFactory(
                    self.listen_ip,
                    self.listen_port,
                    self.fwd_ip,
                    self.fwd_port,
                    self.encrypter,
                    self.encoder,
                    self.decoder,
                )
                if self.mode == 'server':
                    muxer = ServerDemuxer(incoming_socket, address,
                                          fte_stream_factory,
                                          self.encoder_cache_lock, self.encoder_cache)
                    muxer.start()
                elif self.mode == 'client':
                    stream_id = int(address[1])
                    fte_stream = \
                        fte_stream_factory.createStream(stream_id)
                    muxer = ClientMuxer(incoming_socket, fte_stream)
                    muxer.start()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
        if self.pid_file and os.path.exists(self.pid_file):
            os.unlink(self.pid_file)
            if fte.conf.getValue('runtime.console.debug'):
                print (fte.conf.getValue('runtime.mode'), '(pid='
                       + str(os.getpid()) + ') shut down cleanly')


def cheap_copy(obj):
    retval = None
    if obj.compound == True:
        tmpA = obj.singletonEncoderA.format_package
        tmpB = obj.singletonEncoderB.format_package
        obj.singletonEncoderA.format_package = None
        obj.singletonEncoderB.format_package = None
        retval = copy.deepcopy(obj)
        obj.singletonEncoderA.format_package = tmpA
        obj.singletonEncoderB.format_package = tmpB
        retval.singletonEncoderA.format_package = tmpA
        retval.singletonEncoderB.format_package = tmpB
    else:
        tmp_ = obj.format_package
        obj.format_package = None
        retval = copy.deepcopy(obj)
        obj.format_package = tmp_
        retval.format_package = tmp_
    return retval


class FTEStreamFactory(object):

    def __init__(
        self,
        listen_ip,
        listen_port,
        fwd_ip,
        fwd_port,
        encrypter,
        encoder,
        decoder,
    ):
        self.fwd_ip = fwd_ip
        self.fwd_port = fwd_port
        self.encrypter = copy.deepcopy(encrypter)
        self.encoder = None
        if encoder:
            self.encoder = cheap_copy(encoder)
        self.decoder = None
        if decoder:
            self.decoder = cheap_copy(decoder)

    def createStream(self, stream_id):
        rl_encoder = fte.record_layer.RecordLayerEncoder(stream_id,
                                                         None, self.encrypter, self.encoder)
        rl_decoder = fte.record_layer.RecordLayerDecoder(stream_id,
                                                         None, self.encrypter, self.decoder)
        fte_stream = FTEStream(stream_id, self.fwd_ip, self.fwd_port,
                               rl_encoder, rl_decoder)
        return fte_stream


class FTEStream(object):

    def __init__(
        self,
        stream_id,
        remote_ip,
        remote_port,
        encoder,
        decoder,
    ):
        self.stream_id = stream_id
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.socket = None
        self.encoder = encoder
        self.decoder = decoder

    def startTCPConnection(self):
        if self.socket == None:
            self.socket = socket.socket(socket.AF_INET,
                                        socket.SOCK_STREAM)
            self.socket.settimeout(CLIENT_TIMEOUT)
            if fte.conf.getValue('runtime.fte.relay.nolinger'):
                l_onoff = 1
                l_linger = 0
                self.socket.setsockopt(socket.SOL_SOCKET,
                                       socket.SO_LINGER, struct.pack(
                                           'ii', l_onoff,
                                           l_linger))
            self.socket.connect((self.remote_ip, self.remote_port))
            if fte.conf.getValue('runtime.mode') == 'client':
                save_connection_information(['connect',
                                             str(int(round(time.time()))),
                                             str(self.socket.getsockname()[1]),
                                             str(self.remote_port),
                                             fte.conf.getValue('runtime.state.upstream_language'
                                                               )[:-8]])

    def stopTCPConnection(self):
        if self.socket != None:
            if fte.conf.getValue('runtime.mode') == 'client':
                save_connection_information(['terminate',
                                             str(int(round(time.time()))),
                                             str(self.socket.getsockname()[1]),
                                             str(self.remote_port),
                                             fte.conf.getValue('runtime.state.upstream_language'
                                                               )[:-8]])
            if fte.conf.getValue('runtime.fte.relay.forceful_shutdown'):
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass
            try:
                self.socket.close()
            except:
                pass
            self.socket = None

    def resetTCPConnection(self):
        self.stopTCPConnection()
        self.startTCPConnection()

    def terminateFTEStream(self):
        pass


class forwarder(object):

    def __init__(
        self,
        host,
        port,
        remoteip,
        remoteport,
        encrypter,
        encoder,
        decoder,
        mode,
    ):
        self.dispatcher = FTEDispatcher(
            host,
            port,
            remoteip,
            remoteport,
            encrypter,
            encoder,
            decoder,
            mode,
        )
        self.dispatcher.start()