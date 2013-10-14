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

# You should have received a copy of the GNU General Public License
# along with FTE.  If not, see <http://www.gnu.org/licenses/>.

#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import asyncore
import select
import time
import struct
import fte.conf
import fte.logger
LOG_LEVEL = fte.conf.getValue('loglevel.fte.tcp.relay')
BLOCK_SIZE = fte.conf.getValue('runtime.fte.tcp.relay.block_size')
BACKLOG = fte.conf.getValue('runtime.tcp.relay.backlog')
TIMEOUT = 30


class forwarder(asyncore.dispatcher):

    def __init__(
        self,
        ip,
        port,
        remoteip,
        remoteports,
    ):
        asyncore.dispatcher.__init__(self)
        self.remoteip = remoteip
        self.remoteports = remoteports
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        if fte.conf.getValue('runtime.tcp.relay.nolinger'):
            l_onoff = 1
            l_linger = 0
            self.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack('ii', l_onoff, l_linger))
        self.settimeout(TIMEOUT)
        self.set_reuse_addr()
        self.bind((ip, port))
        self.listen(BACKLOG)
        self.robin = 0

    def handle_accept(self):
        (conn, addr) = self.accept()
        fte.logger.debug(LOG_LEVEL, ('--- Connect --- ', self.robin,
                         addr))
        sender(receiver(conn), self.remoteip,
               self.remoteports[self.robin])
        self.robin += 1
        self.robin %= len(self.remoteports)


class receiver(asyncore.dispatcher):

    def __init__(self, conn):
        asyncore.dispatcher.__init__(self, conn)
        self.from_remote_buffer = ''
        self.to_remote_buffer = ''
        self.sender = None

    def handle_connect(self):
        pass

    def handle_read(self):
        ready = select.select([self], [], [self], 0.1)
        if ready[0]:
            read = self.recv(BLOCK_SIZE)
            fte.logger.debug(LOG_LEVEL, '%04i -->' % len(read))
            self.from_remote_buffer += read

    def writable(self):
        return len(self.to_remote_buffer) > 0

    def handle_write(self):
        sent = self.send(self.to_remote_buffer)
        fte.logger.debug(LOG_LEVEL, '%04i <--' % sent)
        self.to_remote_buffer = self.to_remote_buffer[sent:]

    def handle_close(self):
        if fte.conf.getValue('runtime.tcp.relay.forceful_shutdown'):
            try:
                self.shutdown(socket.SHUT_RDWR)
            except:
                pass
        try:
            self.close()
        except:
            pass
        if fte.conf.getValue('runtime.tcp.relay.forceful_shutdown'):
            try:
                self.sender.shutdown(socket.SHUT_RDWR)
            except:
                pass
        try:
            self.sender.close()
        except:
            pass


class sender(asyncore.dispatcher):

    def __init__(
        self,
        receiver,
        remoteaddr,
        remoteport,
    ):
        asyncore.dispatcher.__init__(self)
        self.receiver = receiver
        receiver.sender = self
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.settimeout(TIMEOUT)
        if fte.conf.getValue('runtime.tcp.relay.nolinger'):
            l_onoff = 1
            l_linger = 0
            self.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack('ii', l_onoff, l_linger))
        self.connect((remoteaddr, remoteport))

    def handle_connect(self):
        pass

    def handle_read(self):
        ready = select.select([self], [], [self], 0.1)
        if ready[0]:
            read = self.recv(BLOCK_SIZE)
            fte.logger.debug(LOG_LEVEL, '<-- %04i' % len(read))
            self.receiver.to_remote_buffer += read

    def writable(self):
        return len(self.receiver.from_remote_buffer) > 0

    def handle_write(self):
        sent = self.send(self.receiver.from_remote_buffer)
        fte.logger.debug(LOG_LEVEL, '--> %04i' % sent)
        self.receiver.from_remote_buffer = \
            self.receiver.from_remote_buffer[sent:]

    def handle_close(self):
        if fte.conf.getValue('runtime.tcp.relay.forceful_shutdown'):
            try:
                self.shutdown(socket.SHUT_RDWR)
            except:
                pass
        try:
            self.close()
        except:
            pass
        if fte.conf.getValue('runtime.tcp.relay.forceful_shutdown'):
            try:
                self.receiver.shutdown(socket.SHUT_RDWR)
            except:
                pass
        try:
            self.receiver.close()
        except:
            pass