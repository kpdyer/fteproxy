#!/usr/bin/env python
# -*- coding: utf-8 -*-



import time
import socket
import threading

import fteproxy.conf
import fteproxy.network_io


class worker(threading.Thread):

    """``fteproxy.relay.worker`` is responsible for relaying data between two sockets. Given ``socket1`` and
    ``socket2``, the worker will forward all data
    from ``socket1`` to ``socket2``, and ``socket2`` to ``socket1``. This class is a subclass of
    threading.Thread and does not start relaying until start() is called. The run
    method terminates when either ``socket1`` or ``socket2`` is detected to be closed.
    """

    def __init__(self, socket1, socket2):
        threading.Thread.__init__(self)
        self._socket1 = socket1
        self._socket2 = socket2
        self._running = False

    def run(self):
        """It's the responsibility of run to forward data from ``socket1`` to
        ``socket2`` and from ``socket2`` to ``socket1``. The ``run()`` method
        terminates and closes both sockets if ``fteproxy.network_io.recvall_from_socket``
        returns a negative result for ``success``.
        """
        
        self._running = True
        try:
            throttle = fteproxy.conf.getValue('runtime.fteproxy.relay.throttle')
            while self._running:
                [success, _data] = fteproxy.network_io.recvall_from_socket(
                    self._socket1)
                if not success:
                    break
                if _data:
                    fteproxy.network_io.sendall_to_socket(self._socket2, _data)
                else:
                    time.sleep(throttle)
        except Exception as e:
            fteproxy.warn("fteproxy.worker terminated prematurely: " + str(e))
        finally:
            fteproxy.network_io.close_socket(self._socket1)
            fteproxy.network_io.close_socket(self._socket2)

    def stop(self):
        """Terminate the thread and stop listening on ``local_ip:local_port``.
        """
        self._running = False


class listener(threading.Thread):

    """It's the responsibility of ``fteproxy.relay.listener`` to bind to
    ``local_ip:local_port``. Once bound it will then relay all incoming connections
    to ``remote_ip:remote_port``.
    All new incoming connections are wrapped with ``onNewIncomingConnection``.
    All new outgoing connections are wrapped with ``onNewOutgoingConnection``.
    By default the functions ``onNewIncomingConnection`` and
    ``onNewOutgoingConnection`` are the identity function.
    """

    def __init__(self, local_ip, local_port,
                 remote_ip, remote_port):
        threading.Thread.__init__(self)

        self._running = False
        self._local_ip = local_ip
        self._local_port = local_port
        self._remote_ip = remote_ip
        self._remote_port = remote_port

    def _instantiateSocket(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self._local_ip, self._local_port))
            self._sock.listen(fteproxy.conf.getValue('runtime.fteproxy.relay.backlog'))
            self._sock.settimeout(
                fteproxy.conf.getValue('runtime.fteproxy.relay.accept_timeout'))
        except Exception as e:
            fteproxy.fatal_error('Failed to bind to ' +
                            str((self._local_ip, self._local_port)) + ': ' + str(e))

    def run(self):
        """Bind to ``local_ip:local_port`` and forward all connections to
        ``remote_ip:remote_port``.
        """
        self._instantiateSocket()

        self._running = True
        while self._running:
            try:
                conn, addr = self._sock.accept()

                new_stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                new_stream.connect((self._remote_ip, self._remote_port))

                conn = self.onNewIncomingConnection(conn)
                new_stream = self.onNewOutgoingConnection(new_stream)

                conn.settimeout(
                    fteproxy.conf.getValue('runtime.fteproxy.relay.socket_timeout'))
                new_stream.settimeout(
                    fteproxy.conf.getValue('runtime.fteproxy.relay.socket_timeout'))

                w1 = worker(conn, new_stream)
                w2 = worker(new_stream, conn)
                w1.start()
                w2.start()
            except socket.timeout:
                continue
            except socket.error as e:
                fteproxy.warn('socket.error in fteproxy.listener: ' + str(e))
                continue
            except Exception as e:
                fteproxy.warn('exception in fteproxy.listener: ' + str(e))
                break
            
    def stop(self):
        """Terminate the thread and stop listening on ``local_ip:local_port``.
        """
        self._running = False
        fteproxy.network_io.close_socket(self._sock)

    def onNewIncomingConnection(self, socket):
        """``onNewIncomingConnection`` returns the socket unmodified, by default we do not need to
        perform any modifications to incoming data streams.
        """

        return socket

    def onNewOutgoingConnection(self, socket):
        """``onNewOutgoingConnection`` returns the socket unmodified, by default we do not need to
        perform any modifications to incoming data streams.
        """

        return socket
