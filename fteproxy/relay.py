#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import time
import socket
import threading

import fteproxy.conf
import fteproxy.network_io


class _link(object):

    """The state shared by the two ``worker`` threads that relay one
    connection, one per direction. It counts the directions still open and
    closes both sockets exactly once, so a half-close in one direction leaves
    the other relaying and an error in either tears the whole connection down.
    """

    def __init__(self, socket1, socket2, directions=2):
        self._sockets = (socket1, socket2)
        self._lock = threading.Lock()
        self._open_directions = directions
        self._closed = False

    def direction_done(self):
        """Record that one direction reached EOF. Returns ``True`` once every
        direction has, i.e. when the connection can be closed.
        """
        with self._lock:
            self._open_directions -= 1
            return self._open_directions <= 0

    def close(self):
        """Close both sockets. Safe to call from both workers."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        for sock in self._sockets:
            fteproxy.network_io.close_socket(sock)


class worker(threading.Thread):

    """``fteproxy.relay.worker`` is responsible for relaying data from
    ``socket1`` to ``socket2``. A connection is relayed by two workers, one per
    direction, created together with ``worker.pair`` so they share one
    ``_link``. This class is a subclass of threading.Thread and does not start
    relaying until start() is called.

    When ``socket1`` reports EOF the worker forwards the half-close with
    ``socket2.shutdown(SHUT_WR)`` and terminates, but the sockets stay open
    while the sibling worker still relays the other direction; TCP half-close
    (``shutdown(SHUT_WR)``, ``echo x | nc``, HTTP/1.0-style request/response)
    therefore works through the relay. Both sockets are closed once both
    directions have seen EOF, or as soon as either worker fails.

    A worker constructed on its own (without ``pair``) owns the connection
    alone and closes both sockets as soon as ``socket1`` reports EOF.
    """

    def __init__(self, socket1, socket2, link=None):
        threading.Thread.__init__(self)
        self._socket1 = socket1
        self._socket2 = socket2
        if link is None:
            link = _link(socket1, socket2, directions=1)
        self._link = link
        self._running = False

    @classmethod
    def pair(cls, socket1, socket2):
        """Return the two workers that relay one connection in both
        directions, sharing the state that decides when it is closed.
        """
        link = _link(socket1, socket2)
        return [cls(socket1, socket2, link), cls(socket2, socket1, link)]

    def run(self):
        """It's the responsibility of run to forward data from ``socket1`` to
        ``socket2``. When ``fteproxy.network_io.recvall_from_socket`` reports
        that ``socket1`` is no longer alive, ``run()`` half-closes ``socket2``
        and terminates; the sockets are closed once the sibling worker (if
        any) has finished too. Any other failure closes both sockets at once.
        """

        self._running = True
        teardown = True
        try:
            throttle = fteproxy.conf.getValue('runtime.fteproxy.relay.throttle')
            while self._running:
                [success, _data] = fteproxy.network_io.recvall_from_socket(
                    self._socket1)
                if not success:
                    # Every byte read before EOF has already been handed to
                    # socket2, so the FIN lands after the data. The sibling
                    # keeps relaying socket2 -> socket1 until it sees EOF too.
                    self._half_close()
                    teardown = self._link.direction_done()
                    break
                if _data:
                    fteproxy.network_io.sendall_to_socket(self._socket2, _data)
                else:
                    time.sleep(throttle)
        except Exception as e:
            teardown = True
            fteproxy.warn("fteproxy.worker terminated prematurely: " + str(e))
        finally:
            if teardown:
                self._link.close()

    def _half_close(self):
        """Tell ``socket2``'s peer that this direction has no more data."""
        try:
            self._socket2.shutdown(socket.SHUT_WR)
        except OSError:
            # Already closed or reset; the sibling worker finds that out on
            # its own the next time it touches the socket.
            pass

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

                # Disable Nagle's algorithm on both hops. fteproxy is an
                # interactive tunnel that emits small encoded cells; Nagle would
                # hold a small segment for up to ~40 ms waiting to coalesce,
                # which directly inflates round-trip latency.
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                new_stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                conn = self.onNewIncomingConnection(conn)
                new_stream = self.onNewOutgoingConnection(new_stream)

                conn.settimeout(
                    fteproxy.conf.getValue('runtime.fteproxy.relay.socket_timeout'))
                new_stream.settimeout(
                    fteproxy.conf.getValue('runtime.fteproxy.relay.socket_timeout'))

                w1, w2 = worker.pair(conn, new_stream)
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
