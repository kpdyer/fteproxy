#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The relay: the two roles that move bytes between a socket and a tunnel.

Server
    :class:`ServerListener` accepts fteproxy connections and hands each one to
    a setup thread, which completes the handshake, reads the client's OPEN,
    checks it against the allow rules, dials the destination, answers with an
    OPEN_RESULT, and only then starts the two workers. Nothing slow happens on
    the accept loop, so one client dialling a distant or dead host no longer
    stalls every other client's connect.

Client
    :class:`SocksListener` (``-D``) speaks SOCKS5 to local applications and
    :class:`ForwardListener` (``-L``) sends every connection to one fixed
    destination. Both do the same thing per accepted connection: dial the
    fteproxy server, handshake, send OPEN, wait for OPEN_RESULT, then relay.

The workers themselves are unchanged from 0.3: a ``select`` poll with a small
throttle. That loop looks wasteful and is not -- the throttle is a GIL-yield
that keeps the two workers of a connection from convoying, and removing it
costs an order of magnitude in a real two-process deployment. See
PERFORMANCE.md. What has changed is that the handshake no longer happens
inside them, so neither worker touches a half-built encoder any more.
"""

import socket
import threading
import time

import fteproxy
import fteproxy.conf
import fteproxy.network_io
import fteproxy.record_layer
import fteproxy.socks
import fteproxy.stream


#: How long to wait for a destination to accept our connection.
DIAL_TIMEOUT = 10


class worker(threading.Thread):

    """Forwards everything arriving on ``socket1`` to ``socket2``.

    One direction per worker; a connection runs two. The thread ends when
    ``socket1`` reaches end of stream, and then tells ``socket2`` that this
    direction is finished without closing it, so the other direction can drain.
    ``on_finish`` is how :class:`Connection` learns to close both.
    """

    def __init__(self, socket1, socket2, on_finish=None):
        threading.Thread.__init__(self)
        self._socket1 = socket1
        self._socket2 = socket2
        self._on_finish = on_finish
        self._running = False

    def run(self):
        """Forward data from ``socket1`` to ``socket2`` until ``socket1`` ends.

        Terminates when ``fteproxy.network_io.recvall_from_socket`` reports
        that ``socket1`` is no longer alive.
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
            half_close(self._socket2)
            if self._on_finish is not None:
                self._on_finish()

    def stop(self):
        """Terminate the thread."""
        self._running = False


def half_close(sock):
    """Tell ``sock``'s peer that nothing more will be sent, without closing.

    An fteproxy socket carries this as a CLOSE record; a plain socket as
    ``shutdown(SHUT_WR)``. Either way the peer sees end of stream on its read
    side and can still answer, which is what an HTTP request that ends while
    the response is still coming needs.
    """
    try:
        if hasattr(sock, 'close_write'):
            sock.close_write()
        else:
            sock.shutdown(socket.SHUT_WR)
    except OSError as e:
        fteproxy.debug('half-close failed: %s' % e)


class Connection:
    """Two sockets and the pair of workers that pump between them.

    Both sockets are closed once *both* directions have ended, rather than as
    soon as either does, so a half-closed stream still delivers the rest of
    the other direction.
    """

    def __init__(self, socket1, socket2, on_close=None):
        self._sockets = (socket1, socket2)
        self._outstanding = 2
        self._lock = threading.Lock()
        self._workers = []
        self._on_close = on_close

    def start(self):
        for source, sink in (self._sockets, self._sockets[::-1]):
            thread = worker(source, sink, on_finish=self._finished)
            thread.daemon = True
            self._workers.append(thread)
            thread.start()
        return self

    def _finished(self):
        with self._lock:
            self._outstanding -= 1
            if self._outstanding > 0:
                return
        self.close()

    def close(self):
        for sock in self._sockets:
            fteproxy.network_io.close_socket(sock)
        if self._on_close is not None:
            self._on_close(self)

    def stop(self):
        for thread in self._workers:
            thread.stop()
        self.close()


class listener(threading.Thread):

    """Binds a local address and serves each accepted connection on its own
    thread. Subclasses implement :meth:`serve`.
    """

    def __init__(self, local_ip, local_port):
        threading.Thread.__init__(self)
        self._running = False
        self._sock = None
        self._local_ip = local_ip
        self._local_port = local_port
        # Live connections, so that stop() can tear them down. Entries remove
        # themselves when both directions end; a long-running server would
        # otherwise hold one per connection it had ever accepted.
        self._connections = set()
        self._connections_lock = threading.Lock()

    @property
    def address(self):
        """The address actually bound, which is what port 0 resolves to."""
        if self._sock is None:
            return (self._local_ip, self._local_port)
        return self._sock.getsockname()[:2]

    def bind(self):
        """Bind and listen, raising ``OSError`` on failure.

        Separate from :meth:`run` so a caller can claim the port on the main
        thread and report a bind failure with a non-zero exit status. Binding
        inside the thread instead only killed the thread, and the process went
        on to exit 0.

        An empty host means every interface, which is one socket on the usual
        Unix system (``::`` with ``IPV6_V6ONLY`` off accepts IPv4 too) and two
        families on one that will not allow that, so the fallback is a plain
        IPv4 bind rather than an error.
        """
        if not self._local_ip:
            try:
                self._sock = self._bind_socket(socket.AF_INET6, '::',
                                               dual_stack=True)
                return
            except OSError as e:
                fteproxy.debug('dual-stack bind failed (%s); using IPv4' % e)
                self._sock = self._bind_socket(socket.AF_INET, '0.0.0.0')
                return
        family = socket.AF_INET6 if ':' in self._local_ip else socket.AF_INET
        self._sock = self._bind_socket(family, self._local_ip)

    def _bind_socket(self, family, host, dual_stack=False):
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if dual_stack:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind((host, self._local_port))
            sock.listen(fteproxy.conf.getValue('runtime.fteproxy.relay.backlog'))
            sock.settimeout(
                fteproxy.conf.getValue('runtime.fteproxy.relay.accept_timeout'))
        except OSError:
            sock.close()
            raise
        return sock

    def run(self):
        if self._sock is None:
            try:
                self.bind()
            except OSError as e:
                fteproxy.fatal_error(
                    'Failed to bind to %s:%s: %s'
                    % (self._local_ip, self._local_port, e))

        self._running = True
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError as e:
                if self._running:
                    fteproxy.warn('accept failed: %s' % e)
                break
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(
                fteproxy.conf.getValue('runtime.fteproxy.relay.socket_timeout'))
            # A setup thread per connection: the handshake, the OPEN and the
            # dial all block, and none of them may hold up the accept loop.
            thread = threading.Thread(target=self._serve, args=(conn, addr))
            thread.daemon = True
            thread.start()

    def _serve(self, conn, addr):
        try:
            connection = self.serve(conn, addr)
        except Exception as e:
            fteproxy.warn('connection from %s failed: %s' % (_host(addr), e))
            fteproxy.network_io.close_socket(conn)
            return
        if connection is None:
            return
        with self._connections_lock:
            if not self._running:
                # stop() ran while this connection was being set up.
                connection.close()
                return
            self._connections.add(connection)
        connection.start()

    def _forget(self, connection):
        with self._connections_lock:
            self._connections.discard(connection)

    def serve(self, conn, addr):
        """Set one accepted connection up and return a :class:`Connection`,
        or None if it was handled and closed."""
        raise NotImplementedError

    def stop(self):
        """Stop listening and tear down the connections still open."""
        self._running = False
        if self._sock is not None:
            fteproxy.network_io.close_socket(self._sock)
        with self._connections_lock:
            open_connections = list(self._connections)
            self._connections.clear()
        for connection in open_connections:
            connection.stop()


def _host(addr):
    return '%s:%s' % (addr[0], addr[1]) if addr else 'an unknown peer'


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #

class ServerListener(listener):
    """Accepts fteproxy connections and dials wherever each one asks.

    The destination is in band, so this end needs no forward address; what it
    needs instead is a policy, which is :class:`fteproxy.stream.AllowRules`.
    """

    def __init__(self, local_ip, local_port, server_key, rules=None):
        listener.__init__(self, local_ip, local_port)
        self._server_key = server_key
        self._rules = rules if rules is not None else fteproxy.stream.AllowRules()

    def serve(self, conn, addr):
        tunnel = fteproxy.wrap_socket(conn, server_key=self._server_key)
        try:
            tunnel.handshake()
        except fteproxy.HandshakeFailedException:
            # Never reply, never explain: reject_and_close reads and discards
            # for a random interval first, so a prober cannot tell this from a
            # service with nothing to say.
            tunnel.reject_and_close()
            return None
        except fteproxy._PeerClosed:
            fteproxy.network_io.close_socket(conn)
            return None

        timeout = fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout')
        try:
            destination = tunnel.wait_open(timeout=timeout)
        except (fteproxy.ChannelNotReadyException,
                fteproxy.stream.InvalidAddress) as e:
            fteproxy.debug('no usable OPEN from %s: %s' % (_host(addr), e))
            fteproxy.network_io.close_socket(tunnel)
            return None
        if destination is None:
            fteproxy.debug('%s closed before sending an OPEN' % _host(addr))
            fteproxy.network_io.close_socket(tunnel)
            return None

        host, port = destination
        status, upstream = fteproxy.stream.connect(
            host, port, self._rules, DIAL_TIMEOUT)
        try:
            tunnel.open_result(status)
        except OSError as e:
            fteproxy.debug('could not answer an OPEN: %s' % e)
            if upstream is not None:
                fteproxy.network_io.close_socket(upstream)
            fteproxy.network_io.close_socket(tunnel)
            return None

        if status != fteproxy.stream.SUCCEEDED:
            fteproxy.info('refused %s:%d for %s: %s'
                          % (host, port, _host(addr),
                             fteproxy.stream.status_name(status)))
            fteproxy.network_io.close_socket(tunnel)
            return None

        fteproxy.debug('%s -> %s:%d' % (_host(addr), host, port))
        upstream.settimeout(
            fteproxy.conf.getValue('runtime.fteproxy.relay.socket_timeout'))
        return Connection(tunnel, upstream, on_close=self._forget)


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

class _ClientListener(listener):
    """Shared machinery for the client's listener kinds.

    Each accepted local connection gets its own tunnel: dial the server,
    handshake, OPEN, wait for the answer. Subclasses decide where the
    destination comes from and what to tell the local application.
    """

    def __init__(self, local_ip, local_port, server_address, server_id,
                 format=None, mode=None, defs=None):
        listener.__init__(self, local_ip, local_port)
        self._server_address = server_address
        self._server_id = server_id
        self._format = format
        self._mode = mode
        self._defs = defs

    def dial_tunnel(self):
        """Open and handshake one tunnel to the fteproxy server."""
        raw = socket.create_connection(
            self._server_address,
            timeout=fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout'))
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        tunnel = fteproxy.wrap_socket(raw, server_id=self._server_id,
                                      format=self._format, mode=self._mode,
                                      defs=self._defs)
        try:
            tunnel.handshake()
        except Exception:
            fteproxy.network_io.close_socket(raw)
            raise
        tunnel.settimeout(
            fteproxy.conf.getValue('runtime.fteproxy.relay.socket_timeout'))
        return tunnel

    def check(self):
        """Dial the server once, handshake, and close.

        The client's startup check: a wrong connection string fails here, in
        about a round trip, with a reason, instead of as a timeout on the
        first real connection. On the wire it is one short session, the same
        shape as any other.
        """
        tunnel = self.dial_tunnel()
        try:
            return (tunnel.negotiated_format, tunnel.negotiated_mode)
        finally:
            fteproxy.network_io.close_socket(tunnel)

    def open_stream(self, destination):
        """Dial the server and ask it for ``destination``.

        Returns the tunnel; raises :class:`fteproxy.OpenRefused` with the
        server's status when it will not open the stream.
        """
        tunnel = self.dial_tunnel()
        try:
            tunnel.open(destination,
                        timeout=fteproxy.conf.getValue(
                            'runtime.fteproxy.relay.socket_timeout'))
        except Exception:
            fteproxy.network_io.close_socket(tunnel)
            raise
        return tunnel


class ForwardListener(_ClientListener):
    """``-L [BIND:]PORT:HOST:PORT``: everything here goes to one destination."""

    def __init__(self, local_ip, local_port, server_address, server_id,
                 destination, **kwargs):
        _ClientListener.__init__(self, local_ip, local_port, server_address,
                                 server_id, **kwargs)
        self._destination = destination

    def serve(self, conn, addr):
        try:
            tunnel = self.open_stream(self._destination)
        except fteproxy.OpenRefused as e:
            fteproxy.info('%s -> %s:%d refused: %s'
                          % (_host(addr), self._destination[0],
                             self._destination[1],
                             fteproxy.stream.status_name(e.status)))
            fteproxy.network_io.close_socket(conn)
            return None
        return Connection(conn, tunnel, on_close=self._forget)


class SocksListener(_ClientListener):
    """``-D [BIND:]PORT``: a SOCKS5 CONNECT proxy over the tunnel."""

    def serve(self, conn, addr):
        try:
            destination = fteproxy.socks.handshake(conn)
        except fteproxy.socks.SocksError as e:
            fteproxy.debug('SOCKS request from %s refused: %s'
                           % (_host(addr), e))
            fteproxy.network_io.close_socket(conn)
            return None

        try:
            tunnel = self.open_stream(destination)
        except fteproxy.OpenRefused as e:
            fteproxy.info('%s -> %s:%d refused: %s'
                          % (_host(addr), destination[0], destination[1],
                             fteproxy.stream.status_name(e.status)))
            self._fail(conn, e.status)
            return None
        except OSError as e:
            fteproxy.info('%s -> %s:%d failed: %s'
                          % (_host(addr), destination[0], destination[1], e))
            self._fail(conn, fteproxy.stream.GENERAL_FAILURE)
            return None

        try:
            fteproxy.socks.send_reply(conn, fteproxy.stream.SUCCEEDED)
        except OSError:
            fteproxy.network_io.close_socket(conn)
            fteproxy.network_io.close_socket(tunnel)
            return None
        return Connection(conn, tunnel, on_close=self._forget)

    @staticmethod
    def _fail(conn, status):
        try:
            fteproxy.socks.send_reply(conn, status)
        except OSError:
            pass
        fteproxy.network_io.close_socket(conn)
