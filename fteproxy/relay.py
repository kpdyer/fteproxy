#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCP relay listeners, admission limits, and bidirectional workers.

Server setup performs handshake, OPEN, destination policy/dial, and OPEN_RESULT
before starting two relay workers. Client SOCKS/forward setup opens one tunnel
per local connection. Setup runs outside the accept loop under concurrency
limits; established server relays have separate limits.

Workers poll readiness and sleep after idle polls. Historical throttle
experiments are recorded in PERFORMANCE.md; benchmark changes to this loop.
"""

import ipaddress
import socket
import threading
import time

import fteproxy
import fteproxy.conf
import fteproxy.network_io
import fteproxy.record_layer
import fteproxy.socks
import fteproxy.stream


# Per-candidate socket-connect timeout; DNS resolution has no deadline here.
DIAL_TIMEOUT = 10


class _SetupAdmission:
    """A non-blocking global and per-source setup limit.

    The accept loop must never wait for a slot: doing so would leave accepted
    sockets queued in user space and make shutdown/load behaviour depend on an
    attacker's timeout.  Instead, :meth:`acquire` either accounts the peer and
    returns its source token, or returns ``None`` so the socket can be closed
    before a setup thread is created.
    """

    def __init__(self, maximum, per_source):
        for name, value in (('maximum', maximum),
                            ('per-source maximum', per_source)):
            if (isinstance(value, bool) or not isinstance(value, int)
                    or value < 1):
                raise ValueError('%s must be a positive integer' % name)
        self.maximum = maximum
        self.per_source = per_source
        self._total = 0
        self._by_source = {}
        self._lock = threading.Lock()

    @staticmethod
    def _source(addr):
        """Return one stable token per source IP, without its ephemeral port."""
        if not addr:
            return '<unknown>'
        host = addr[0]
        try:
            parsed = ipaddress.ip_address(host)
        except ValueError:
            return host
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            parsed = parsed.ipv4_mapped
        return str(parsed)

    def acquire(self, addr):
        source = self._source(addr)
        with self._lock:
            source_total = self._by_source.get(source, 0)
            if (self._total >= self.maximum
                    or source_total >= self.per_source):
                return None
            self._total += 1
            self._by_source[source] = source_total + 1
        return source

    def release(self, source):
        with self._lock:
            source_total = self._by_source.get(source, 0)
            if source_total < 1:
                raise RuntimeError('released an unclaimed setup slot')
            self._total -= 1
            if source_total == 1:
                del self._by_source[source]
            else:
                self._by_source[source] = source_total - 1


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
        self._stopped = threading.Event()

    def run(self):
        """Forward data from ``socket1`` to ``socket2`` until ``socket1`` ends.

        Terminates when ``fteproxy.network_io.recvall_from_socket`` reports
        that ``socket1`` is no longer alive.
        """

        try:
            throttle = fteproxy.conf.getValue('runtime.fteproxy.relay.throttle')
            while not self._stopped.is_set():
                [success, _data] = fteproxy.network_io.recvall_from_socket(
                    self._socket1)
                if not success:
                    break
                if _data:
                    self._socket2.sendall(_data)
                else:
                    time.sleep(throttle)
        except Exception as e:
            fteproxy.warn("fteproxy.worker terminated prematurely: " + str(e))
        finally:
            half_close(self._socket2)
            if self._on_finish is not None:
                self._on_finish()

    def stop(self):
        """Request loop termination; Connection.stop also closes sockets to wake I/O."""
        self._stopped.set()


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
        # Starting and stopping are mutually exclusive. A listener can begin
        # shutdown after adding this connection to its live set but just before
        # calling start(); without this gate, stop() could close both sockets
        # and start() would then create workers over already-closed endpoints.
        self._start_lock = threading.RLock()
        self._workers = []
        self._on_close = on_close
        self._closed = False

    def start(self):
        with self._start_lock:
            with self._lock:
                if self._closed:
                    return self
            try:
                for source, sink in (self._sockets, self._sockets[::-1]):
                    thread = worker(source, sink, on_finish=self._finished)
                    thread.daemon = True
                    self._workers.append(thread)
                    thread.start()
            except BaseException:
                # Starting the pair is one operation. If the process runs out
                # of threads after the first starts, leaving it behind would
                # strand ``_outstanding`` at one and leak both sockets forever.
                self.stop()
                raise
        return self

    def _finished(self):
        with self._lock:
            self._outstanding -= 1
            if self._outstanding > 0:
                return
        self.close()

    def close(self):
        with self._start_lock:
            with self._lock:
                if self._closed:
                    return
                self._closed = True
            for sock in self._sockets:
                fteproxy.network_io.close_socket(sock)
            if self._on_close is not None:
                self._on_close(self)

    def stop(self):
        with self._start_lock:
            for thread in self._workers:
                thread.stop()
            self.close()


class listener(threading.Thread):

    """Binds a local address and serves each admitted connection on its own
    thread. Subclasses implement :meth:`serve` and may add admission control.
    """

    def __init__(self, local_ip, local_port):
        threading.Thread.__init__(self)
        self._running = False
        # Monotonic shutdown state. ``_running`` describes the accept loop and
        # is set by run(); on its own it lets an early stop() be overwritten by
        # a thread which has not reached run() yet.
        self._stopping = threading.Event()
        self._sock = None
        self._activated = False
        self._local_ip = local_ip
        self._local_port = local_port
        # Live connections, so that stop() can tear them down. Entries remove
        # themselves when both directions end; a long-running server would
        # otherwise hold one per connection it had ever accepted.
        self._connections = set()
        # Accepted sockets remain owned by the listener while their handshake,
        # OPEN and destination dial are still in progress. Without this set,
        # stop() cannot wake setup threads blocked on a partial peer.
        self._pending_sockets = set()
        self._connections_lock = threading.Lock()
        self._setup_admission = None
        # A listener runs on its own thread, so an accept failure cannot be
        # raised directly to serve_forever. Preserve it explicitly instead of
        # letting a failed service look like a clean stop.
        self._terminal_error = None
        self._terminal_lock = threading.Lock()

    @property
    def address(self):
        """The address actually bound, which is what port 0 resolves to."""
        if self._sock is None:
            return (self._local_ip, self._local_port)
        return self._sock.getsockname()[:2]

    def bind(self):
        """Reserve the address without accepting connections yet.

        run() activates the listener after durable startup state is ready. An empty
        host tries dual-stack IPv6 first and falls back to an IPv4-only wildcard bind.
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
        except OSError:
            sock.close()
            raise
        return sock

    def _activate(self):
        """Make a reserved socket connectable immediately before serving."""
        if self._activated:
            return
        self._sock.listen(
            fteproxy.conf.getValue('runtime.fteproxy.relay.backlog'))
        self._sock.settimeout(
            fteproxy.conf.getValue('runtime.fteproxy.relay.accept_timeout'))
        self._activated = True

    def run(self):
        if self._stopping.is_set():
            return
        try:
            if self._sock is None:
                self.bind()
            if self._stopping.is_set():
                fteproxy.network_io.close_socket(self._sock)
                return
            self._activate()
        except OSError as e:
            if self._stopping.is_set():
                return
            self._terminate('failed to listen on %s:%s: %s'
                            % (self._local_ip, self._local_port, e))
            return

        if self._stopping.is_set():
            fteproxy.network_io.close_socket(self._sock)
            return
        self._running = True
        # stop() can race the assignment above; check the monotonic event once
        # more so shutdown always wins.
        if self._stopping.is_set():
            self._running = False
            fteproxy.network_io.close_socket(self._sock)
            return
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError as e:
                if self._running:
                    self._terminate('accept failed: %s' % e)
                break
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                conn.settimeout(fteproxy.conf.getValue(
                    'runtime.fteproxy.relay.socket_timeout'))
                admission = self._admit(addr)
            except Exception as e:
                fteproxy.network_io.close_socket(conn)
                self._terminate('could not initialize an accepted socket: %s'
                                % e)
                break
            if admission is None:
                fteproxy.debug('setup limit reached; dropping %s' % _host(addr))
                fteproxy.network_io.close_socket(conn)
                continue
            with self._connections_lock:
                if not self._running:
                    track_setup = False
                else:
                    self._pending_sockets.add(conn)
                    track_setup = True
            if not track_setup:
                self._release_admission(admission)
                fteproxy.network_io.close_socket(conn)
                break
            # A setup thread per connection: the handshake, the OPEN and the
            # dial all block, and none of them may hold up the accept loop. A
            # server admission slot bounds how many such threads may exist.
            try:
                thread = threading.Thread(target=self._serve_admitted,
                                          args=(conn, addr, admission))
                thread.daemon = True
                thread.start()
            except Exception as e:
                with self._connections_lock:
                    self._pending_sockets.discard(conn)
                self._release_admission(admission)
                fteproxy.network_io.close_socket(conn)
                self._terminate('could not start connection worker: %s' % e)
                break
        self._running = False

    def _admit(self, addr):
        """Claim capacity for a setup thread, or return None to reject it.

        A bare library listener has no allocator. Server and client listener
        classes both install one, with role-specific defaults.
        """
        if self._setup_admission is None:
            return True
        return self._setup_admission.acquire(addr)

    def _release_admission(self, admission):
        """Return a token acquired by :meth:`_admit`."""
        if self._setup_admission is not None:
            self._setup_admission.release(admission)

    def _serve_admitted(self, conn, addr, admission):
        try:
            self._serve(conn, addr)
        finally:
            with self._connections_lock:
                self._pending_sockets.discard(conn)
            self._release_admission(admission)

    def _serve(self, conn, addr):
        try:
            connection = self.serve(conn, addr)
        except Exception as e:
            fteproxy.warn('connection from %s failed: %s' % (_host(addr), e))
            fteproxy.network_io.close_socket(conn)
            return
        if connection is None:
            return
        close_after_setup = False
        with self._connections_lock:
            if not self._running:
                # stop() ran while this connection was being set up.
                close_after_setup = True
            else:
                self._connections.add(connection)
        if close_after_setup:
            # Connection.close() calls _forget(), which takes this same
            # non-reentrant lock. Close only after releasing it.
            connection.close()
            return
        try:
            connection.start()
        except Exception as e:
            # Connection.start() has already stopped any half-started worker,
            # closed both sockets and removed itself from bookkeeping.
            self._terminate('could not start relay workers: %s' % e)

    def _forget(self, connection):
        with self._connections_lock:
            self._connections.discard(connection)

    def serve(self, conn, addr):
        """Set one accepted connection up and return a :class:`Connection`,
        or None if it was handled and closed."""
        raise NotImplementedError

    @property
    def terminal_error(self):
        """Why this listener stopped unexpectedly, or None while healthy."""
        with self._terminal_lock:
            return self._terminal_error

    def _terminate(self, message):
        """Record a terminal listener error and wake its foreground runner."""
        with self._terminal_lock:
            if self._terminal_error is None:
                self._terminal_error = str(message)
                fteproxy.warn('listener terminated: %s' % message)
        self._stopping.set()
        self._running = False
        if self._sock is not None:
            fteproxy.network_io.close_socket(self._sock)

    def stop(self):
        """Stop listening and tear down the connections still open."""
        self._stopping.set()
        self._running = False
        if self._sock is not None:
            fteproxy.network_io.close_socket(self._sock)
        with self._connections_lock:
            open_connections = list(self._connections)
            pending_sockets = list(self._pending_sockets)
            self._connections.clear()
            self._pending_sockets.clear()
        for sock in pending_sockets:
            fteproxy.network_io.close_socket(sock)
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

    def __init__(self, local_ip, local_port, server_key, rules=None,
                 max_pending=None, max_pending_per_source=None,
                 max_active=None, max_active_per_source=None):
        listener.__init__(self, local_ip, local_port)
        self._server_key = server_key
        self._rules = rules if rules is not None else fteproxy.stream.AllowRules()
        if max_pending is None:
            max_pending = fteproxy.conf.getValue(
                'runtime.fteproxy.relay.max_pending')
        if max_pending_per_source is None:
            max_pending_per_source = fteproxy.conf.getValue(
                'runtime.fteproxy.relay.max_pending_per_source')
        self._setup_admission = _SetupAdmission(
            max_pending, max_pending_per_source)
        if max_active is None:
            max_active = fteproxy.conf.getValue(
                'runtime.fteproxy.relay.max_active')
        if max_active_per_source is None:
            max_active_per_source = fteproxy.conf.getValue(
                'runtime.fteproxy.relay.max_active_per_source')
        self._active_admission = _SetupAdmission(
            max_active, max_active_per_source)

    def serve(self, conn, addr):
        tunnel = fteproxy.wrap_socket(conn, server_key=self._server_key)
        try:
            tunnel.handshake()
        except fteproxy.HandshakeFailedException:
            # Discard without replying until the rejection deadline, then close.
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
        active = None
        transferred = False
        try:
            # A destination that connected successfully must claim its active
            # capacity before the client is told OPEN succeeded. At capacity,
            # discard that destination and give an ordinary explicit refusal.
            if status == fteproxy.stream.SUCCEEDED:
                active = self._active_admission.acquire(addr)
                if active is None:
                    fteproxy.debug('active session limit reached for %s'
                                   % _host(addr))
                    fteproxy.network_io.close_socket(upstream)
                    upstream = None
                    status = fteproxy.stream.GENERAL_FAILURE

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
                fteproxy.conf.getValue(
                    'runtime.fteproxy.relay.socket_timeout'))

            def close_active(connection):
                try:
                    self._forget(connection)
                finally:
                    self._active_admission.release(active)

            connection = Connection(tunnel, upstream, on_close=close_active)
            transferred = True
            return connection
        except BaseException:
            if upstream is not None:
                fteproxy.network_io.close_socket(upstream)
            fteproxy.network_io.close_socket(tunnel)
            raise
        finally:
            # Once a Connection exists its idempotent close callback owns this
            # slot. Every earlier return/exception releases it here exactly once.
            if active is not None and not transferred:
                self._active_admission.release(active)


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
                 format=None, mode=None, defs=None, max_pending=None,
                 max_pending_per_source=None, setup_admission=None):
        listener.__init__(self, local_ip, local_port)
        self._server_address = server_address
        self._server_id = server_id
        self._format = format
        self._mode = mode
        self._defs = defs
        if setup_admission is None:
            if max_pending is None:
                max_pending = fteproxy.conf.getValue(
                    'runtime.fteproxy.relay.client_max_pending')
            if max_pending_per_source is None:
                max_pending_per_source = fteproxy.conf.getValue(
                    'runtime.fteproxy.relay.client_max_pending_per_source')
            setup_admission = _SetupAdmission(
                max_pending, max_pending_per_source)
        self._setup_admission = setup_admission

    def dial_tunnel(self):
        """Open and handshake one tunnel to the fteproxy server."""
        raw = socket.create_connection(
            self._server_address,
            timeout=fteproxy.conf.getValue('runtime.fteproxy.handshake.timeout'))
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            tunnel = fteproxy.wrap_socket(raw, server_id=self._server_id,
                                          format=self._format,
                                          mode=self._mode, defs=self._defs)
            tunnel.handshake()
            tunnel.settimeout(fteproxy.conf.getValue(
                'runtime.fteproxy.relay.socket_timeout'))
            return tunnel
        except BaseException:
            fteproxy.network_io.close_socket(raw)
            raise

    def check(self):
        """Dial, complete a handshake, report format/mode, and close.

        This startup check does not send OPEN or verify a destination. Failures can
        wait for the handshake timeout.
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
