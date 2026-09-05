#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import select
import socket


def recvall_from_socket(sock,
                        bufsize=2 ** 18,
                        select_timeout=0.1):
    """Give ``sock``, does a best effort to pull data from ``sock``.
    By default, fails quickly if ``sock`` is closed or has no data ready.
    The return value ``is_alive`` reports if ``sock`` is still alive.
    The return value ``retval`` is the data extracted from the socket.
    Unlike normal raw sockets, it may be the case that ``retval`` is b'', and
    ``is_alive`` is ``true``.
    """

    try:
        # A protocol wrapper can hold decoded DATA or logical EOF that the
        # operating system knows nothing about. In particular, OPEN_RESULT
        # and the first DATA record may arrive in one wire read: the control
        # waiter consumes OPEN_RESULT and leaves DATA buffered while the raw
        # descriptor becomes idle. Ask the wrapper before selecting.
        pending_read = getattr(sock, 'pending_read', None)
        if pending_read is not None and pending_read():
            data = sock.recv(bufsize)
            return [bool(data), data]

        # Compatibility for socket-like objects implementing the older,
        # narrower hook.
        pending_eof = getattr(sock, 'pending_eof', None)
        if pending_eof is not None and pending_eof():
            return [False, b'']

        readable, _, _ = select.select([sock], [], [sock], select_timeout)
        if not readable:
            return [True, b'']
        data = sock.recv(bufsize)
        return [bool(data), data]
    except socket.timeout:
        return [True, b'']
    except OSError:
        return [False, b'']


def close_socket(sock):
    """Wake blocked I/O, close ``sock``, and tolerate repeated cleanup."""
    try:
        # On several platforms close() from another thread does not wake a
        # blocking recv promptly. shutdown() makes listener.stop() observable
        # to setup workers and to the peer before ownership is released.
        sock.shutdown(socket.SHUT_RDWR)
    except (AttributeError, OSError):
        pass
    try:
        sock.close()
    except (AttributeError, OSError):
        pass
