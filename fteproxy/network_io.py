import select
import socket


def sendall_to_socket(sock, data):
    """Given a socket ``sock`` and ``msg`` does a best effort to send
    ``msg`` on ``sock`` as quickly as possible.
    """

    return sock.sendall(data)


def recvall_from_socket(sock,
                        bufsize=2 ** 18,
                        select_timeout=0.1):
    """Give ``sock``, does a best effort to pull data from ``sock``.
    By default, fails quickly if ``sock`` is closed or has no data ready.
    The return value ``is_alive`` reports if ``sock`` is still alive.
    The return value ``retval`` is the data extracted from the socket.
    Unlike normal raw sockets, it may be the case that ``retval`` is '', and
    ``is_alive`` is ``true``.
    """

    retval = ''
    is_alive = False

    try:
        ready = select.select([sock], [], [sock], select_timeout)
        if ready[0]:
            _data = sock.recv(bufsize)
            if _data:
                retval += _data
                is_alive = True
            else:
                is_alive = False
        else:
            # select.timeout
            is_alive = True
    except socket.timeout:
        is_alive = True
    except socket.error:
        is_alive = (len(retval) > 0)
    except select.error:
        is_alive = (len(retval) > 0)
    finally:
        if retval: is_alive = True

    return [is_alive, retval]


def close_socket(sock, lock=None):
    """Given socket ``sock`` closes the socket for reading and writing.
    If the optional ``lock`` parameter is provided, protects all accesses
    to ``sock`` with ``lock``.
    """

    try:
        if lock is not None:
            with lock:
                sock.close()
        else:
            sock.close()
    except:
        pass
