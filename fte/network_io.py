import select
import socket


def sendall_to_socket(sock, msg):
    """Given a socket ``sock`` and ``msg`` does a best effort to send
    ``msg`` on ``sock`` as quickly as possible.
    """

    totalsent = 0
    try:
        while totalsent < len(msg):
            sent = sock.send(msg[totalsent:])
            if sent == 0:
                break
            totalsent = totalsent + sent
    except socket.error:
        totalsent = -1

    return totalsent


def recvall_from_socket(sock,
                        bufsize=2 ** 17,
                        socket_timeout=0.1,
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
            while True:
                _data = sock.recv(bufsize)
                if _data:
                    retval += _data
                    is_alive = True
                    if len(retval) >= bufsize:
                        break
                    else:
                        continue
                else:
                    is_alive = (len(retval) > 0)
                    break
        else:
            # select.timeout
            is_alive = True
    except socket.timeout:
        is_alive = True
    except socket.error:
        is_alive = (len(retval) > 0)
    except select.error:
        is_alive = (len(retval) > 0)

    return [is_alive, retval]


def close_socket(sock, lock=None):
    """Given socket ``sock`` closes the socket for reading and writing.
    If the optional ``lock`` parameter is provided, protects all accesses
    to ``sock`` with ``lock``.
    """

    try:
        if lock is not None:
            with lock:
                sock.shutdown(socket.SHUT_RDWR)
        else:
            sock.shutdown(socket.SHUT_RDWR)
    except:
        pass
    try:
        if lock is not None:
            with lock:
                sock.close()
        else:
            sock.close()
    except:
        pass
