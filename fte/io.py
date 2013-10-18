import select
import socket


def sendall_to_socket(sock, msg, socket_timeout = 0.01):
    totalsent = 0
    try:
        _incoming_timeout = sock.gettimeout()
        sock.settimeout(socket_timeout)
        while totalsent < len(msg):
            sent = sock.send(msg[totalsent:])
            if sent == 0:
                break
            totalsent = totalsent + sent
    except socket.error:
        totalsent = -1
    finally:
        sock.settimeout(_incoming_timeout)

    return totalsent


def recvall_from_socket(sock,
                        bufsize=2**12,
                        socket_timeout=0.001,
                        select_timeout=0.001):
    retval = ''
    success = False
    _incoming_timeout = sock.gettimeout()
    sock.settimeout(socket_timeout)
    try:
        ready = select.select([sock], [], [sock], select_timeout)
        if ready[0]:
            while True:
                _data = sock.recv(bufsize)
                if _data:
                    retval += _data
                    success = True
                    if len(retval)>=bufsize:
                        break
                    else:
                        continue
                else:
                    success = (len(retval)>0)
                    break
        elif ready[2]:
            success = (len(retval)>0)
        else:
            # select.timeout
            success = True
    except socket.timeout:
        success = True
    except socket.error:
        success = (len(retval)>0)
    except select.error:
        success = (len(retval)>0)
    finally:
        sock.settimeout(_incoming_timeout)

    return [success, retval]


def close_socket(sock, lock=None):
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
