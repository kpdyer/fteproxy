import select
import socket

ENCODER_BLOCK_SIZE = 1024
DECODER_BLOCK_SIZE = 1024
CLOCK_SPEED = 0.01
SELECT_SPEED = 0.01


def sendall_to_socket(sock, msg, timeout=5):
    totalsent = 0

    try:
        while totalsent < len(msg):
            sent = sock.send(msg[totalsent:])
            if sent == 0:
                break
            totalsent = totalsent + sent
    except:
        pass

    return totalsent > 0


def recvall_from_socket(sock, covertext=None, timeout=SELECT_SPEED):
    retval = ''
    success = False

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
