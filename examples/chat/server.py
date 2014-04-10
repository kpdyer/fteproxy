# FTE-Powered echo server program
import socket
import fteproxy

client_server_regex = '^(0|1)+$'
server_client_regex = '^(A|B)+$'

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 50007              # Arbitrary non-privileged port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = fteproxy.wrap_socket(s,
                    outgoing_regex=server_client_regex,
                    outgoing_fixed_slice=256,
                    incoming_regex=client_server_regex,
                    incoming_fixed_slice=256)
s.bind((HOST, PORT))
s.listen(1)
conn, addr = s.accept()
print 'Connected by', addr
while 1:
    data = conn.recv(1024)
    if not data:
        break
    conn.sendall(data)
conn.close()
