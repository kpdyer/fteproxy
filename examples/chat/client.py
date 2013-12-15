# FTE-Powered echo client program
import socket
import fte

client_server_regex = '^(0|1)+$'
server_client_regex = '^(A|B)+$'

HOST = '127.0.0.1'    # The remote host
PORT = 50007              # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = fte.wrap_socket(s,
                    outgoing_regex=client_server_regex,
                    outgoing_fixed_slice=256,
                    incoming_regex=server_client_regex,
                    incoming_fixed_slice=256)
s.connect((HOST, PORT))
s.sendall('Hello, world')
data = s.recv(1024)
s.close()
print 'Received', repr(data)
