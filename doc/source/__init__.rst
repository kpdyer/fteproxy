Most Important Interface
************************

Overview
--------

Interface
---------

.. autofunction:: fte.wrap_socket

Quickstart
----------

Detailed description.


.. code-block:: python
   :emphasize-lines: 3,5,6,11,12,13
   :linenos:

    # FTE-Powered echo server program
    import socket
    import fte
    
    client_server_regex = '^(0|1)+$'
    server_client_regex = '^(A|B)+$'
    
    HOST = ''                 # Symbolic name meaning all available interfaces
    PORT = 50007              # Arbitrary non-privileged port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = fte.wrap_socket(s,
                        outgoing_regex=server_client_regex,
                        incoming_regex=client_server_regex)
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    print 'Connected by', addr
    while 1:
        data = conn.recv(1024)
        if not data: break
        conn.sendall(data)
    conn.close()

.. code-block:: python
   :emphasize-lines: 3,5,6,11,12,13
   :linenos:

    # FTE-Powered echo client program
    import socket
    import fte
    
    client_server_regex = '^(0|1)+$'
    server_client_regex = '^(A|B)+$'
    
    HOST = 'daring.cwi.nl'    # The remote host
    PORT = 50007              # The same port as used by the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = fte.wrap_socket(s,
                        outgoing_regex=client_server_regex,
                        incoming_regex=server_client_regex)
    s.connect((HOST, PORT))
    s.sendall('Hello, world')
    data = s.recv(1024)
    s.close()
    print 'Received', repr(data)