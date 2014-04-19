``fteproxy.wrap_socket``
************************


Overview
--------

The ``fteproxy.wrap_socket`` function is useful for rapidly integrating FTE
into existing applications. The interface is inspired by ``ssl.wrap_socket`` [1].

.. [1] http://docs.python.org/2/library/ssl.html

Interface
---------

.. autofunction:: fteproxy.wrap_socket

Example
-------

An example FTE-powered client-server chat application.
The highlighted lines are the only lines introduced to the example chat
application at for Python's socket module [2].

.. [2] http://docs.python.org/2/library/socket.html

.. code-block:: python
   :emphasize-lines: 3,5,6,11,12,13,14,15

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
        if not data: break
        conn.sendall(data)
    conn.close()

.. code-block:: python
   :emphasize-lines: 3,5,6,11,12,13,14,15

    # FTE-Powered echo client program
    import socket
    import fteproxy

    client_server_regex = '^(0|1)+$'
    server_client_regex = '^(A|B)+$'

    HOST = '127.0.0.1'    # The remote host
    PORT = 50007              # The same port as used by the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = fteproxy.wrap_socket(s,
                        outgoing_regex=client_server_regex,
                        outgoing_fixed_slice=256,
                        incoming_regex=server_client_regex,
                        incoming_fixed_slice=256)
    s.connect((HOST, PORT))
    s.sendall('Hello, world')
    data = s.recv(1024)
    s.close()
    print 'Received', repr(data)
