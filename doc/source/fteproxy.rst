``fteproxy``
************

The ``fteproxy`` command-line application is used to start an fteproxy client or
server.

Parameters
----------

The ``fteproxy`` command-line application usage:

.. code-block:: none

    usage: fteproxy [-h] [--version] [--mode (client|server|test)] [--stop]
                    [--upstream-format UPSTREAM_FORMAT]
                    [--downstream-format DOWNSTREAM_FORMAT]
                    [--client_ip CLIENT_IP] [--client_port CLIENT_PORT]
                    [--server_ip SERVER_IP] [--server_port SERVER_PORT]
                    [--proxy_ip PROXY_IP] [--proxy_port PROXY_PORT] [--quiet]
                    [--release RELEASE] [--managed] [--key KEY]
    
    optional arguments:
      -h, --help            show this help message and exit
      --version             Output the version of fteproxy, then quit. (default:
                            False)
      --mode (client|server|test)
                            Relay mode: client or server (default: client)
      --stop                Shutdown daemon process (default: False)
      --upstream-format UPSTREAM_FORMAT
                            Client-to-server language format (default: manual-
                            http-request)
      --downstream-format DOWNSTREAM_FORMAT
                            Server-to-client language format (default: manual-
                            http-response)
      --client_ip CLIENT_IP
                            Client-side listening IP (default: 127.0.0.1)
      --client_port CLIENT_PORT
                            Client-side listening port (default: 8079)
      --server_ip SERVER_IP
                            Server-side listening IP (default: 127.0.0.1)
      --server_port SERVER_PORT
                            Server-side listening port (default: 8080)
      --proxy_ip PROXY_IP   Forwarding-proxy (SOCKS) listening IP (default:
                            127.0.0.1)
      --proxy_port PROXY_PORT
                            Forwarding-proxy (SOCKS) listening port (default:
                            8081)
      --quiet               Be completely silent. Print nothing. (default: False)
      --release RELEASE     Definitions file to use, specified as YYYYMMDD
                            (default: 20131224)
      --managed             Start in pluggable transport managed mode, for use
                            with Tor. (default: False)
      --key KEY             Cryptographic key, hex, must be exactly 64 characters
                            (default: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000
                            00000000000000000000)

Example Usage
-------------

Starting the ``fteproxy`` client with the default configuration parameters.

.. code-block:: none

    fteproxy --mode client

Starting the ``fteproxy`` client, binding to ``127.0.0.1:8888``.

.. code-block:: none

    fteproxy --mode client --client_ip 127.0.0.1 --client_port 8888

Starting the ``fteproxy`` client, using ``XXX`` for upstream communications
and ``YYY`` for downstream communications.

.. code-block:: none

    fteproxy --mode client --upstream-format XXX --downstream-format YYY

Starting the ``fteproxy`` server, binding to port ``8888`` on all interfaces.

.. code-block:: none

    fteproxy --mode server --client_ip 0.0.0.0 --client_port 8888

Start ``fteproxy``, execute all unit tests, then exit.

.. code-block:: none

    fteproxy --mode test
