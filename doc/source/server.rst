:mod:`fteproxy.server` Module
*****************************

Overview
--------
It's the responsibility of the server listener to broker incoming/
outgoing connections on the server-side of an fteproxy setup.
Incoming connections are encapsulated by FTE, as they
are from an fteproxy client application. Outgoing connections
will be destined to some sort of proxy, such as a SOCKS server or Tor bridge.

The ``fteproxy.server.listener`` class extends ``fteproxy.relay.listener``.
See ``fteproxy.relay.listener`` for more information, which is also the base class
for ``fteproxy.client.listener``. The ``fteproxy.relay.listener`` class extends
``threading.Thread``, hence we invoke the fteproxy server via fteproxy.listener.server.start().


Interface
---------

.. automodule:: fteproxy.server
    :members:
    :undoc-members:
    :show-inheritance:

Examples
--------

Start the fteproxy server with default configuration parameters.

.. code-block:: python

    import fteproxy.server.listener

    server = fteproxy.server.listener()
    server.start()
    server.join(10) # run for 10 seconds
    server.stop()

Start the fteproxy server listening on server-side port ``127.0.0.1:8888``.

.. code-block:: python

    import fteproxy.conf
    import fteproxy.server.listener

    fteproxy.conf.setValue('runtime.server.ip', '127.0.0.1')
    fteproxy.conf.setValue('runtime.server.port', 8888)

    server = fteproxy.server.listener()
    server.start()
    server.join(10) # run for 10 seconds
    server.stop()
