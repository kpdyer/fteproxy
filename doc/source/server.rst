:mod:`fte.server` Module
************************

Overview
--------
It's the responsibility of the server listener to broker incoming/
outgoing connections on the server-side of an FTE setup.
Incoming connections are encapsulated by FTE, as they
are from an FTE client application. Outgoing connections
will be destined to some sort of proxy, such as a SOCKS server or Tor bridge.

The ``fte.server.listener`` class extends ``fte.relay.listener``.
See ``fte.relay.listener`` for more information, which is also the base class
for ``fte.client.listener``. The ``fte.relay.listener`` class extends
``threading.Thread``, hence we invoke the FTE server via fte.listener.server.start().


Interface
---------

.. automodule:: fte.server
    :members:
    :undoc-members:
    :show-inheritance:

Examples
--------

Start the FTE server with default configuration paramters.

.. code-block:: python

    import fte.server.listener

    server = fte.server.listener()
    server.start()
    server.join(10) # run for 10 seconds
    server.stop()

Start the FTE server listening on server-side port ``127.0.0.1:8888``.

.. code-block:: python

    import fte.conf
    import fte.server.listener

    fte.conf.setValue('runtime.server.ip', '127.0.0.1')
    fte.conf.setValue('runtime.server.port', 8888)

    server = fte.server.listener()
    server.start()
    server.join(10) # run for 10 seconds
    server.stop()
