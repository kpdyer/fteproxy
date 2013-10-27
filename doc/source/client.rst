:mod:`fte.client` Module
************************

Overview
--------
It's the responsibility of the client listener to broker incoming/
outgoing connections on the client-side of an FTE setup.
Incoming connections are not encapsulated by FTE, as they
are from a client-side application, such as Firefox. Outgoing connections
will be destined to an FTE server. They will be encapsuled by FTE.

The ``fte.client.listener`` class extends ``fte.relay.listener``.
See ``fte.relay.listener`` for more information, which is also the base class
for ``fte.server.listener``. The ``fte.relay.listener`` class extends
``threading.Thread``, hence we invoke the FTE client via fte.listener.client.start().


Interface
---------

.. automodule:: fte.client
    :members:
    :undoc-members:
    :show-inheritance:

Examples
--------

Start the FTE client with default configuration paramters.

.. code-block:: python

    import fte.client.listener

    client = fte.client.listener()
    client.start()
    client.join(10) # run for 10 seconds
    client.stop()

Start the FTE client listening on client-side port ``127.0.0.1:8888``.

.. code-block:: python

    import fte.conf
    import fte.client.listener

    fte.conf.setValue('runtime.client.ip', '127.0.0.1')
    fte.conf.setValue('runtime.client.port', 8888)

    client = fte.client.listener()
    client.start()
    client.join(10) # run for 10 seconds
    client.stop()

Start the FTE client and connect to remote server ``myfteserver:80``.

.. code-block:: python

    import fte.conf
    import fte.client.listener

    fte.conf.setValue('runtime.server.ip', 'myfteserver')
    fte.conf.setValue('runtime.server.port', 80)

    client = fte.client.listener()
    client.start()
    client.join(10) # run for 10 seconds
    client.stop()