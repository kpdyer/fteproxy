API overview
============

Be sure to read :file:`API.rst` and :file:`glossary.rst` before
reading this file.

General Overview
################

Applications begin by initializing pyptlib.

Then pyptlib informs the application about which transports it should
spawn, in which ports they should listen for connections, etc.

Then the application launches the appropriate transports as
instructed, and for each transport it reports to pyptlib whether it
was launched successfully or not. Finally, the application announces
to pyptlib that it finished launching transports.

From that point and on the application should forget about pyptlib
and start accepting connections.

Detailed API Overview
#####################

0) Find if it's a client or a server
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

An application using pyptlib should start by calling
:func:`pyptlib.config.checkClientMode` to learn whether Tor wants it
to run as a client or as a server.

You should then create a :class:`pyptlib.client.ClientTransportPlugin`
or :class:`pyptlib.server.ServerTransportPlugin` as appropriate. This
object is your main entry point to the pyptlib API, so you should
keep it somewhere for later access.

1) Get transport information from Tor
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The next step is to run :func:`init <pyptlib.core.TransportPlugin.init>`
to parse the rest of the configuration and communicate the results
to Tor. You should pass a list of names of the transports your
application supports.

The application should be prepared for :exc:`pyptlib.config.EnvError`,
which signifies that the environment was not prepared by Tor.

Consider an example of the fictional application *rot0r* which
implements the pluggable transports *rot13* and *rot26*. If *rot0r*,
in step 1, learned that Tor expects it to act as a client, it should
now do:

.. code-block::
   python

   from pyptlib.client import ClientTransportPlugin
   from pyptlib.config import EnvError

   client = ClientTransportPlugin()
   try:
       client.init(supported_transports=["rot13", "rot26"])
   except EnvError, err:
       print "pyptlib could not bootstrap ('%s')." % str(err)

Afterwards, the API's ``config`` attribute provides methods to find
out how Tor wants your application to be configured. For example, if
you store state, it should go in :func:`client.config.getStateLocation()
<pyptlib.config.Config.getStateLocation>`. For a complete list, see
the documentation for that module.

2) Launch transports
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Client case (skip if you are a server)
"""""""""""""""""""""""""""""""""""""""""""

Your application should then use :func:`client.getTransports()
<pyptlib.core.TransportPlugin.getTransports>` to learn which
transports it should launch.

Proceeding with the previous example:

.. code-block::
   python

   if 'rot13' in client.getTransports():
       launch_rot13_client()
   if 'rot26' in client.getTransports():
       launch_rot26_client()

For a full list of the methods available, see the module docs for :class:`client
<pyptlib.client.ClientTransportPlugin>` and :class:`client.config
<pyptlib.client_config.ClientConfig>`.

.. note:: Since the application runs as a client, it should launch a
          SOCKS server in the upstream side of the proxy.

Server case (skip if you are a client):
""""""""""""""""""""""""""""""""""""""""""""

Your application should then use :func:`server.getBindAddresses()
<pyptlib.server.ServerTransportPlugin.getBindAddresses>` to
learn which transports it should launch.

Since the application runs as a server, it will push data to Tor's
ORPort, which you can get using :func:`server.config.getORPort()
<pyptlib.server_config.ServerConfig.getORPort>`.

Proceeding with the previous example:

.. code-block::
   python

   transports = server.getBindAddresses()
   if 'rot13' in transports:
       launch_rot13_server(transports['rot13'], server.config.getORPort())
   if 'rot26' in transports:
       launch_rot26_server(transports['rot26'], server.config.getORPort())

For a full list of the methods available, see the module docs for :class:`server
<pyptlib.server.ServerTransportPlugin>` and :class:`server.config
<pyptlib.server_config.ServerConfig>`.

3) Report results back to Tor.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For every transport that the application launches, it reports to
pyptlib whether it was launched successfully or not. This way, Tor
is informed on whether a transport is expected to work or not.

Client case (skip if you are a server):
""""""""""""""""""""""""""""""""""""""""""""

Every time a transport is successfully launched, the application
calls :func:`client.reportMethodSuccess
<pyptlib.client.ClientTransportPlugin.reportMethodSuccess>` with the
name of the transport that was launched, the address where it is
listening for connections, and the SOCKS version that the upstream
SOCKS server supports.

For example, if *rot13* was launched successfully, waits for
connections in '127.0.0.1:42042' and supports SOCKSv4, the
appropriate call would be:

.. code-block::
   python

   client.reportMethodSuccess('rot13', 'socks5', ('127.0.0.1', 42042))

Every time a transport failed to launch, the application calls
:func:`client.reportMethodError
<pyptlib.core.TransportPlugin.reportMethodError>` with the name of
the transport and a message.

For example, if *rot26* failed to launch, the appropriate call
would be:

.. code-block::
   python

   client.reportMethodError('rot26', 'Could not bind to 127.0.0.1:666 (Operation not permitted)')

Server case (skip if you are a client):
""""""""""""""""""""""""""""""""""""""""""""

Everytime a transport is successfully launched, the application
calls :func:`server.reportMethodSuccess
<pyptlib.server.ServerTransportPlugin.reportMethodSuccess>` with the
name of the transport that was launched, and the address where it is
listening for connections.

For example, if *rot13* was launched successfully and waits for
connections in '127.0.0.1:42042', the appropriate call would be:

.. code-block::
   python

   server.reportMethodSuccess('rot13', ('127.0.0.1', 42042))

Everytime a transport failed to launch, the application should call
:func:`server.reportMethodError
<pyptlib.core.TransportPlugin.reportMethodError>` with the name of
the transport and a message.

For example, if *rot26* failed to launch, the appropriate call
would be:

.. code-block::
   python

   server.reportMethodError('rot26', 'Could not bind to 127.0.0.1:666 (Operation not permitted)')

4) Stop using pyptlib and start accepting connections
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When the application finishes launching connections, it should call
:func:`reportMethodsEnd()
<pyptlib.core.TransportPlugin.reportMethodsEnd>`, to announce to
pyptlib that all transports were launched. This way, Tor knows that
it can start pushing traffic to the application.

After this point, the API object (in this current version of pyptlib)
has no other use.
