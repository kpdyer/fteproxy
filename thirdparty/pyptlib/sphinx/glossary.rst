Pluggable transports glossary
"""""""""""""""""""""""""""""

pluggable transport (sometimes also called 'transport')
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Pluggable transports obfuscate network traffic.

Specifically, pluggable transports transform the Tor traffic flow
between the client and the bridge. This way, censors who monitor
traffic between the client and the bridge see innocent-looking
transformed traffic instead of the actual Tor traffic.

pluggable transport proxy
^^^^^^^^^^^^^^^^^^^^^^^^^

Pluggable transport proxies are programs that implement pluggable
transports. They also implement the networking system that a pluggable
transport needs (so that it can proxy data).

obfsproxy
^^^^^^^^^

`obfsproxy <https://www.torproject.org/projects/obfsproxy.html.en>`_
is a pluggable transport proxy written in C. It implements the `obfs2
<https://gitweb.torproject.org/obfsproxy.git/blob/HEAD:/doc/obfs2/protocol-spec.txt>`_
pluggable transport.


upstream/downstream
^^^^^^^^^^^^^^^^^^^

The upstream side of a pluggable transport proxy is the side that
communicates with Tor. Upstream data is non-obfuscated.

The downstream side of a pluggable transport proxy is the side that
communicates with the other pluggable transport proxy. Downstream data
is obfuscated.

client-mode / server-mode
^^^^^^^^^^^^^^^^^^^^^^^^^^

A pluggable transport is a client if it has a Tor client in its
upstream side.

A pluggable transport is a server if it has a Tor bridge in its
upstream side.

external-mode proxy
^^^^^^^^^^^^^^^^^^^

A pluggable transport proxy is in external-mode if the user explicitly
configures it using its command-line interface.

managed-mode proxy
^^^^^^^^^^^^^^^^^^

A pluggable transport proxy is in managed-mode if it's launched and
managed by Tor using the managed-proxy configuration protocol. The
managed-proxy configuration protocol is defined in the `pluggable
transport specification
<https://gitweb.torproject.org/torspec.git/blob/HEAD:/proposals/180-pluggable-transport.txt>`_.

pyptlib
^^^^^^^

pyptlib is a library that implements the managed-proxy configuration
protocol and makes it easier for application to be used as managed
proxies.

extended orport
^^^^^^^^^^^^^^^

Extended ORPort is an non-implemented feature of Tor that allows a
pluggable transport proxy to communicate with Tor in real-time.
