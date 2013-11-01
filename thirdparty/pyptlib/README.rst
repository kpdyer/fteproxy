pyptlib README
===============

- What is pyptlib?

pyptlib is a little Python library which understands the `pluggable
transport managed-proxy protocol <https://gitweb.torproject.org/torspec.git/blob_plain/HEAD:/proposals/180-pluggable-transport.txt>`_.

- Who is interested in pyptlib?

You might be interested in pyptlib if you have an application that
obfuscates TCP traffic and you want to integrate it easily with Tor.

- What does pyptlib do?

pyptlib speaks with Tor and informs your application about which
pluggable transports Tor needs, in which ports they should listen for
connections, in which filesystem directory they should keep state, etc.

- What does pyptlib not do?

pyptlib doesn't help your application do networking or obfuscation.

- What does pyptlib expect from an application?

pyptlib assumes that your application is executed by Tor as a
managed-proxy.

pyptlib assumes that your application acts as a proxy: it listens for
traffic on a TCP port and pushes the traffic somewhere else.

pyptlib assumes that your application has a SOCKS server when it acts
as a client. This is needed because Tor needs to dynamically select
where its data will be pushed to.

- How do I use pyptlib?

Read the documentation, the examples and the source.

- What are these buzzwords?

:file:`glossary.rst`

