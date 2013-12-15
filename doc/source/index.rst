fteproxy Documentation
=======================

Format-Transforming Encryption (FTE) is a strategy for communicating using
strings defined by compact regular expressions.
fteproxy is well-positioned to circumvent regex-based DPI systems.

``fteproxy`` Command Line Application
-------------------------------------

The ``fteproxy`` command-line application can be used to run and fteproxy proxy client
or server.

.. toctree::
   :maxdepth: 2

   fteproxy.rst


fteproxy Wrapper for Socket Objects
------------------------------

The fteproxy socket wrapper is useful for rapidly integrating fteproxy into existing
socket-powered applications.

.. toctree::
   :maxdepth: 2

   __init__.rst


fteproxy API
-------

The fteproxy API contains the essential building blocks for constructing the FTE
socket wrapper and fteproxy command line application.

.. toctree::
   :maxdepth: 1

   api.rst


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
