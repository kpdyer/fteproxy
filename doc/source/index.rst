fteproxy Documentation
=======================

Format-Transforming Encryption (FTE) is a stategy for communicating using
strings defined by compact regular expressions.
FTE is well-positioned to circumvent regex-based DPI systems.

``fteproxy`` Command Line Application
-------------------------------------

The ``fteproxy`` command-line application can be used to run and FTE proxy client
or server.

.. toctree::
   :maxdepth: 2

   fteproxy.rst


FTE Wrapper for Socket Objects
------------------------------

The FTE socket wrapper is useful for rapidly integrating FTE into existing
socket-powered applications.

.. toctree::
   :maxdepth: 2

   __init__.rst


FTE API
-------

The FTE API contains the essential building blocks for constructing the FTE
socket wrapper and fteproxy command line application.

.. toctree::
   :maxdepth: 1

   api.rst


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
