fteproxy
========

* homepage: https://fteproxy.org
* github: https://github.com/redjack/fteproxy

Overview
--------

fteproxy is client-server proxy powered by Format-Transforming Encryption [1] that tunnels arbitrary TCP streams.
Regular expressions specified at runtime are used to format messages on the wire.
That is, given a regular epxression R, fteproxy can tunnel arbitrary TCP streams by transmitting messages in the language L(R).

[1] http://eprint.iacr.org/2012/494

Building fteproxy
--------

Dependencies for building from source:
* standard build tools: gcc/g++/make/etc.
* git: http://git-scm.com/
* python 2.7: http://python.org
* gmp5: http://gmplib.org/
* gmpy: https://code.google.com/p/gmpy/
* pycrypto: https://www.dlitz.net/software/pycrypto/
* python twisted: http://twistedmatrix.com/trac/
* boost (python,system,filesystem): http://www.boost.org/

For platform-specific build instructions see: README.[linux|osx|windows]

Documentation
-------------

See: https://fteproxy.org/documentation
