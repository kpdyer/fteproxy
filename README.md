fteproxy
========

* homepage: https://fteproxy.org
* source code: https://github.com/redjack/fteproxy
* publication: https://eprint.iacr.org/2012/494

Overview
--------

fteproxy provides transport-layer protection to resist keyword filtering, censorship and discrimantory routing policies.
It's job is to relay datastreams, such as web browsing traffic, by encoding the stream into messages that satisfy a user-specified regular expression. 

fteproxy is powered by Format-Transforming Encryption [1] and was presented as CCS 2013.

[1] https://eprint.iacr.org/2012/494

Dependencies
--------

Dependencies for building from source:
* Standard build tools: gcc/g++/make/etc.
* Python 2.7: http://python.org
* GMP: http://gmplib.org/
* gmpy: https://code.google.com/p/gmpy/
* PyCrypto: https://www.dlitz.net/software/pycrypto/
* Twisted: http://twistedmatrix.com/trac/
* boost (python, system, filesystem): http://www.boost.org/
* obfsproxy: https://pypi.python.org/pypi/obfsproxy
* pyptlib: https://pypi.python.org/pypi/pyptlib

Building
-----------

For platform-specific instructions on how to install dependencies see: BUILDING.[linux|osx|windows]

Once all dependencies are installed, it's as simple as:

```
git clone https://github.com/redjack/fteproxy.git
cd fteproxy
make
sudo make install
```

Documentation
-------------

See: https://fteproxy.org/documentation
