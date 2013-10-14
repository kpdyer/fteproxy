Format-Transforming Encryption (FTE)
-----
* url: https://kpdyer.com/fte
* github: https://github.com/redjack/FTE

Quickstart - Debian 7.1.0 i386
----------

```
$ sudo apt-get update
$ sudo apt-get install git
$ sudo apt-get install python-dev
$ sudo apt-get install python-gmpy
$ sudo apt-get install python-crypto
$ sudo apt-get install m4
$ sudo apt-get install libboost-python-dev
$ sudo apt-get install libboost-system-dev
$ sudo apt-get install libgmp-dev
```

```
$ mkdir my-working-dir
$ cd my-working-dir
$ git clone https://github.com/redjack/FTE.git
$ cd FTE
$ python build.py
$ ls dist
fte_relay-0.1.2-alpha.linux.i686.tar.gz
tor-browser-gnu-linux-i686-2.3.25-10-dev-en-US+[fte_relay-0.1.2-alpha].tar.gz
```
