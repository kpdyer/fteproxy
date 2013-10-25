Format-Transforming Encryption (FTE)
-----
* url: https://kpdyer.com/fte
* github: https://github.com/redjack/FTE

Quickstart - Debian 7.1.0 i386
----------

```
$ sudo apt-get update
$ sudo apt-get -y install build-essential
$ sudo apt-get -y install m4
$ sudo apt-get -y install git
$ sudo apt-get -y install python-dev
$ sudo apt-get -y install python-gmpy
$ sudo apt-get -y install python-crypto
$ sudo apt-get -y install python-sphinx
$ sudo apt-get -y install python-twisted
$ sudo apt-get -y install libboost-python-dev
$ sudo apt-get -y install libboost-system-dev
$ sudo apt-get -y install libboost-filesystem-dev
$ sudo apt-get -y install libgmp-dev
```

```
$ cd ~
$ mkdir my-working-dir
$ cd my-working-dir
$ git clone https://github.com/redjack/fte-proxy.git
$ cd FTE
$ make all
```

```
$ ./unittests
```

```
$ sudo make install
```

```
$ ./systemtests
```
