fteproxy Build Instructions
===========================

Ubuntu 10.04+
-------------

```
sudo apt-get install python-dev libgmp-dev python-crypto python-twisted python-pip upx
sudo pip install pyptlib obfsproxy
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
make
make test
make dist
```

OSX 10.6+
---------

Install homebrew: http://brew.sh/

```
ruby -e "$(curl -fsSL https://raw.github.com/Homebrew/homebrew/go/install)"```

```
brew install --build-from-source python gmp git upx
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
make
make test
make dist
```
