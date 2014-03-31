fteproxy Build Instructions
===========================

Ubuntu/Debian
-------------

Install the following packages.
```
sudo apt-get install python-dev libgmp-dev python-crypto python-twisted python-pip upx git
sudo pip install --upgrade pyptlib obfsproxy pyinstaller
```

Then, clone and build fteproxy.
```
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
make
make test
make dist
```

OSX
---

Install homebrew [1], if you don't have it already.

```
ruby -e "$(curl -fsSL https://raw.github.com/Homebrew/homebrew/go/install)"
```

Install the following packages.
```
brew install --build-from-source python gmp git upx
pip install --upgrade pyptlib obfsproxy pyinstaller
```

Then, clone and build fteproxy.
```
git clone https://github.com/kpdyer/fteproxy.git
cd fteproxy
make
make test
make dist
```

Windows
-------

If you must build fteproxy on Windows, please see [2] for guidance.


### References

* [1] http://brew.sh/
* [2] https://github.com/kpdyer/fteproxy-builder/blob/master/build/windows-i386/build_fteproxy.sh
