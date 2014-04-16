# This file is part of fteproxy.
#
# fteproxy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation,either version 3 of the License,or
# (at your option) any later version.
#
# fteproxy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with fteproxy.  If not,see <http://www.gnu.org/licenses/>.


# Automatically figure out what we're doing

ifneq ($(CROSS_COMPILE),1)
CROSS_COMPILE=0
PLATFORM_UNAME=$(shell uname)
PLATFORM=$(shell echo $(PLATFORM_UNAME) | tr A-Z a-z)
ifneq (,$(findstring cygwin,$(PLATFORM)))
PLATFORM='windows'
WINDOWS_BUILD=1
endif
ifeq ($(ARCH),)
ARCH=$(shell arch)
endif
endif

VERSION=$(shell cat fteproxy/VERSION)
FTEPROXY_RELEASE=$(VERSION)-$(PLATFORM)-$(ARCH)
THIRD_PARTY_DIR=thirdparty
BINARY_ARCHIVE=dist/fteproxy-$(FTEPROXY_RELEASE).tar.gz

ifeq ($(PYTHON),)
PYTHON="python"
endif

ifeq ($(WINDOWS_BUILD),1)
BINARY_ARCHIVE=dist/fteproxy-$(FTEPROXY_RELEASE).zip
endif

dist: do-dist

dist-all: dist-windows-i386 dist-osx-i386 dist-linux-i386 dist-linux-x86_64

dist-windows-i386:
	LDFLAGS="$(LDFLAGS) -m32" \
	CFLAGS="$(CFLAGS) -m32" \
	CXXFLAGS="$(CXXFLAGS) -m32" \
	CROSS_COMPILE=1 \
	WINDOWS_BUILD=1 \
	PLATFORM='windows' \
	ARCH='i386' \
	BINARY_ARCHIVE=dist/fteproxy-$(FTEPROXY_RELEASE).zip \
	CDFA_BINARY=fte/cDFA.pyd \
	$(MAKE) do-dist-windows-i386
	
dist-osx-i386:
	LDFLAGS="$(LDFLAGS) -m32" \
	CFLAGS="$(CFLAGS) -m32" \
	CXXFLAGS="$(CXXFLAGS) -m32" \
	CROSS_COMPILE=1 \
	PLATFORM='darwin' \
	ARCH='i386' \
	$(MAKE) do-dist-osx-i386
	
dist-linux-i386:
	LDFLAGS="$(LDFLAGS) -m32" \
	CFLAGS="$(CFLAGS) -m32" \
	CXXFLAGS="$(CXXFLAGS) -m32" \
	CROSS_COMPILE=1 \
	PLATFORM='linux' \
	ARCH='i386' \
	$(MAKE) do-dist-linux-i386
	
dist-linux-x86_64:
	CROSS_COMPILE=1 \
	PLATFORM='linux' \
	ARCH='x86_64' \
	$(MAKE) do-dist-linux-x86_64

dist-deb:
	@rm -rfv debian/fteproxy
	DEB_CPPFLAGS_SET="-fPIC" dpkg-buildpackage -B -us -uc #-k8FBA6390
	mkdir -p dist
	cp ../*deb dist/
	cp ../*changes dist/
	
# Our high-level targets that can be called directly
do-dist: $(BINARY_ARCHIVE)
do-dist-windows-i386: $(BINARY_ARCHIVE)
do-dist-osx-i386: $(BINARY_ARCHIVE)
do-dist-linux-i386: $(BINARY_ARCHIVE)
do-dist-linux-x86_64: $(BINARY_ARCHIVE)

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp -an bin/fteproxy $(DESTDIR)/usr/bin/
	python setup.py install --root=$(DESTDIR) --install-layout=deb

clean:
	@rm -rvf build
	@rm -vf fte/*.so
	@rm -vf fte/*.pyd
	@rm -vf *.pyc
	@rm -vf */*.pyc
	@rm -vf */*/*.pyc
	@rm -rvf $(THIRD_PARTY_DIR)/re2
	@rm -rvf debian/fteproxy
	
test:
	@PATH=./bin:$(PATH) $(PYTHON) ./bin/fteproxy --mode test --quiet
	@PATH=./bin:$(PATH) $(PYTHON) ./systemtests


# Supporting targets
$(BINARY_ARCHIVE): $(CDFA_BINARY)
	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)
	
ifeq ($(WINDOWS_BUILD),1)
	$(PYTHON) setup.py py2exe
	
	cd dist && mv *.dll fteproxy-$(FTEPROXY_RELEASE)/
	cd dist && mv *.zip fteproxy-$(FTEPROXY_RELEASE)/
	cd dist && mv *.exe fteproxy-$(FTEPROXY_RELEASE)/

	cp README.md dist/fteproxy-$(FTEPROXY_RELEASE)
	cp COPYING dist/fteproxy-$(FTEPROXY_RELEASE)

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fteproxy
	cp fteproxy/VERSION dist/fteproxy-$(FTEPROXY_RELEASE)/fteproxy
	cp -rfv fteproxy/defs dist/fteproxy-$(FTEPROXY_RELEASE)/fteproxy
	cp -rfv fteproxy/tests dist/fteproxy-$(FTEPROXY_RELEASE)/fteproxy

	cd dist && zip -9 -r fteproxy-$(FTEPROXY_RELEASE).zip fteproxy-$(FTEPROXY_RELEASE)
	cd dist && rm -rf fteproxy-$(FTEPROXY_RELEASE)
else
	$(PYTHON) `which pyinstaller` --clean fteproxy.spec
	cd dist && mv fteproxy fteproxy-$(FTEPROXY_RELEASE)/fteproxy.bin

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fteproxy
	cp fteproxy/VERSION dist/fteproxy-$(FTEPROXY_RELEASE)/fteproxy

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fteproxy/defs
	cp fteproxy/defs/*.json dist/fteproxy-$(FTEPROXY_RELEASE)/fteproxy/defs/

	cp README.md dist/fteproxy-$(FTEPROXY_RELEASE)
	cp COPYING dist/fteproxy-$(FTEPROXY_RELEASE)

	cp README.md dist/fteproxy-$(FTEPROXY_RELEASE)
	cp COPYING dist/fteproxy-$(FTEPROXY_RELEASE)
	
	cd dist && tar cvf fteproxy-$(FTEPROXY_RELEASE).tar fteproxy-$(FTEPROXY_RELEASE)
	cd dist && gzip -9 fteproxy-$(FTEPROXY_RELEASE).tar
	cd dist && rm -rf fteproxy-$(FTEPROXY_RELEASE)
endif


$(CDFA_BINARY):
ifeq ($(WINDOWS_BUILD),1)
	$(PYTHON) setup.py build_ext --inplace -c mingw32
else
	$(PYTHON) setup.py build_ext --inplace
endif
