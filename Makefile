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
ARCH=$(shell arch)
endif

VERSION=$(shell cat fte/VERSION)
FTEPROXY_RELEASE=$(VERSION)-$(PLATFORM)-$(ARCH)
THIRD_PARTY_DIR=thirdparty
RE2_VERSION=20140111
RE2_VERSION_WIN32=20110930
RE2_DIR=$(THIRD_PARTY_DIR)/re2
BINARY_ARCHIVE=dist/fteproxy-$(FTEPROXY_RELEASE).tar.gz
CDFA_BINARY=fte/cDFA.so

ifeq ($(PYTHON),)
PYTHON="python"
endif

ifeq ($(WINDOWS_BUILD),1)
BINARY_ARCHIVE=dist/fteproxy-$(FTEPROXY_RELEASE).zip
CDFA_BINARY=fte/cDFA.pyd
endif

default: $(CDFA_BINARY)

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
	
# Our high-level targets that can be called directly
do-dist: $(BINARY_ARCHIVE)
do-dist-windows-i386: $(BINARY_ARCHIVE)
do-dist-osx-i386: $(BINARY_ARCHIVE)
do-dist-linux-i386: $(BINARY_ARCHIVE)
do-dist-linux-x86_64: $(BINARY_ARCHIVE)

clean:
	@rm -rvf build
	@rm -vf fte/*.so
	@rm -vf fte/*.pyd
	@rm -vf *.pyc
	@rm -vf */*.pyc
	@rm -vf */*/*.pyc
	@rm -rvf $(THIRD_PARTY_DIR)/re2
	
test:
	@PATH=./bin:$(PATH) ./unittests
	@PATH=./bin:$(PATH) ./systemtests


# Supporting targets
$(BINARY_ARCHIVE): $(CDFA_BINARY)
	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)
	
ifeq ($(WINDOWS_BUILD),1)
	$(PYTHON) setup.py py2exe
	
	cd dist && mv *.dll fteproxy-$(FTEPROXY_RELEASE)/
	cd dist && mv *.exe fteproxy-$(FTEPROXY_RELEASE)/
	cd dist && mv *.pyd fteproxy-$(FTEPROXY_RELEASE)/
	cd dist && mv *.zip fteproxy-$(FTEPROXY_RELEASE)/

	cp README.md dist/fteproxy-$(FTEPROXY_RELEASE)
	cp COPYING dist/fteproxy-$(FTEPROXY_RELEASE)

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte
	cp fte/VERSION dist/fteproxy-$(FTEPROXY_RELEASE)/fte
	cp -rfv fte/defs dist/fteproxy-$(FTEPROXY_RELEASE)/fte
	cp -rfv fte/tests dist/fteproxy-$(FTEPROXY_RELEASE)/fte

	cd dist && zip -r fteproxy-$(FTEPROXY_RELEASE).zip fteproxy-$(FTEPROXY_RELEASE)
	cd dist && rm -rf fteproxy-$(FTEPROXY_RELEASE)
else
	pyinstaller fteproxy.spec
	cd dist && mv fteproxy fteproxy-$(FTEPROXY_RELEASE)/fteproxy

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas
	cp fte/tests/dfas/*.dfa dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas
	cp fte/tests/dfas/*.regex dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte
	cp fte/VERSION dist/fteproxy-$(FTEPROXY_RELEASE)/fte

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte/defs
	cp fte/defs/*.json dist/fteproxy-$(FTEPROXY_RELEASE)/fte/defs/

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas
	cp fte/tests/dfas/*.dfa dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas
	cp fte/tests/dfas/*.regex dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas

	cp README.md dist/fteproxy-$(FTEPROXY_RELEASE)
	cp COPYING dist/fteproxy-$(FTEPROXY_RELEASE)

	cp README.md dist/fteproxy-$(FTEPROXY_RELEASE)
	cp COPYING dist/fteproxy-$(FTEPROXY_RELEASE)
	
	cd dist && tar cvf fteproxy-$(FTEPROXY_RELEASE).tar fteproxy-$(FTEPROXY_RELEASE)
	cd dist && gzip -9 fteproxy-$(FTEPROXY_RELEASE).tar
	cd dist && rm -rf fteproxy-$(FTEPROXY_RELEASE)
endif


$(CDFA_BINARY): $(THIRD_PARTY_DIR)/re2/obj/libre2.a
ifeq ($(WINDOWS_BUILD),1)
	$(PYTHON) setup.py build_ext --inplace -c mingw32
else
	$(PYTHON) setup.py build_ext --inplace
endif


$(THIRD_PARTY_DIR)/re2/obj/libre2.a: $(RE2_DIR)
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a


$(RE2_DIR):
ifeq ($(WINDOWS_BUILD),1)
	cd $(THIRD_PARTY_DIR) && unzip re2-$(RE2_VERSION_WIN32)-src-win32.zip
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-core.patch

ifeq ($(CROSS_COMPILE),1)
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-crosscompile.patch
else
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-mingw.patch
endif

else
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-$(RE2_VERSION)-src-linux.tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-core.patch
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -R -i re2-nix.patch
endif


doc: phantom
phantom:
	@cd doc && $(MAKE) html
