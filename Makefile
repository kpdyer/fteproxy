# This file is part of fteproxy.
#
# fteproxy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# fteproxy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with fteproxy.  If not, see <http://www.gnu.org/licenses/>.

PLATFORM=$(shell uname)
PLATFORM_LOWER=$(shell echo $(PLATFORM) | tr A-Z a-z)
ifneq (, $(findstring cygwin, $(PLATFORM_LOWER)))
PLATFORM='windows'
endif
ARCH=$(shell arch)
VERSION=$(shell cat fte/VERSION)
FTEPROXY_RELEASE=$(VERSION)-$(PLATFORM_LOWER)-$(ARCH)

FTEPROXY_SRC=https://github.com/kpdyer/fteproxy/archive/master.zip
THIRD_PARTY_DIR=thirdparty
RE2_VERSION=20140111
RE2_VERSION_WIN32=20110930
RE2_DIR=$(THIRD_PARTY_DIR)/re2

all: fte/cDFA.so
win32: $(RE2_DIR)-win32
dist: dist/fteproxy-$(FTEPROXY_RELEASE).tar.gz

ifneq (, $(findstring windows, $(PLATFORM)))
dist/fteproxy-$(FTEPROXY_RELEASE).tar.gz: fte/cDFA.pyd
else
dist/fteproxy-$(FTEPROXY_RELEASE).tar.gz: fte/cDFA.so
endif
	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)
ifneq (, $(findstring windows, $(PLATFORM)))
	python setup.py py2exe
	cd dist && mv -f *.exe fteproxy-$(FTEPROXY_RELEASE)/
	cd dist && mv -f *.zip fteproxy-$(FTEPROXY_RELEASE)/
	cd dist && mv -f *.pyd fteproxy-$(FTEPROXY_RELEASE)/
	cp C:\\Windows\\System32\\msvcp100.dll dist/fteproxy-$(FTEPROXY_RELEASE)/
	cp C:\\Windows\\System32\\msvcr100.dll dist/fteproxy-$(FTEPROXY_RELEASE)/
else
	pyinstaller fteproxy.spec
	cd dist && mv fteproxy fteproxy-$(FTEPROXY_RELEASE)/fteproxy
endif

	cp README.md dist/fteproxy-$(FTEPROXY_RELEASE)
	cp COPYING dist/fteproxy-$(FTEPROXY_RELEASE)
	
	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte
	cp fte/VERSION dist/fteproxy-$(FTEPROXY_RELEASE)/fte

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte/defs
	cp fte/defs/*.json dist/fteproxy-$(FTEPROXY_RELEASE)/fte/defs/

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas
	cp fte/tests/dfas/*.dfa dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas
	cp fte/tests/dfas/*.regex dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas

	cd dist && tar cvf fteproxy-$(FTEPROXY_RELEASE).tar fteproxy-$(FTEPROXY_RELEASE)
	cd dist && gzip -9 fteproxy-$(FTEPROXY_RELEASE).tar
	cd dist && rm -rf fteproxy-$(FTEPROXY_RELEASE)

src: dist/fteproxy-$(VERSION)-src.tar.gz
dist/fteproxy-$(VERSION)-src.tar.gz: dist/fteproxy-master
	cd dist && mv fteproxy-master fteproxy-$(VERSION)-src
	cd dist && tar cvf fteproxy-$(VERSION)-src.tar fteproxy-$(VERSION)-src
	cd dist && gzip -9 fteproxy-$(VERSION)-src.tar
	cd dist && rm -rf fteproxy-$(VERSION)-src
	cd dist && rm master.zip
dist/fteproxy-master: dist/master.zip
	cd dist && unzip master.zip
dist/master.zip:
	mkdir -p dist
	cd dist && wget $(FTEPROXY_SRC)

fte/cDFA.pyd: win32 $(THIRD_PARTY_DIR)/re2/obj/libre2.a
	python.exe setup.py build_ext --inplace -c mingw32
fte/cDFA.so: $(THIRD_PARTY_DIR)/re2/obj/libre2.a
	python setup.py build_ext --inplace

$(THIRD_PARTY_DIR)/re2/obj/libre2.a: $(RE2_DIR)
	cd $(RE2_DIR) && CXXFLAGS="-Wall -O3 -fPIC -pthread $(CXXFLAGS)" $(MAKE) obj/libre2.a

$(RE2_DIR):
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-$(RE2_VERSION)-src-linux.tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-001.patch

$(RE2_DIR)-win32:
	cd $(THIRD_PARTY_DIR) && unzip re2-$(RE2_VERSION_WIN32)-src-win32.zip
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-001.patch
#	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-003.patch
	touch $(RE2_DIR)-win32

clean:
	@rm -rvf build
	@rm -rvf dist
	@rm -vf fte/*.so
	@rm -vf fte/*.pyd
	@rm -vf *.pyc
	@rm -vf */*.pyc
	@rm -vf */*/*.pyc


test:
	@PATH=./bin:$(PATH) ./unittests
	@PATH=./bin:$(PATH) ./systemtests


doc: phantom
phantom:
	@cd doc && $(MAKE) html
