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
VERSION=$(shell cat VERSION)
FTEPROXY_RELEASE=$(VERSION)-$(PLATFORM_LOWER)-$(ARCH)

THIRD_PARTY_DIR=thirdparty

RE2_VERSION=20131024
RE2_TGZ=https://re2.googlecode.com/files/re2-$(RE2_VERSION).tgz
RE2_DIR=$(THIRD_PARTY_DIR)/re2

all: fte/cDFA
	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)
ifneq (, $(findstring windows, $(PLATFORM)))
	python setup.py py2exe
	cd dist && mv -f *.exe fteproxy-$(FTEPROXY_RELEASE)/
	cp C:\\Windows\\System32\\msvcp100.dll dist/fteproxy-$(FTEPROXY_RELEASE)/
	cp C:\\Windows\\System32\\msvcr100.dll dist/fteproxy-$(FTEPROXY_RELEASE)/
else
	pyinstaller fteproxy.spec
	cd dist && mv fteproxy fteproxy-$(FTEPROXY_RELEASE)/fteproxy
endif

	cp README.md dist/fteproxy-$(FTEPROXY_RELEASE)
	cp COPYING dist/fteproxy-$(FTEPROXY_RELEASE)

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte/defs
	cp fte/defs/*.json dist/fteproxy-$(FTEPROXY_RELEASE)/fte/defs/

	mkdir -p dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas
	cp fte/tests/dfas/*.dfa dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas
	cp fte/tests/dfas/*.regex dist/fteproxy-$(FTEPROXY_RELEASE)/fte/tests/dfas

	cd dist && tar cvf fteproxy-$(FTEPROXY_RELEASE).tar fteproxy-$(FTEPROXY_RELEASE)
	cd dist && gzip -9 fteproxy-$(FTEPROXY_RELEASE).tar

fte/cDFA: $(THIRD_PARTY_DIR)/re2/obj/libre2.a
	python setup.py build_ext --inplace

$(THIRD_PARTY_DIR)/re2/obj/libre2.a: $(THIRD_PARTY_DIR)/re2-$(RE2_VERSION).tgz
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a

$(THIRD_PARTY_DIR)/re2-$(RE2_VERSION).tgz:
	cd $(THIRD_PARTY_DIR) && curl $(RE2_TGZ) > re2-$(RE2_VERSION).tgz
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-$(RE2_VERSION).tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-001.patch
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-002.patch


clean:
	@rm -rvf build
	@rm -rvf dist
	@rm -vf fte/*.so
	@rm -vf fte/*.pyd
	@rm -rvf *.pyc


test:
	@PATH=./bin:$(PATH) ./unittests
	@PATH=./bin:$(PATH) ./systemtests


doc: phantom
phantom:
	@cd doc && $(MAKE) html
