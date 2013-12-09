PREFIX=/usr/local
PLATFORM=$(shell uname)
PLATFORM_LOWER=$(shell echo $(PLATFORM) | tr A-Z a-z)
ifneq (, $(findstring cygwin, $(PLATFORM_LOWER)))
PLATFORM='windows'
endif
ARCH=$(shell arch)
FTEPROXY_VERSION=0.2.0-$(PLATFORM_LOWER)-$(ARCH)

THIRD_PARTY_DIR=thirdparty

RE2_VERSION=20130115
RE2_TGZ=https://re2.googlecode.com/files/re2-$(RE2_VERSION).tgz
RE2_DIR=$(THIRD_PARTY_DIR)/re2

all: fte/cDFA
	mkdir -p dist/fteproxy-$(FTEPROXY_VERSION)
ifneq (, $(findstring windows, $(PLATFORM)))
	python setup.py py2exe
	cd dist && mv -f *.exe fteproxy-$(FTEPROXY_VERSION)/
	cp C:\\Windows\\System32\\msvcp100.dll dist/fteproxy-$(FTEPROXY_VERSION)/
	cp C:\\Windows\\System32\\msvcr100.dll dist/fteproxy-$(FTEPROXY_VERSION)/
else
	pyinstaller fteproxy.spec
	cd dist && mv fteproxy fteproxy-$(FTEPROXY_VERSION)/fteproxy
endif

	cp README.md dist/fteproxy-$(FTEPROXY_VERSION)
	cp COPYING dist/fteproxy-$(FTEPROXY_VERSION)

	mkdir -p dist/fteproxy-$(FTEPROXY_VERSION)/fte/defs
	cp fte/defs/*.json dist/fteproxy-$(FTEPROXY_VERSION)/fte/defs/

	mkdir -p dist/fteproxy-$(FTEPROXY_VERSION)/fte/tests/dfas
	cp fte/tests/dfas/*.dfa dist/fteproxy-$(FTEPROXY_VERSION)/fte/tests/dfas
	cp fte/tests/dfas/*.regex dist/fteproxy-$(FTEPROXY_VERSION)/fte/tests/dfas

	cd dist && tar cvf fteproxy-$(FTEPROXY_VERSION).tar fteproxy-$(FTEPROXY_VERSION)
	cd dist && gzip -9 fteproxy-$(FTEPROXY_VERSION).tar

fte/cDFA: $(THIRD_PARTY_DIR)/re2/obj/libre2.a
	python setup.py build_ext --inplace

$(THIRD_PARTY_DIR)/re2/obj/libre2.a: $(THIRD_PARTY_DIR)/re2-$(RE2_VERSION).tgz
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-$(RE2_VERSION).tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-001.patch
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-002.patch
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a

$(THIRD_PARTY_DIR)/re2-$(RE2_VERSION).tgz:
	cd $(THIRD_PARTY_DIR) && curl $(RE2_TGZ) > re2-$(RE2_VERSION).tgz


clean:
	@rm -rvf build
	@rm -rvf dist
	@rm -rvf $(THIRD_PARTY_DIR)/re2
	@rm -vf fte/*.so
	@rm -vf fte/*.pyd
	@rm -vf fte/*.pyc


test:
	@PATH=./bin:$(PATH) ./unittests
	@PATH=./bin:$(PATH) ./systemtests


uninstall:
	@rm -fv /usr/local/bin/fteproxy


doc: phantom
phantom:
	@cd doc && $(MAKE) html
