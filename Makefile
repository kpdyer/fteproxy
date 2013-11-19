PREFIX=/usr/local
PLATFORM=$(shell uname)
PLATFORM_LOWER=$(shell echo $(PLATFORM) | tr A-Z a-z)
ARCH=$(shell arch)
FTEPROXY_VERSION=0.2.0-$(PLATFORM_LOWER)-$(ARCH)

THIRD_PARTY_DIR=thirdparty

RE2_VERSION=20130115
RE2_TGZ=https://re2.googlecode.com/files/re2-$(RE2_VERSION).tgz
RE2_DIR=$(THIRD_PARTY_DIR)/re2

OPENFST_VERSION=1.3.3
OPENFST_TGZ=http://www.openfst.org/twiki/pub/FST/FstDownload/openfst-$(OPENFST_VERSION).tar.gz

all: fte/cDFA.so
	mkdir -p dist/fteproxy-$(FTEPROXY_VERSION)
	pyinstaller fteproxy.spec
	cd dist && cp fteproxy fteproxy-$(FTEPROXY_VERSION)/
	cp README.md dist/fteproxy-$(FTEPROXY_VERSION)
	cp COPYING dist/fteproxy-$(FTEPROXY_VERSION)
	cd dist && tar cvf fteproxy-$(FTEPROXY_VERSION).tar fteproxy-$(FTEPROXY_VERSION)
	cd dist && gzip -9 fteproxy-$(FTEPROXY_VERSION).tar

install:
	@test -s dist/fteproxy || { echo "Please run \"make\" first."; exit 1; }
	cp dist/fteproxy $(PREFIX)/bin/
	@echo ""
	@echo "###########################################################"
	@echo "#"
	@echo "# Installation complete!!"
	@echo "# "
	@echo "# !!! For fteproxy to work, you must ensure $(PREFIX) is in your PATH!"
	@echo "#"
	@echo "###########################################################"
	@echo ""

fte/cDFA.so: $(THIRD_PARTY_DIR)/re2/obj/libre2.a bin/fstcompile bin/fstprint bin/fstminimize
	python setup.py build_ext --inplace

$(THIRD_PARTY_DIR)/re2/obj/libre2.a: bin/fstminimize bin/fstprint bin/fstcompile
	cd $(THIRD_PARTY_DIR) && curl $(RE2_TGZ) > re2-$(RE2_VERSION).tgz
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-$(RE2_VERSION).tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-001.patch
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-002.patch
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a

$(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize:
	cd $(THIRD_PARTY_DIR) && curl $(OPENFST_TGZ) > openfst-$(OPENFST_VERSION).tar.gz
	cd $(THIRD_PARTY_DIR) && tar zxvf openfst-$(OPENFST_VERSION).tar.gz
	cd $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION) && ./configure --enable-fast-install --disable-dependency-tracking --disable-shared --enable-static --prefix=$(PREFIX)
	cd $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION) && $(MAKE)

clean:
	@find . -name "*.pyc" -exec rm {} \;
	@rm -rvf build
	@rm -rvf dist
	@rm -rvf $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)
	@rm -vf $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION).tar.gz
	@rm -rvf $(THIRD_PARTY_DIR)/re2
	@rm -vf $(THIRD_PARTY_DIR)/*.tgz
	@rm -vf src/*.o
	@rm -vf fte/*.so
	@rm -vf bin/fst*
	@rm -vf socks.log
	@cd doc && $(MAKE) clean

test:
	@PATH=./bin:./$(THIRD_PARTY_DIR)/openfst-1.3.3/src/bin:$(PATH) ./unittests
	@PATH=./bin:./$(THIRD_PARTY_DIR)/openfst-1.3.3/src/bin:$(PATH) ./systemtests

uninstall:
	@rm -fv /usr/local/bin/fteproxy

doc: phantom
phantom:
	@cd doc && $(MAKE) html
	
dist: all

bin/fstminimize: $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize
	cp $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize bin/
bin/fstcompile: $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize
	cp $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstcompile bin/
bin/fstprint: $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize
	cp $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstprint bin/
