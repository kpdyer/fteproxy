# TODO: print warning if /usr/local/bin is not in PATH
# TODO: print warning if /usr/local/lib is not in LD_LIBRARY_PATH
# TODO: encourage user to run "make test"

PREFIX=/usr/local
FTEPROXY_VERSION=0.2.0

THIRD_PARTY_DIR=thirdparty

RE2_TGZ=https://re2.googlecode.com/files/re2-20130115.tgz
RE2_DIR=$(THIRD_PARTY_DIR)/re2

OPENFST_VERSION=1.3.3
OPENFST_TGZ=http://www.openfst.org/twiki/pub/FST/FstDownload/openfst-$(OPENFST_VERSION).tar.gz

all: fte/cDFA.so

install: dist
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
	cd $(THIRD_PARTY_DIR) && wget $(RE2_TGZ)
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-20130115.tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-001.patch
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-002.patch
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a

$(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize:
	cd $(THIRD_PARTY_DIR) && wget $(OPENFST_TGZ)
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
	rm -rfv dist
	mkdir -p dist
	PATH=bin:$(PATH) pyinstaller --clean packaging/fteproxy.spec
	cp README.md dist/
	cp COPYING dist/

bin/fstminimize: $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize
	cp $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize bin/
bin/fstcompile: $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize
	cp $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstcompile bin/
bin/fstprint: $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize
	cp $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstprint bin/
