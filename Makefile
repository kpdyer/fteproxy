# TODO: print warning if /usr/local/bin is not in PATH
# TODO: print warning if /usr/local/lib is not in LD_LIBRARY_PATH
# TODO: encourage user to run "make test"

PREFIX=/usr/local

THIRD_PARTY_DIR=third-party

RE2_TGZ=https://re2.googlecode.com/files/re2-20130115.tgz
RE2_DIR=third-party/re2

OPENFST_VERSION=1.3.3
OPENFST_TGZ=http://www.openfst.org/twiki/pub/FST/FstDownload/openfst-$(OPENFST_VERSION).tar.gz

all: $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize $(THIRD_PARTY_DIR)/re2/obj/so/libre2.so fte/cDFA.so

install: all
	cd $(THIRD_PARTY_DIR)/re2 && make install
	cd $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION) && make install
	python setup.py install --prefix=$(PREFIX)
	@echo ""
	@echo "###########################################################"
	@echo "#"
	@echo "# Installation complete!!"
	@echo "# "
	@echo "# For fteproxy to work, you must ensure:"
	@echo "#"
	@echo "#   /usr/local/bin"
	@echo "#"
	@echo "# is in your PATH, and"
	@echo "#"
	@echo "#   /usr/local/lib"
	@echo "#"
	@echo "# is in your LD_LIBRARY_PATH."
	@echo "#"
	@echo "###########################################################"
	@echo ""

f/tch --verbose -p0 -i re2-002.patchte/cDFA.so: $(THIRD_PARTY_DIR)/re2/obj/so/libre2.so $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize
	python setup.py build_ext --inplace

$(THIRD_PARTY_DIR)/re2/obj/so/libre2.so:
	cd $(THIRD_PARTY_DIR) && wget $(RE2_TGZ)
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-20130115.tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-001.patch
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i re2-002.patch
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a
	cd $(RE2_DIR) && $(MAKE) obj/so/libre2.so

$(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize:
	cd $(THIRD_PARTY_DIR) && wget $(OPENFST_TGZ)
	cd $(THIRD_PARTY_DIR) && tar zxvf openfst-$(OPENFST_VERSION).tar.gz
	cd $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION) && ./configure --enable-fast-install --disable-dependency-tracking --prefix=$(PREFIX)
	cd $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION) && $(MAKE)

clean:
	@find . -name "*.pyc" -exec rm {} \;
	@rm -rvf build
	@rm -rvf third-party/openfst-$(OPENFST_VERSION)
	@rm -vf third-party/openfst-$(OPENFST_VERSION).tar.gz
	@rm -rvf third-party/re2
	@rm -vf third-party/*.tgz
	@rm -vf src/*.o
	@rm -vf fte/*.so
	@rm -vf socks.log
	@cd doc && $(MAKE) clean

test:
	@./unittests
	@./systemtests

uninstall:
	@rm -rfv /usr/local/fteproxy
	@rm -vf /usr/local/lib/libfst*
	@rm -vf /usr/local/lib/libre2*
	@rm -rfv /usr/local/lib/python2.7/dist-packages/fte
	@rm -rfv /usr/local/lib/python2.7/dist-packages/cDFAs
	@rm -fv /usr/local/lib/python2.7/dist-packages/Format_Transforming_Encrypion_*.info
	@rm -fv /usr/local/bin/fteproxy

doc: phantom
phantom:
	@cd doc && $(MAKE) html
