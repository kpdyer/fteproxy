PREFIX=/usr/local

THIRD_PARTY_DIR=third-party

RE2_TGZ=https://re2.googlecode.com/files/re2-20130115.tgz
RE2_DIR=third-party/re2
RE2_PATCHFILE=re2.patch

OPENFST_VERSION=1.3.3
OPENFST_TGZ=http://www.openfst.org/twiki/pub/FST/FstDownload/openfst-$(OPENFST_VERSION).tar.gz

all: $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize $(THIRD_PARTY_DIR)/re2/obj/libre2.a fte/cDFA.so

install: all
	cd $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION) && make install
	python setup.py install --prefix=$(PREFIX)

fte/cDFA.so: $(THIRD_PARTY_DIR)/re2/obj/libre2.a $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize
	python setup.py build_ext --inplace

$(THIRD_PARTY_DIR)/re2/obj/libre2.a:
	cd $(THIRD_PARTY_DIR) && wget $(RE2_TGZ)
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-20130115.tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i $(RE2_PATCHFILE)
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a

$(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION)/src/bin/fstminimize:
	cd $(THIRD_PARTY_DIR) && wget $(OPENFST_TGZ)
	cd $(THIRD_PARTY_DIR) && tar zxvf openfst-$(OPENFST_VERSION).tar.gz
	cd $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION) && ./configure --enable-fast-install --disable-dependency-tracking --prefix=$(PREFIX)
	cd $(THIRD_PARTY_DIR)/openfst-$(OPENFST_VERSION) && make -j `nproc`

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
	@rm -rfv /usr/local/lib/python2.7/dist-packages/fte
	@rm -rfv /usr/local/lib/python2.7/dist-packages/cDFAs
	@rm -fv /usr/local/lib/python2.7/dist-packages/Format_Transforming_Encrypion_FTE_-0.2.0_alpha.egg-info
	@rm -fv /usr/local/bin/fteproxy

doc: phantom
phantom:
	@cd doc && $(MAKE) html
