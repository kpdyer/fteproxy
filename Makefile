THIRD_PARTY_DIR=third-party
RE2_DIR=third-party/re2
RE2_PATCHFILE=re2.patch

all: third-party/re2/obj/libre2.a fte/dfa.so doc

install: all
	python setup.py install

fte/dfa.so:
	python setup.py build_ext --inplace

third-party/re2/obj/libre2.a:
	cd $(THIRD_PARTY_DIR) && wget https://re2.googlecode.com/files/re2-20130115.tgz
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-20130115.tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i $(RE2_PATCHFILE)
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a

clean:
	@find . -name "*.pyc" -exec rm {} \;
	@rm -rvf build
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
	@rm -rfv /usr/local/lib/python2.7/dist-packages/fte
	@rm -rfv /usr/local/lib/python2.7/dist-packages/dfas
	@rm -fv /usr/local/lib/python2.7/dist-packages/Format_Transforming_Encrypion_FTE_-0.2.0_alpha.egg-info
	@rm -fv /usr/local/bin/fteproxy

doc: phantom
phantom:
	@cd doc && $(MAKE) html
