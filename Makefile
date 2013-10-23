CC=gcc
CFLAGS=-c -Wall -static -O3
LDFLAGS=-Lthird-party/re2/obj -lpthread -lgmp -lgmpxx -lre2
SOURCES=src/re2dfa.cc
OBJECTS=$(SOURCES:.cc=.o)
EXECUTABLE=bin/re2dfa

THIRD_PARTY_DIR=third-party
RE2_DIR=third-party/re2
RE2_PATCHFILE=re2.patch
INCLUDE_DIRS=-I$(RE2_DIR)

all: third-party/re2/obj/libre2.a bin/re2dfa fte/regex.so

install: all
	python setup.py install

bin/re2dfa: $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) $(LDFLAGS) -o $(EXECUTABLE)

.cc.o:
	$(CC) $(CFLAGS) $(INCLUDE_DIRS) $< -o $@

fte/regex.so:
	python setup.py build_ext --inplace

third-party/re2/obj/libre2.a:
	cd $(THIRD_PARTY_DIR) && wget https://re2.googlecode.com/files/re2-20130115.tgz
	cd $(THIRD_PARTY_DIR) && tar zxvf re2-20130115.tgz
	cd $(THIRD_PARTY_DIR) && patch --verbose -p0 -i $(RE2_PATCHFILE)
	cd $(RE2_DIR) && $(MAKE) obj/libre2.a

clean:
	rm -rvf third-party/re2
	rm -vf third-party/*.tgz
	rm -vf src/*.o
	rm -vf fte/*.so
	rm -vf bin/re2dfa

test:
	python test.py
