CC=gcc
CFLAGS=-c -Wall -static
LDFLAGS=
SOURCES=src/re2dfa.cc
OBJECTS=$(SOURCES:.cc=.o)
EXECUTABLE=bin/re2dfa
INCLUDE_DIR=third-party/re2

all: re2 re2dfa fte

install: fte
	sudo python setup.py install

re2dfa: $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -Lthird-party/re2/obj -lpthread -lgmp -lgmpxx -lre2 -o $(EXECUTABLE)

.cc.o:
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< -o $@

fte:
	python setup.py build_ext --inplace

re2:
	cd third-party && wget https://re2.googlecode.com/files/re2-20130115.tgz
	cd third-party && tar zxvf re2-20130115.tgz
	cd third-party && patch --verbose -p0 -i re2.patch
	cd third-party/re2 && make obj/libre2.a

clean:
	rm -rvf third-party/re2
	rm -rvf third-party/*.tgz
	rm src/*.o
	rm fte/*.o
