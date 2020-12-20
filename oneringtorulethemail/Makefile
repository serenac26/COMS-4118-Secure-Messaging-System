CC=gcc
CFLAGS=-I.

ODIR=obj
LDIR =../lib

LIBS=-lm
LDLIBS=

install: pemithor boromail faramail

pemithor: pemithor.o
	$(CC) $^ $(LDLIBS) -o $@ $(CFLAGS) $(LIBS)

boromail: boromail.o
	$(CC) $^ $(LDLIBS) -o $@ $(CFLAGS) $(LIBS)

faramail: faramail.o
	$(CC) $^ $(LDLIBS) -o $@ $(CFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f *.o pemithor boromail faramail