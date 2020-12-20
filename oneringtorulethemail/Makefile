CC=gcc
CFLAGS=-I.

ODIR=obj
LDIR =../lib

LIBS=-lm

install: pemithor boromail faramail

pemithor: pemithor.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

boromail: boromail.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

faramail: faramail.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f *.o pemithor boromail faramail