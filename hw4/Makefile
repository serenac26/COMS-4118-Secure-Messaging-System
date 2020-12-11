CC = gcc
LD = gcc

BSTRDIR = ./bstrlib
INCLUDES = -I$(BSTRDIR)
BSTROBJS = bstrlib.o bstrlibext.o
DEFINES =
LFLAGS = -L/usr/lib/ -L./bstrlib -lm 
CFLAGS = -O3 -Wall -pedantic -ansi -s $(DEFINES) -std=c99 -g -D_GNU_SOURCE

install: install-unpriv scripts install-priv

install-unpriv:
	./install-unpriv.sh $(TREE)

install-priv:
	sudo ./install-priv.sh $(TREE)

scripts: mail-in mail-out
	cp mail-in mail-out $(TREE)/bin

mail-in: mail-in.o $(BSTROBJS)
	echo Linking: $@
	$(CC) $< $(BSTROBJS) -o $@ $(LFLAGS)

mail-out: mail-out.o $(BSTROBJS)
	echo Linking: $@
	$(CC) $< $(BSTROBJS) -o $@ $(LFLAGS)

%.o : $(BSTRDIR)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o : %.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f mail-in mail-out *.o

.PHONY : all
.PHONY : install
.PHONY : install-unpriv
.PHONY : install-priv
.PHONY : clean