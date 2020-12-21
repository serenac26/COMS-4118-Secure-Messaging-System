CC = gcc
LD = gcc

BSTRDIR = ./bstrlib
NINERINGS = ./oneringtorulethemail/nineformortalmendoomedtodie
INCLUDES = -I$(BSTRDIR)
BSTROBJS = bstrlib.o bstrlibext.o
DEFINES =
LFLAGS = -L/usr/lib/ -L./bstrlib -lm -lcrypt
CFLAGS = -O3 -Wall -pedantic -ansi -s $(DEFINES) -std=c99 -g -D_GNU_SOURCE

install: install-unpriv scripts install-priv servercomponents

install-unpriv:
	./install-unpriv.sh $(TREE)

install-priv:
	sudo ./install-priv.sh $(TREE)

scripts: mail-in mail-out
	cp mail-in mail-out $(TREE)/server/bin

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

servercomponents: login checkmail changepw verifysign
	cp $^ $(TREE)/server/bin

login: login.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

checkmail: checkmail.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

changepw: changepw.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

verifysign: verifysign.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

%.o: $(NINERINGS)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f mail-in mail-out login checkmail changepw verifysign *.o

.PHONY : all
.PHONY : install
.PHONY : install-unpriv
.PHONY : install-priv
.PHONY : clean
