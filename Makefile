CC = gcc
LD = gcc

BSTRDIR = ./bstrlib
NINERINGS = ./oneringtorulethemail/nineformortalmendoomedtodie
INCLUDES = -I$(BSTRDIR)
BSTROBJS = bstrlib.o bstrlibext.o
SERVERUTILS = utils.o
DEFINES =
LFLAGS = -L/usr/lib/ -L./bstrlib -lm -lssl -lcrypt -lcrypto
CFLAGS = -O3 -Wall -pedantic -ansi -s $(DEFINES) -std=c99 -g -D_GNU_SOURCE

install: install-unpriv scripts install-priv servercomponents userhelpers

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

servercomponents: login checkmail verifysign sendto msgin #changepw
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

sendto: sendto.o $(SERVERUTILS) $(BSTROBJS)
	echo Linking: $@
	$(CC) $< $(SERVERUTILS) $(BSTROBJS) -o $@ $(LFLAGS)

msgin: msgin.o $(SERVERUTILS) $(BSTROBJS)
	echo Linking: $@
	$(CC) $< $(SERVERUTILS) $(BSTROBJS) -o $@ $(LFLAGS)

userhelpers: signmsg

signmsg: signmsg.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

signmsg.o: signmsg.c

%.o: $(NINERINGS)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f mail-in mail-out login checkmail changepw verifysign signmsg *.o

.PHONY : all
.PHONY : install
.PHONY : install-unpriv
.PHONY : install-priv
.PHONY : clean
