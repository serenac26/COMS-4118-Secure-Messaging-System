CC = gcc
LD = gcc

BSTRDIR = ./bstrlib
ONERING = ./oneringtorulethemail
NINERINGS = $(ONERING)/nineformortalmendoomedtodie
GOLLUM = ./gollum
INCLUDES = -I$(BSTRDIR)
BSTROBJS = bstrlib.o bstrlibext.o
SERVERUTILS = utils.o
DEFINES =
LFLAGS = -L/usr/lib/ -L./bstrlib -lm -lssl -lcrypt -lcrypto
CFLAGS = -O3 -Wall -pedantic -ansi -s $(DEFINES) -std=c99 -g -D_GNU_SOURCE

install: install-unpriv install-priv server servercomponents client

install-unpriv:
	./install-unpriv.sh $(TREE)

install-priv:
	sudo ./install-priv.sh $(TREE)

%.o : $(BSTRDIR)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o : %.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

server: pemithor boromail faramail
	mv $^ $(TREE)/server/bin

pemithor: pemithor.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)
	
boromail: boromail.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

faramail: faramail.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

%.o: $(ONERING)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

servercomponents: login checkmail verifysign sendto msgin #changepw
	mv $^ $(TREE)/server/bin
	cp $(NINERINGS)/getcert.sh $(TREE)/server/bin

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
	
%.o: $(NINERINGS)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

client: signmsg encryptmsg decryptmsg
	sudo mv $^ $(TREE)/client/bin
	sudo cp $(GOLLUM)/makecsr.sh $(TREE)/client/bin

signmsg: signmsg.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

encryptmsg: encryptmsg.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

decryptmsg: decryptmsg.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

%.o: $(GOLLUM)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f pemithor boromail faramail login checkmail changepw verifycert verifysign sendto msgin msgout signmsg encryptmsg decryptmsg *.o

.PHONY : all
.PHONY : install
.PHONY : install-unpriv
.PHONY : install-priv
.PHONY : clean