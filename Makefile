CC = gcc
LD = gcc

BSTRDIR = ./bstrlib
ONERING = ./oneringtorulethemail
GOLLUM = ./gollum
INCLUDES = -I$(BSTRDIR) -I./
BSTROBJS = bstrlib.o bstrlibext.o
DEFINES =
LFLAGS = -L/usr/lib/ -L./bstrlib -lm -lssl -lcrypt -lcrypto
CFLAGS = -O3 -Wall -pedantic -ansi -s $(DEFINES) -std=c99 -g -D_GNU_SOURCE

install: install-unpriv server client gen-certs install-priv 

install-unpriv:
	./install-unpriv.sh $(TREE)

install-priv:
	sudo ./install-priv.sh $(TREE)

gen-certs:
	sudo ./gen-certs.sh $(TREE)

%.o : $(BSTRDIR)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o : %.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

server: pemithor boromail faramail
	sudo mv $^ $(TREE)/server/bin
	sudo cp $(ONERING)/getcert.sh $(TREE)/server/bin

pemithor: pemithor.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)
	
boromail: boromail.o utils.o boromailutils.o $(BSTROBJS)
	echo Linking: $@
	$(CC) $< utils.o boromailutils.o $(BSTROBJS) -o $@ $(LFLAGS)

faramail: faramail.o utils.o faramailutils.o $(BSTROBJS)
	echo Linking: $@
	$(CC) $< utils.o faramailutils.o $(BSTROBJS) -o $@ $(LFLAGS)

%.o: $(ONERING)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Start testing
boromailutils: boromailutils.o utils.o $(BSTROBJS)
	echo Linking: $@
	$(CC) $< utils.o $(BSTROBJS) -o $@ $(LFLAGS)
	sudo cp boromailutils $(TREE)/server/bin

servercomponents: verifysign msgout
	sudo mv $^ $(TREE)/server/bin
	
verifysign: verifysign.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

msgout: msgout.o utils.o $(BSTROBJS)
	echo Linking: $@
	$(CC) $< utils.o $(BSTROBJS) -o $@ $(LFLAGS)
# End testing
	
client: signmsg encryptmsg decryptmsg
	sudo mv $^ $(TREE)/client/bin
	sudo cp $(GOLLUM)/makecsr.sh $(GOLLUM)/genkey.sh $(TREE)/client/bin
	sudo cp imopenssl.cnf $(TREE)/client

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
	rm -f pemithor boromail boromailutils faramail verifysign msgout signmsg encryptmsg decryptmsg *.o

.PHONY : all
.PHONY : install
.PHONY : install-unpriv
.PHONY : install-priv
.PHONY : gen-certs
.PHONY : clean