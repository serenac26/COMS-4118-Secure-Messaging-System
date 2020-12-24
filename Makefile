CC = gcc
LD = gcc

B64DIR = ./base64
BSTRDIR = ./bstrlib
ONERING = ./oneringtorulethemail
GOLLUM = ./gollum
INCLUDES = -I$(BSTRDIR) -I$(B64DIR) -I./
B64OBJS = base64.o
BSTROBJS = bstrlib.o bstrlibext.o
DEFINES =
LFLAGS = -L/usr/lib/ -L./bstrlib -L./base64 -lm -lssl -lcrypt -lcrypto
CFLAGS = -O3 -Wall -pedantic -ansi -s $(DEFINES) -std=c99 -g -D_GNU_SOURCE

install: install-unpriv server client gen-certs install-priv 

install-unpriv:
	./install-unpriv.sh $(TREE)

install-priv:
	sudo ./install-priv.sh $(TREE)

gen-certs:
	sudo ./gen-certs.sh $(TREE)

%.o : $(B64DIR)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

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
	
boromail: boromail.o utils.o boromailutils.o $(BSTROBJS) $(B64OBJS)
	echo Linking: $@
	$(CC) $< utils.o boromailutils.o $(BSTROBJS) $(B64OBJS) -o $@ $(LFLAGS)

faramail: faramail.o utils.o faramailutils.o $(BSTROBJS) $(B64OBJS)
	echo Linking: $@
	$(CC) $< utils.o faramailutils.o $(BSTROBJS) $(B64OBJS) -o $@ $(LFLAGS)

%.o: $(ONERING)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Start testing
boromailutils: boromailutils.o utils.o $(BSTROBJS) $(B64OBJS)
	echo Linking: $@
	$(CC) $< utils.o $(BSTROBJS) $(B64OBJS) -o $@ $(LFLAGS)
	sudo cp boromailutils $(TREE)/server/bin

faramailutils: faramailutils.o utils.o $(BSTROBJS) $(B64OBJS)
	echo Linking: $@
	$(CC) $< utils.o $(BSTROBJS) $(B64OBJS) -o $@ $(LFLAGS)
	sudo cp faramailutils $(TREE)/server/bin

servercomponents: verifysign msgout
	sudo mv $^ $(TREE)/server/bin
	
verifysign: verifysign.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)
# End testing
	
client: signmsg encryptmsg decryptmsg send-msg recv-msg
	sudo mv $^ $(TREE)/client/bin
	sudo cp $(GOLLUM)/makecsr.sh $(GOLLUM)/genkey.sh $(TREE)/client/bin
	sudo cp imopenssl.cnf $(TREE)/client

# Not compiling yet
get-cert: get-cert.o utils.o $(BSTROBJS) $(B64OBJS)
	echo Linking: $@
	$(CC) $< utils.o $(BSTROBJS) $(B64OBJS) -o $@ $(LFLAGS)

change-pw: change-pw.o utils.o $(BSTROBJS) $(B64OBJS)
	echo Linking: $@
	$(CC) $< utils.o $(BSTROBJS) $(B64OBJS) -o $@ $(LFLAGS)
#

send-msg: send-msg.o utils.o $(BSTROBJS) $(B64OBJS)
	echo Linking: $@
	$(CC) $< utils.o $(BSTROBJS) $(B64OBJS) -o $@ $(LFLAGS)

recv-msg: recv-msg.o utils.o $(BSTROBJS) $(B64OBJS)
	echo Linking: $@
	$(CC) $< utils.o $(BSTROBJS) $(B64OBJS) -o $@ $(LFLAGS)

signmsg: signmsg.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

encryptmsg: encryptmsg.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

decryptmsg: decryptmsg.o
	echo Linking: $@
	$(CC) $< -o $@ $(LFLAGS)

testutils: testutils.o utils.o $(BSTROBJS) $(B64OBJS)
	echo Linking: $@
	$(CC) $< utils.o $(BSTROBJS) $(B64OBJS) -o $@ $(LFLAGS)

%.o: $(GOLLUM)/%.c
	echo Compiling: $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f pemithor boromail boromailutils faramail faramailutils verifysign msgout signmsg encryptmsg decryptmsg get-cert change-pw send-msg recv-msg testutils *.o

.PHONY : all
.PHONY : install
.PHONY : install-unpriv
.PHONY : install-priv
.PHONY : gen-certs
.PHONY : clean
