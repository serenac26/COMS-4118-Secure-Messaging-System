#!/bin/bash

[ -z "${1+xxx}" ] && echo "Dir not specified" && exit
[ -d $1 ] && echo "$1 exists" && exit

pwd=$(pwd)

mkdir "$1"
cd $1

mkdir server client
mkdir server/bin server/mail server/ca server/credentials

ca=server/ca
im=$ca/intermediate

mkdir $ca/certs $ca/intermediate $ca/newcerts $ca/private
mkdir $im/certs $im/csr $im/newcerts $im/private

for f in /home/mailbox/*; do
    cred="$(python3 $pwd/crypt-pw.py ${f:14})"
    credarray=($cred)
	echo "$cred" >> creds.txt
    printf "${credarray[1]}" >> server/credentials/${f:14}.hashedpw
done

mkdir client/bin client/tmp

for f in /home/mailbox/*; do
    mkdir "server/mail/${f:14}"
done