#!/bin/bash

# boromail should maybe copy this script and the CSR into ca directory before sandboxing (if sandboxing mail and ca separately

cd ..

cert=ca/intermediate/certs/$1.cert.pem
clientreq=$2
pass=pass
imcnf=$4
clientcert=$5

# intermediate CA signs certificate containing user's public key
openssl ca -batch -config $imcnf -extensions usr_cert \
    -passin pass:$pass \
    -days 365 -notext -md sha256 \
    -in $clientreq \
    -out $cert
    
cp $cert $clientcert


