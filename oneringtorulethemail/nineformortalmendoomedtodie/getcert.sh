#!/bin/bash

# boromail should maybe copy this script and the CSR into ca directory before sandboxing (if sandboxing mail and ca separately)

# TODO: add TLS+encryption+signing roles for usr_cert configuration in imcnf

cert=../ca/intermediate/certs/$1.cert.pem
clientreq=$2
intermedcert=$3
intermediatekey=$4
pass=$5
imcnf=$6
clientcert=$7

# intermediate CA signs certificate containing user's public key
openssl ca -batch -config $imcnf -extensions usr_cert \
    -passin pass:$pass \
    -days 365 -notext -md sha256 \
    -in $clientreq \
    -out $cert
    
cp $cert $clientcert


