#!/bin/bash

# faramail should maybe copy this script and the CSR into ca directory before sandboxing (if sandboxing mail and ca separately

cd ..

clientcert=$1
clientreq=$2
impass=pass
imcnf=$3

# intermediate CA signs certificate containing user's public key
openssl ca -batch -config $imcnf -extensions usr_cert \
    -passin pass:$impass \
    -days 365 -notext -md sha256 \
    -in $clientreq \
    -out $clientcert
