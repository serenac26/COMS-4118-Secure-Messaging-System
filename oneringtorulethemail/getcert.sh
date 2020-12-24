#!/bin/bash

# faramail should maybe copy this script and the CSR into ca directory before sandboxing (if sandboxing mail and ca separately

cd ..

clientcert=$1
clientreq=$2
impass=pass
imcnf=$3

# check if $clientcert already exists
# if it does, then openssl ca -config $imcnf -revoke $clientcert
if test -f "$clientcert"; then
    echo "Revoking old certificate $clientcert"
    openssl ca -config $imcnf -revoke $clientcert
fi

# intermediate CA signs certificate containing user's public key
openssl ca -batch -config $imcnf -extensions usr_cert \
    -passin pass:$impass \
    -days 365 -notext -md sha256 \
    -in $clientreq \
    -out $clientcert
