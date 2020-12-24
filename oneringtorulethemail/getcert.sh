#!/bin/bash

# faramail should maybe copy this script and the CSR into ca directory before sandboxing (if sandboxing mail and ca separately

cd ..

clientcert=$1
clientreq=$2
impass=pass
imcnf=$3
revoke=$4

# if $clientcert already exists and revoke flag is set, then openssl ca -config $imcnf -revoke $clientcert
# before creating a new cert
# else if $clientcert exists and revoke not set, then do nothing
# if $clientcert does not exist then create a new cert

if test -f "$clientcert"; then
    if [[ ! $revoke == "0" ]]; then
        echo "Revoking old certificate $clientcert"
        openssl ca -config $imcnf -revoke $clientcert -passin pass:$impass
        # intermediate CA signs certificate containing user's public key
        openssl ca -batch -config $imcnf -extensions usr_cert \
            -passin pass:$impass \
            -days 365 -notext -md sha256 \
            -in $clientreq \
            -out $clientcert
    fi
else
    # intermediate CA signs certificate containing user's public key
    openssl ca -batch -config $imcnf -extensions usr_cert \
        -passin pass:$impass \
        -days 365 -notext -md sha256 \
        -in $clientreq \
        -out $clientcert
fi