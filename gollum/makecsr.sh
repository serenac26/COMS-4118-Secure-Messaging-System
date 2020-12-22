#!/bin/bash

# either user or client can use this script to create a CSR
# if user, then the user will simply provide the resulting CSR file to the client
# if client, then the user will provide their private key to the client
# leaning toward client rn for user-friendliness :)

imcnf=$1
username=$2
clientkey=$3
pass=$4
clientreq=$5

openssl req -config $imcnf -new -sha256 \
  -key $clientkey \
  -passin pass:$pass \
  -subj /C=US/ST=NY/O=$username/OU=client_$username/CN=$username/ \
  -out $clientreq