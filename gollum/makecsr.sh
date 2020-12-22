#!/bin/bash

# either user or client can use this script to create a CSR
# if user, then the user will simply provide the resulting CSR file to the client
# if client, then the user will provide their private key to the client
# leaning toward client rn for user-friendliness :)

openssl req -config $cacnf -nodes \
  -key $clientprivkey -out $clientreq