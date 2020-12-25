#!/bin/bash

# uncomment main in faramailutils.c first
make faramailutils TREE=$1
cd $1/client/bin
./genkey.sh ../../../$2.key.pem $3
./makecsr.sh ../imopenssl.cnf $2 ../../../$2.key.pem ../../../$2.req.pem
cd ../../..
sudo cp $2.req.pem $1/server/ca/intermediate/csr/
cd $1/server/bin
sudo ./faramailutils getcert $2
sudo cp ../ca/intermediate/certs/$2.cert.pem ../../../$2.cert.pem