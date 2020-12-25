#!/bin/bash

# rsapass=$(head -c 100 /dev/urandom | tr -dc 'a-zA-Z0-9+_-')
rsapass=pass

pwd=$(pwd)

cp rootopenssl.cnf $1/server/rootopenssl.cnf
cp imopenssl.cnf $1/server/imopenssl.cnf

cd $1/server

rootcnf=rootopenssl.cnf
imcnf=imopenssl.cnf

touch ca/index.txt
echo 1000 >ca/serial

rootrsa=ca/private/ca.key.pem
echo "generate root RSA key and store in read-only file $rootrsa"
openssl genrsa -aes256 -out $rootrsa -passout pass:$rsapass 4096
chmod 400 $rootrsa

echo _________________________________________________________________________________________

rootcert=ca/certs/ca.cert.pem
echo "generate self-signed root certificate from root RSA key \
and store in read-only file $rootcert"
openssl req -config $rootcnf \
    -passin pass:$rsapass \
    -key $rootrsa \
    -subj /C=ME/ST=Gondor/O=Aragorn/OU=Aragorn_Certificate_Authority/CN=Aragorn_Root_CA/ \
    -new -x509 -days 7300 -sha256 -extensions v3_ca \
    -out $rootcert
chmod 444 $rootcert

echo _________________________________________________________________________________________

echo "verify root certificate"
openssl x509 -noout -text -in $rootcert

echo _________________________________________________________________________________________

im=ca/intermediate

touch $im/index.txt
echo 1000 > $im/serial

imrsa=$im/private/intermediate.key.pem
echo "generate intermediate RSA key and store in read-only file $imrsa"
openssl genrsa -aes256 -out $imrsa -passout pass:$rsapass 4096
chmod 400 $imrsa

echo _________________________________________________________________________________________

imreq=$im/csr/intermediate.csr.pem
echo "create intermediate certificate signing request with intermediate RSA key $imreq"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $imrsa \
    -subj /C=ME/ST=Gondor/O=Aragorn/OU=Aragorn_Certificate_Authority/CN=Aragorn_Intermediate_CA/ \
    -out $imreq

echo _________________________________________________________________________________________

imcert=$im/certs/intermediate.cert.pem
echo "sign intermediate certificate with root certificate and store in $imcert"
openssl ca -batch -config $rootcnf -extensions v3_intermediate_ca \
    -passin pass:$rsapass \
    -days 3650 -notext -md sha256 \
    -in $imreq \
    -out $imcert

echo _________________________________________________________________________________________

echo "verify intermediate certificate"
openssl x509 -noout -text -in $imcert
openssl verify -CAfile $rootcert $imcert

echo _________________________________________________________________________________________

cachain=$im/certs/ca-chain.cert.pem
echo "create certificate chain file $cachain"
cat $imcert $rootcert > $cachain
chmod 444 $cachain

echo _________________________________________________________________________________________

bserverrsa=$im/private/boromail.key.pem
echo "generate boromail web server RSA key"
openssl genrsa -aes256 -out $bserverrsa -passout pass:$rsapass 2048
chmod 400 $bserverrsa

echo _________________________________________________________________________________________

bserverreq=$im/csr/boromail.csr.pem
echo "create boromail web server CSR with web server RSA key $bserverreq"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $bserverrsa \
    -subj /C=ME/ST=Gondor/O=Boromail/OU=Boromail_Web_Server/CN=boromail.com/ \
    -out $bserverreq

echo _________________________________________________________________________________________

bservercert=$im/certs/boromail.cert.pem
echo "sign boromail web server certificate with intermediate certificate"
openssl ca -batch -config $imcnf -extensions server_cert \
    -passin pass:$rsapass \
    -days 375 -notext -md sha256 \
    -in $bserverreq \
    -out $bservercert
chmod 444 $bservercert

echo _________________________________________________________________________________________

echo "verify boromail web server certificate"
openssl x509 -noout -text -in $bservercert
openssl verify -CAfile $cachain $bservercert

echo _________________________________________________________________________________________

fserverrsa=$im/private/faramail.key.pem
echo "generate faramail web server RSA key"
openssl genrsa -aes256 -out $fserverrsa -passout pass:$rsapass 2048
chmod 400 $fserverrsa

echo _________________________________________________________________________________________

fserverreq=$im/csr/faramail.csr.pem
echo "create faramail web server CSR with web server RSA key $fserverreq"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $fserverrsa \
    -subj /C=ME/ST=Gondor/O=Faramail/OU=Faramail_Web_Server/CN=faramail.com/ \
    -out $fserverreq

echo _________________________________________________________________________________________

fservercert=$im/certs/faramail.cert.pem
echo "sign faramail web server certificate with intermediate certificate"
openssl ca -batch -config $imcnf -extensions server_cert \
    -passin pass:$rsapass \
    -days 375 -notext -md sha256 \
    -in $fserverreq \
    -out $fservercert
chmod 444 $fservercert

echo _________________________________________________________________________________________

echo "verify faramail web server certificate"
openssl x509 -noout -text -in $fservercert
openssl verify -CAfile $cachain $fservercert

cd $pwd
rm $1/server/rootopenssl.cnf
cp $1/server/ca/certs/ca.cert.pem $1/client/ca.cert.pem
cp $1/server/ca/intermediate/certs/intermediate.cert.pem $1/client/intermediate.cert.pem
cp $1/server/ca/intermediate/certs/ca-chain.cert.pem $1/client/ca-chain.cert.pem