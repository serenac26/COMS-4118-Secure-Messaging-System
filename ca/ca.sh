#!/bin/bash

rootcnf=rootopenssl.cnf

dir=./ca
rsapass=rsapassword

rm -rf $dir
rm -f server.out*

mkdir -p $dir
mkdir $dir/certs $dir/newcerts $dir/private
chmod 700 $dir/private
touch $dir/index.txt
echo 1000 > $dir/serial

rootrsa=$dir/private/ca.key.pem
echo "generate root RSA key and store in read-only file $rootrsa"
openssl genrsa -aes256 -out $rootrsa -passout pass:$rsapass 4096
chmod 400 $rootrsa

echo _________________________________________________________________________________________

rootcert=$dir/certs/ca.cert.pem
echo "generate self-signed root certificate from root RSA key \
and store in read-only file $rootcert"
openssl req -config $rootcnf \
    -passin pass:$rsapass \
    -key $rootrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Certificate_Authority/CN=stc2137_Root_CA/ \
    -new -x509 -days 7300 -sha256 -extensions v3_ca \
    -out $rootcert
chmod 444 $rootcert

echo _________________________________________________________________________________________

echo "verify root certificate"
openssl x509 -noout -text -in $rootcert

echo _________________________________________________________________________________________

imdir=$dir/intermediate
mkdir $imdir
mkdir $imdir/certs $imdir/csr $imdir/newcerts $imdir/private
chmod 700 $imdir/private
touch $imdir/index.txt
echo 1000 > $imdir/serial

imcnf=imopenssl.cnf
imrsa=$imdir/private/intermediate.key.pem
echo "generate intermediate RSA key and store in read-only file $imrsa"
openssl genrsa -aes256 -out $imrsa -passout pass:$rsapass 4096
chmod 400 $imrsa

echo _________________________________________________________________________________________

imreq=$imdir/csr/intermediate.csr.pem
echo "create intermediate certificate signing request with intermediate RSA key $imreq"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $imrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Certificate_Authority/CN=stc2137_Intermediate_CA/ \
    -out $imreq

echo _________________________________________________________________________________________

imcert=$imdir/certs/intermediate.cert.pem
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

cachain=$imdir/certs/ca-chain.cert.pem
echo "create certificate chain file $cachain"
cat $imcert $rootcert > $cachain
chmod 444 $cachain

echo _________________________________________________________________________________________

serverrsa=$imdir/private/server.key.pem
echo "generate web server RSA key"
openssl genrsa -aes256 -out $serverrsa -passout pass:$rsapass 2048
chmod 400 $serverrsa

echo _________________________________________________________________________________________

serverreq=$imdir/csr/server.csr.pem
echo "create web server CSR with web server RSA key $serverreq"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $serverrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Web_Server/CN=stc2137.server.com/ \
    -out $serverreq

echo _________________________________________________________________________________________

servercert=$imdir/certs/server.cert.pem
echo "sign web server certificate with intermediate certificate"
openssl ca -batch -config $imcnf -extensions server_cert \
    -passin pass:$rsapass \
    -days 375 -notext -md sha256 \
    -in $serverreq \
    -out $servercert
chmod 444 $servercert

echo _________________________________________________________________________________________

echo "verify web server certificate"
openssl x509 -noout -text -in $servercert
openssl verify -CAfile $cachain $servercert

echo _________________________________________________________________________________________

echo "start web server"
openssl s_server -HTTP -Verify 3 -cert $servercert -CAfile $cachain -key $serverrsa -pass pass:$rsapass >server.out 2>&1 &

echo _________________________________________________________________________________________

clientrsa=$imdir/private/client.key.pem
echo "generate client RSA key"
openssl genrsa -aes256 -out $clientrsa -passout pass:$rsapass 2048
chmod 400 $clientrsa

echo _________________________________________________________________________________________

clientreq=$imdir/csr/client.csr.pem
echo "create client CSR with client RSA key $clientreq"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $clientrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Client/CN=stc2137_client/ \
    -out $clientreq

echo _________________________________________________________________________________________

clientcert=$imdir/certs/client.cert.pem
echo "sign client certificate with intermediate certificate"
openssl ca -batch -config $imcnf -extensions usr_cert \
    -passin pass:$rsapass \
    -days 375 -notext -md sha256 \
    -in $clientreq \
    -out $clientcert
chmod 444 $clientcert

echo _________________________________________________________________________________________

echo "verify client certificate"
openssl x509 -noout -text -in $clientcert
openssl verify -CAfile $cachain $clientcert

echo _________________________________________________________________________________________

mkfifo pipe1
mkfifo pipe2
gethello="
GET /hello.txt HTTP/1.1
"
getbye="
GET /bye.txt HTTP/1.1
"
echo "connect clients to web server and request hello.text and bye.text with $gethello and $getbye"
openssl s_client -ign_eof -servername stc2137.server.com -cert $clientcert -CAfile $cachain -key $clientrsa -pass pass:$rsapass <pipe1 &
echo $gethello >pipe1
sleep 1
openssl s_client -ign_eof -servername stc2137.server.com -cert $clientcert -CAfile $cachain -key $clientrsa -pass pass:$rsapass <pipe2 &
echo $getbye >pipe2
sleep 1

echo _________________________________________________________________________________________

echo "Web server output:"
cat server.out

echo _________________________________________________________________________________________

encrypterrsa=$imdir/private/encrypter.key.pem
echo "generate file encrypter RSA key"
openssl genrsa -aes256 -out $encrypterrsa -passout pass:$rsapass 2048
chmod 400 $encrypterrsa

echo _________________________________________________________________________________________

encrypterreq=$imdir/csr/encrypter.csr.pem
echo "create file encrypter CSR with client RSA key $encrypterreq"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $encrypterrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Encrypter/CN=stc2137_encrypter/ \
    -out $encrypterreq

echo _________________________________________________________________________________________

encryptercert=$imdir/certs/encrypter.cert.pem
echo "sign file encrypter certificate with intermediate certificate"
openssl ca -batch -config $imcnf -extensions encrypt_cert \
    -passin pass:$rsapass \
    -days 375 -notext -md sha256 \
    -in $encrypterreq \
    -out $encryptercert
chmod 444 $encryptercert

echo _________________________________________________________________________________________

echo "verify file encrypter certificate"
openssl x509 -noout -text -in $encryptercert
openssl verify -CAfile $cachain $encryptercert

echo _________________________________________________________________________________________

signerrsa=$imdir/private/signer.key.pem
echo "generate file signer RSA key"
openssl genrsa -aes256 -out $signerrsa -passout pass:$rsapass 2048
chmod 400 $signerrsa

echo _________________________________________________________________________________________

signerreq=$imdir/csr/signer.csr.pem
echo "create file signer CSR with client RSA key $signerreq"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $signerrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Signer/CN=stc2137_signer/ \
    -out $signerreq

echo _________________________________________________________________________________________

signercert=$imdir/certs/signer.cert.pem
echo "sign file signer certificate with intermediate certificate"
openssl ca -batch -config $imcnf -extensions signer_cert \
    -passin pass:$rsapass \
    -days 375 -notext -md sha256 \
    -in $signerreq \
    -out $signercert
chmod 444 $signercert

echo _________________________________________________________________________________________

echo "verify file signer certificate"
openssl x509 -noout -text -in $signercert
openssl verify -CAfile $cachain $signercert

echo _________________________________________________________________________________________

rm -f pipe*

./testserver.sh
kill %1

./testclient.sh
