#!/bin/bash

dir=./ca
imdir=$dir/intermediate
testdir=$dir/test
imcnf=imopenssl.cnf
clientrsa=$imdir/private/client.key.pem
rsapass=rsapassword
cachain=$imdir/certs/ca-chain.cert.pem

clientreq=$testdir/csr/client.csr.pem
clientcert=$testdir/certs/client.cert.pem

server=stc2137.server.com

getreq="
GET /hello.txt HTTP/1.1
"

serverrsa=$imdir/private/server.key.pem
serverreq=$testdir/csr/server.csr.pem
servercert=$testdir/certs/server.cert.pem

mkfifo testpipe

openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $clientrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Client/CN=stc2137_test/ \
    -out $clientreq

openssl ca -batch -config $imcnf -extensions usr_cert \
    -passin pass:$rsapass \
    -days 1 -notext -md sha256 \
    -in $clientreq \
    -out $clientcert.
chmod 444 $clientcert.


echo _________________________________________________________________________________________
echo _________________________________________________________________________________________

echo "BEGIN CLIENT TESTS"

echo _________________________________________________________________________________________

echo "TEST 8"
echo "generate expired server certificate"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $serverrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Web_Server/CN=$server.test1/ \
    -out $serverreq

openssl ca -batch -config $imcnf -extensions server_cert \
    -passin pass:$rsapass \
    -startdate 20191018000000Z -enddate 20191018000001Z -notext -md sha256 \
    -in $serverreq \
    -out $servercert.1
chmod 444 $servercert.1

echo "start web server"
openssl s_server -accept 4434 -HTTP -Verify 3 -cert $servercert.1 -CAfile $cachain -key $serverrsa -pass pass:$rsapass >server.out.test1 2>&1 &

sleep 2

echo "attempt to connect client to server (should fail with expired certificate error)"
openssl s_client -connect localhost:4434 -quiet -servername $server.test1 -cert $clientcert. -CAfile $cachain -key $clientrsa -pass pass:$rsapass <testpipe &
echo $getreq >testpipe
sleep 1

kill %1
rm -f testpipe
