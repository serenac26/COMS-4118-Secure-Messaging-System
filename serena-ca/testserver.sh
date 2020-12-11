#!/bin/bash

dir=./ca
imdir=$dir/intermediate
testdir=$dir/test
mkdir $testdir
mkdir $testdir/csr $testdir/certs
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

mkfifo testpipe

echo _________________________________________________________________________________________
echo _________________________________________________________________________________________

echo "BEGIN SERVER TESTS"
echo _________________________________________________________________________________________

echo "TEST 1"
echo "generate an expired client certificate"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $clientrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Client/CN=stc2137_test_1/ \
    -out $clientreq

openssl ca -batch -config $imcnf -extensions usr_cert \
    -passin pass:$rsapass \
    -startdate 20191018000000Z -enddate 20191018000001Z -notext -md sha256 \
    -in $clientreq \
    -out $clientcert.1
chmod 444 $clientcert.1

echo "attempt to connect client to server and request a file (should fail with expired certificate error)"
openssl s_client -quiet -servername $server -cert $clientcert.1 -CAfile $cachain -key $clientrsa -pass pass:$rsapass <testpipe &
echo $getreq >testpipe
sleep 1
echo ""
echo "Error code from server output:"
tail server.out | grep error 

echo _________________________________________________________________________________________

echo "TEST 2"
echo "generate a not yet valid client certificate"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $clientrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Client/CN=stc2137_test_2/ \
    -out $clientreq

openssl ca -batch -config $imcnf -extensions usr_cert \
    -passin pass:$rsapass \
    -startdate 20201118000000Z -enddate 20201118000001Z -notext -md sha256 \
    -in $clientreq \
    -out $clientcert.2
chmod 444 $clientcert.2

echo "attempt to connect client to server and request a file (should fail with not yet valid certificate error)"
openssl s_client -quiet -servername $server -cert $clientcert.2 -CAfile $cachain -key $clientrsa -pass pass:$rsapass <testpipe &
echo $getreq >testpipe
sleep 1
echo ""
echo "Error code from server output:"
tail server.out | grep error

echo _________________________________________________________________________________________

echo "TEST 3"
echo "generate a self signed client certificate"
openssl req -config $imcnf -new -sha256 -x509 \
    -passin pass:$rsapass \
    -key $clientrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Client/CN=stc2137_test_3/ \
    -out $clientcert.3

echo "attempt to connect client to server and request a file (should fail with self signed certificate error)"
openssl s_client -quiet -servername $server -cert $clientcert.3 -CAfile $cachain -key $clientrsa -pass pass:$rsapass <testpipe &
echo $getreq >testpipe
sleep 1
echo ""
echo "Error code from server output:"
tail server.out | grep error

echo _________________________________________________________________________________________

echo "TEST 4"
echo "generate a client certificate with incorrect purpose"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $clientrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Client/CN=stc2137_test_4/ \
    -out $clientreq

openssl ca -batch -config $imcnf -extensions server_cert \
    -passin pass:$rsapass \
    -days 1 -notext -md sha256 \
    -in $clientreq \
    -out $clientcert.4
chmod 444 $clientcert.4

echo "attempt to connect client to server and request a file (should fail with unsupported certificate purpose error)"
openssl s_client -quiet -servername $server -cert $clientcert.4 -CAfile $cachain -key $clientrsa -pass pass:$rsapass <testpipe &
echo $getreq >testpipe
sleep 1
echo ""
echo "Error code from server output:"
tail server.out | grep error

echo _________________________________________________________________________________________

echo "TEST 5"
echo "generate a client certificate from an untrusted intermediate certificate"
rootcnf=rootopenssl.cnf
testimcnf=testimopenssl.cnf
imrsa=$imdir/private/intermediate.key.pem
imreq=$imdir/csr/intermediate.csr.pem.test
imcert=$imdir/certs/intermediate.cert.pem.test
openssl req -config $testimcnf.1 -new -sha256 \
    -passin pass:$rsapass \
    -key $imrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Certificate_Authority/CN=stc2137_Intermediate_CA_test1/ \
    -out $imreq

openssl ca -batch -config $rootcnf -extensions v3_intermediate_ca \
    -passin pass:$rsapass \
    -days 3650 -notext -md sha256 \
    -in $imreq \
    -out $imcert.1

rootcert=$dir/certs/ca.cert.pem
testcachain=$imdir/certs/ca-chain.cert.pem.test
cat $imcert.1 $rootcert > $testcachain.1
chmod 444 $testcachain.1

openssl req -config $testimcnf.1 -new -sha256 \
    -passin pass:$rsapass \
    -key $clientrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Client/CN=stc2137_test_5/ \
    -out $clientreq

openssl ca -batch -config $testimcnf.1 -extensions usr_cert \
    -passin pass:$rsapass \
    -days 1 -notext -md sha256 \
    -in $clientreq \
    -out $clientcert.5
chmod 444 $clientcert.5

echo "attempt to connect client to server and request a file (should fail with local issuer and first certificate errors)"
openssl s_client -quiet -servername $server -cert $clientcert.5 -CAfile $cachain -key $clientrsa -pass pass:$rsapass <testpipe &
echo $getreq >testpipe
sleep 1
echo ""
echo "Error code from server output:"
tail -n 7 server.out | grep error

echo _________________________________________________________________________________________

echo "TEST 6"
echo "generate a client certificate from an untrusted root and intermediate certificate"
rootrsa=$dir/private/ca.key.pem
testrootcnf=testrootopenssl.cnf
testrootcert=$dir/certs/ca.cert.pem.test

openssl req -config $testrootcnf \
    -passin pass:$rsapass \
    -key $rootrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Certificate_Authority/CN=stc2137_Root_CA_test/ \
    -new -x509 -days 7300 -sha256 -extensions v3_ca \
    -out $testrootcert
chmod 444 $testrootcert

openssl req -config $testimcnf.2 -new -sha256 \
    -passin pass:$rsapass \
    -key $imrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Certificate_Authority/CN=stc2137_Intermediate_CA_test2/ \
    -out $imreq

openssl ca -batch -config $testrootcnf -extensions v3_intermediate_ca \
    -passin pass:$rsapass \
    -days 3650 -notext -md sha256 \
    -in $imreq \
    -out $imcert.2

cat $imcert.2 $testrootcert > $testcachain.2
chmod 444 $testcachain.2

openssl req -config $testimcnf.2 -new -sha256 \
    -passin pass:$rsapass \
    -key $clientrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Client/CN=stc2137_test_6/ \
    -out $clientreq

openssl ca -batch -config $testimcnf.2 -extensions usr_cert \
    -passin pass:$rsapass \
    -days 1 -notext -md sha256 \
    -in $clientreq \
    -out $clientcert.6
chmod 444 $clientcert.6

echo "attempt to connect client to server and request a file (should fail with local issuer and first certificate errors)"
openssl s_client -quiet -servername $server -cert $clientcert.6 -CAfile $cachain -key $clientrsa -pass pass:$rsapass <testpipe &
echo $getreq >testpipe
sleep 1
echo ""
echo "Error code from server output:"
tail -n 7 server.out | grep error

echo _________________________________________________________________________________________

echo "TEST 7"
echo "generate a corrupted client certificate"
openssl req -config $imcnf -new -sha256 \
    -passin pass:$rsapass \
    -key $clientrsa \
    -subj /C=US/ST=Texas/O=stc2137/OU=stc2137_Client/CN=stc2137_test_7/ \
    -out $clientreq

openssl ca -batch -config $imcnf -extensions usr_cert \
    -passin pass:$rsapass \
    -days 1 -notext -md sha256 \
    -in $clientreq \
    -out $clientcert.7
# change a byte in the certificate
printf 'a' | dd of=$clientcert.7 bs=1 seek=512 count=1 conv=notrunc
chmod 444 $clientcert.7

echo "attempt to connect client to server and request a file (should fail with key mismatch error)"
openssl s_client -quiet -servername $server -cert $clientcert.7 -CAfile $cachain -key $clientrsa -pass pass:$rsapass <testpipe &
echo $getreq >testpipe
sleep 1


rm -f testpipe
