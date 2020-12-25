#!/bin/bash

# run as sudo!
# the tests will handle switching to the correct mail users before running commands
# to ensure that permissions are being honored

tmp=../../../test/tmp/
mail=../mail/

A=$addleness
B=$muermo

keysuffix=.key.pem
certsuffix=.cert.pem

pass=pass

cd ..
sudo rm -rf $1 && make clean && make install TREE=$1
msg1="MAILFROM: <$A>
MAILTO: <$B>
Hello $B!
Love,
$A
"
cd $1/client/bin

test1 () {
    echo "Test 1: basic end to end without changepw"
    keyA=$tmp$A$keysuffix
    keyB=$tmp$B$keysuffix
    certA=$tmp$A$certsuffix
    certB=$tmp$B$certsuffix
    msg=msg1.txt
    msgout=msg1out.txt
    echo $msg1 > $tmp$msg

    echo "$A and $B generate private keys and certificates"
    -u $A ./genkey $keyA
    -u $A ./getcert $A $keyA
    expect "Enter password: "
    send -- "$pass\r"
    expect "Enter certificate file path:"
    send -- "$certA\n"

    -u $B ./genkey $keyB
    -u $B ./getcert $B $keyB
    expect "Enter password: "
    send -- "$pass\r"
    expect "Enter certificate file path:"
    send -- "$certB\n"

    echo "$A sends message to $B"
    -u $A ./sendmsg $certA $keyA $tmp$msg
    expect "Enter PEM pass phrase:"
    send -- "$pass\r"
    if [ ! test -f "$mail$A/00001" ]; then
        echo "Error: message not written to $A's mailbox"
        return 1
    fi

    echo "$B receives message from $A"
    -u $B ./recvmsg $certB $keyB
    expect "Enter PEM pass phrase:"
    send -- "$pass\r"
    expect "Enter message output file path:"
    send -- "$tmp$msgout\n"
    if [ test -f "$mail$A/00001" ]; then
        echo "Error: message not deleted from $A's mailbox"
        return 1
    fi

    if [ $(diff $tmp$msg $tmp$msgout) != "" ]; then
        echo "Error: received message does not match sent message!"
        return 1
    fi

    return 0
}

test2 () {
    echo "Test 2: changepw with no pending messages"
    echo "$A generates new private key and changes password to get a new certificate"
    -u $A ./genkey $keyA
    -u $A ./changepw $A $keyA
    expect "Enter password: "
    send -- "$pass\r"
    expect "Enter new password: "
    send -- "new$pass\r"
    expect "Enter certificate file path:"
    send -- "$certA\n"

    echo "$A tries to login with old pw; expect login failure"
    -u $A ./getcert $A $keyA
    expect "Enter password: "
    send -- "$pass\r"

    echo "$A tries to login with new pw; expect success with certificate already exists message"
    -u $A ./getcert $A $keyA
    expect "Enter password: "
    send -- "new$pass\r"

    echo ""
}

test1
echo "___________________________________________________________________________"
