#!/bin/bash

# run as sudo!
# the tests will handle switching to the correct mail users before running commands
# to ensure that permissions are being honored

tmp=../../../test/tmp/
mail=../mail/

A=addleness
B=muermo
C=forfend

keysuffix=.key.pem
certsuffix=.cert.pem

keyA=$tmp$A$keysuffix
keyB=$tmp$B$keysuffix
certA=$tmp$A$certsuffix
certB=$tmp$B$certsuffix
    
keypass=keypass
pass=pass

pwprompt="Enter password: "
newpwprompt="Enter new password: "
keypassprompt="Enter PEM pass phrase:"
certprompt="Enter certificate file path:"
msgoutprompt="Enter message output file path:"

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
    msg=msg1.txt
    msgout=msg1out.txt
    echo $msg1 > $tmp$msg

    echo "$A and $B generate private keys and certificates"
    -u $A ./genkey $keyA
    -u $A ./getcert $A $keyA
    expect $pwprompt
    send -- "$pass\r"
    expect $certprompt
    send -- "$certA\n"

    -u $B ./genkey $keyB
    -u $B ./getcert $B $keyB
    expect $pwprompt
    send -- "$pass\r"
    expect $certprompt
    send -- "$certB\n"

    echo "___________________________________________________________________________"

    echo "$A sends message to $B"
    -u $A ./sendmsg $certA $keyA $tmp$msg
    expect $keypassprompt
    send -- "$keypass\r"
    if [ ! test -f "$mail$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        return 1
    fi

    echo "___________________________________________________________________________"

    echo "$B receives message from $A"
    -u $B ./recvmsg $certB $keyB
    expect $keypassprompt
    send -- "$keypass\r"
    expect $msgoutprompt
    send -- "$tmp$msgout\n"
    if [ ! test -f "$tmp$msgout" ]; then
        echo "Error: received message not written to path"
        return 1
    fi
    if [ test -f "$mail$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        return 1
    fi
    if [ $(diff $tmp$msg $tmp$msgout) != "" ]; then
        echo "Error: received message does not match sent message"
        return 1
    fi

    rm -f $msg $msgout

    return 0
}

test2 () {
    echo "Test 2: changepw with no pending messages"
    msg=msg2.txt
    msgout=msg2out.txt
    echo $msg1 > $tmp$msg

    echo "$A generates new private key and changes password to get a new certificate"
    -u $A ./genkey new$keyA
    -u $A ./changepw $A new$keyA
    expect $pwprompt
    send -- "$pass\r"
    expect $newpwprompt
    send -- "new$pass\r"
    expect $certprompt
    send -- "new$certA\n"

    echo "___________________________________________________________________________"

    echo "$A tries to login with old pw; expect login failure"
    -u $A ./getcert $A $keyA
    expect $pwprompt
    send -- "$pass\r"

    echo "___________________________________________________________________________"

    echo "$A tries to login with new pw; expect success with certificate already exists message"
    -u $A ./getcert $A $keyA
    expect $pwprompt
    send -- "new$pass\r"

    echo "___________________________________________________________________________"

    echo "$A sends message to $B with old certificate and old key; expect message to be sent"
    -u $A ./sendmsg $certA $keyA $tmp$msg
    expect $keypassprompt
    send -- "$keypass\r"
    if [ ! test -f "$mail$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        return 1
    fi

    echo "___________________________________________________________________________"

    echo "$B tries to receive message from $A; expect client signature verification to fail"
    -u $B ./recvmsg $certB $keyB
    expect $keypassprompt
    send -- "$keypass\r"
    if [ test -f "$mail$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        return 1
    fi

    echo "___________________________________________________________________________"

    echo "$A sends message to $B with new certificate and new key; expect message to be sent"
    -u $A ./sendmsg new$certA new$keyA $tmp$msg
    expect $keypassprompt
    send -- "$keypass\r"
    if [ ! test -f "$mail$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        return 1
    fi

    echo "___________________________________________________________________________"

    echo "$B receives message from $A; expect success"
    -u $B ./recvmsg $certB $keyB
    expect $keypassprompt
    send -- "$keypass\r"
    expect $msgoutprompt
    send -- "$tmp$msgout\r"
    if [ ! test -f "$tmp$msgout" ]; then
        echo "Error: received message not written to path"
        return 1
    fi
    if [ test -f "$mail$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        return 1
    fi
    if [ $(diff $tmp$msg $tmp$msgout) != "" ]; then
        echo "Error: received message does not match sent message"
        return 1
    fi
    
    rm -f $msg $msgout

    return 0
}

test3 () {
    echo "Test 3: getcert idempotency"
    msg=msg3.txt
    msgout=msg3out.txt
    echo $msg1 > $tmp$msg

    echo "$A generates new private key"
    -u $A ./genkey newnew$keyA
    
    echo "___________________________________________________________________________"

    echo "$A getcert with new private key; expect login success with certificate already exists message"
    -u $A ./getcert $A newnew$keyA
    expect $pwprompt
    send -- "new$pass\r"
    expect $certprompt
    send -- "newnew$certA\r"
    if [ $(diff new$certA newnew$certA) != "" ]; then
        echo "Error: getcert generated a new certificate"
        return 1
    fi

    echo "___________________________________________________________________________"
    
    echo "check that $A's certificate has not changed in the CA"
    echo "$A sends message to $B"
    -u $A ./sendmsg new$certA new$keyA $tmp$msg
    expect $keypassprompt
    send -- "$keypass\r"
    if [ ! test -f "$mail$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        return 1
    fi
    
    echo "___________________________________________________________________________"

    echo "$B receives message from $A; expect success"
    -u $B ./recvmsg $certB $keyB
    expect $keypassprompt
    send -- "$keypass\r"
    expect $msgoutprompt
    send -- "$tmp$msgout\r"
    if [ ! test -f "$tmp$msgout" ]; then
        echo "Error: received message not written to path"
        return 1
    fi
    if [ test -f "$mail$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        return 1
    fi
    if [ $(diff $tmp$msg $tmp$msgout) != "" ]; then
        echo "Error: received message does not match sent message"
        return 1
    fi
    
    rm -f $msg $msgout

    return 0
}

test4 () {
    echo "Test 4: changepw with pending message"
    msg=msg4.txt
    msgout=msg4out.txt
    echo $msg1 > $tmp$msg

    echo "$A sends message to $B"
    -u $A ./sendmsg new$certA new$keyA $tmp$msg
    expect $keypassprompt
    send -- "$keypass\r"
    if [ ! test -f "$mail$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        return 1
    fi

    echo "$B tries to change password; expect pending messages failure"
    -u $B ./changepw $B $keyB
    expect $pwprompt
    send -- "$pass\r"
    expect $newpwprompt
    send -- "new$pass\r"

    rm -f $msg $msgout
    
    return 0;
}

test5 () {
    echo "Test 5: unsend feature"
    
    # revert pw to original and overwrite original key and cert 
    echo "$A generates new private key and changes password to get a new certificate"
    -u $A ./genkey $keyA
    -u $A ./changepw $A $keyA
    expect $pwprompt
    send -- "new$pass\r"
    expect $newpwprompt
    send -- "$pass\r"
    expect $certprompt
    send -- "$certA\n"

    echo "___________________________________________________________________________"

    echo "$B tries to receive message from $A; expect client signature verification to fail"
    -u $B ./recvmsg $certB $keyB
    expect $keypassprompt
    send -- "$keypass\r"
    if [ test -f "$mail$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        return 1
    fi
        
    rm -f $msg $msgout

    return 0
}

badmsg1="MAILFROM: <$A>
MAILTO: <bad$B> <$B>
Hello $B!
Love,
$A
"

test6 () {
    echo "Test 6: sendmsg to invalid recipient"
    msg=msg6.txt
    msgout=msg6out.txt
    echo $badmsg1 > $tmp$msg

    echo "$A sends message to invalid recipient and $B; expect one invalid recipient error and one success"
    -u $A ./sendmsg $certA $keyA $tmp$msg
    expect $keypassprompt
    send -- "$keypass\r"
    if [ ! test -f "$mail$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        return 1
    fi

    rm -f $msg $msgout

    return 0
}

badmsg2="MAILFROM: <$A>
MAILTO: <$C>
Hello $C!
Love,
$A
"

test7 () {
    echo "Test 7: sendmsg to user who has not getcert'd yet"
    msg=msg7.txt
    msgout=msg7out.txt
    echo $badmsg2 > $tmp$msg

    echo "$A sends message to uncertified recipient; expect certificate read error"
    -u $A ./sendmsg $certA $keyA $tmp$msg
    expect $keypassprompt
    send -- "$keypass\r"
    if [ test -f "$mail$C/00001" ]; then
        echo "Error: message written to uncertified $C's mailbox"
        return 1
    fi

    rm -f $msg $msgout

    return 0
}

test1
echo "___________________________________________________________________________"
echo "___________________________________________________________________________"
test2
echo "___________________________________________________________________________"
echo "___________________________________________________________________________"
test3
echo "___________________________________________________________________________"
echo "___________________________________________________________________________"
test4
echo "___________________________________________________________________________"
echo "___________________________________________________________________________"
test5
echo "___________________________________________________________________________"
echo "___________________________________________________________________________"
test6
echo "___________________________________________________________________________"
echo "___________________________________________________________________________"
test7