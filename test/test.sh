#!/bin/bash

# run as sudo!
# the tests will handle switching to the correct mail users before running commands
# to ensure that permissions are being honored

tmp=../../../test/tmp
mail=../mail

A=addleness
B=muermo
C=forfend

keysuffix=.key.pem
certsuffix=.cert.pem

keyA=$tmp/$A$keysuffix
keyB=$tmp/$B$keysuffix
keyC=$tmp/$C$keysuffix
certA=$tmp/$A$certsuffix
certB=$tmp/$B$certsuffix
certC=$tmp/$C$certsuffix

keypass=pass
passA=pass
passB=pass
passC=pass

pwprompt="Enter password: "
newpwprompt="Enter new password: "
keypassprompt="Enter PEM pass phrase:"
certprompt="Enter certificate file path:"
msgoutprompt="Enter message output file path:"

cd ../$1/client/bin

rm -f $tmp/msg*.txt
rm -f $tmp/$A* $tmp/$B* $tmp/$C*

# Functionality tests

msg1="MAIL FROM:<$A>\n
MAIL TO:<$B>\n
Hello $B!\n
Love,\n
$A
"

testfunctionality1 () {
    echo "Test Functionality 1: basic end to end without changepw"
    msg=msg1.txt
    msgout=msg1out.txt
    echo $msg1 > $tmp/$msg

    echo "$A and $B generate private keys and certificates"
    ./genkey.sh $keyA $keypass
    echo "pw=$pass"
    echo "cert=$certA"
    ./getcert $A $keyA
    # expect $pwprompt
    # send -- "$pass\r"
    # expect $certprompt
    # send -- "$certA\n"

    ./genkey.sh $keyB $keypass
    ./getcert $B $keyB
    # expect $pwprompt
    # send -- "$pass\r"
    # expect $certprompt
    # send -- "$certB\n"

    echo "___________________________________________________________________________"

    echo "$A sends message to $B"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$B receives message from $A"
    ./recvmsg $certB $keyB
    # expect $keypassprompt
    # send -- "$keypass\r"
    # expect $msgoutprompt
    # send -- "$tmp/$msgout\n"
    if [ ! -f "$tmp/$msgout" ]; then
        echo "Error: received message not written to path"
        rm -f $msg $msgout; return 1
    fi
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
    if [ $(diff $tmp/$msg $tmp/$msgout) != "" ]; then
        echo "Error: received message does not match sent message"
        rm -f $msg $msgout; return 1
    fi

    rm -f $msg $msgout

    return 0
}

testfunctionality2 () {
    echo "Test Functionality 2: changepw with no pending messages"
    msg=msg2.txt
    msgout=msg2out.txt
    echo $msg1 > $tmp/$msg

    echo "$A generates new private key and changes password to get a new certificate"
    ./genkey.sh new$keyA $keypass
    ./changepw $A new$keyA
    # expect $pwprompt
    # send -- "$pass\r"
    # expect $newpwprompt
    # send -- "new$pass\r"
    # expect $certprompt
    # send -- "new$certA\n"

    echo "___________________________________________________________________________"

    echo "$A tries to login with old pw; # expect login failure"
    ./getcert $A $keyA
    # expect $pwprompt
    # send -- "$pass\r"

    echo "___________________________________________________________________________"

    echo "$A tries to login with new pw; # expect success with certificate already exists message"
    ./getcert $A $keyA
    # expect $pwprompt
    # send -- "new$pass\r"

    echo "___________________________________________________________________________"

    echo "$A sends message to $B with old certificate and old key; # expect message to be sent"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$B tries to receive message from $A; # expect client signature verification to fail"
    ./recvmsg $certB $keyB
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msg $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$A sends message to $B with new certificate and new key; # expect message to be sent"
    ./sendmsg new$certA new$keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$B receives message from $A; # expect success"
    ./recvmsg $certB $keyB
    # expect $keypassprompt
    # send -- "$keypass\r"
    # expect $msgoutprompt
    # send -- "$tmp/$msgout\r"
    if [ ! -f "$tmp/$msgout" ]; then
        echo "Error: received message not written to path"
        rm -f $msg $msgout; return 1
    fi
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
    if [ $(diff $tmp/$msg $tmp/$msgout) != "" ]; then
        echo "Error: received message does not match sent message"
        rm -f $msg $msgout; return 1
    fi
    
    rm -f $msg $msgout

    return 0
}

testfunctionality3 () {
    echo "Test Functionality 3: getcert idempotency"
    msg=msg3.txt
    msgout=msg3out.txt
    echo $msg1 > $tmp/$msg

    echo "$A generates new private key"
    ./genkey.sh newnew$keyA $keypass
    
    echo "___________________________________________________________________________"

    echo "$A getcert with new private key; # expect login success with certificate already exists message"
    ./getcert $A newnew$keyA
    # expect $pwprompt
    # send -- "new$pass\r"
    # expect $certprompt
    # send -- "newnew$certA\r"
    if [ $(diff new$certA newnew$certA) != "" ]; then
        echo "Error: getcert generated a new certificate"
        rm -f $msg $msgout; return 1
    fi

    echo "___________________________________________________________________________"
    
    echo "check that $A's certificate has not changed in the CA"
    echo "$A sends message to $B"
    ./sendmsg new$certA new$keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
    
    echo "___________________________________________________________________________"

    echo "$B receives message from $A; # expect success"
    ./recvmsg $certB $keyB
    # expect $keypassprompt
    # send -- "$keypass\r"
    # expect $msgoutprompt
    # send -- "$tmp/$msgout\r"
    if [ ! -f "$tmp/$msgout" ]; then
        echo "Error: received message not written to path"
        rm -f $msg $msgout; return 1
    fi
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
    if [ $(diff $tmp/$msg $tmp/$msgout) != "" ]; then
        echo "Error: received message does not match sent message"
        rm -f $msg $msgout; return 1
    fi
    
    rm -f $msg $msgout

    return 0
}

testfunctionality4 () {
    echo "Test Functionality 4: changepw with pending message"
    msg=msg4.txt
    msgout=msg4out.txt
    echo $msg1 > $tmp/$msg

    echo "$A sends message to $B"
    ./sendmsg new$certA new$keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi

    echo "$B tries to change password; # expect pending messages failure"
    ./changepw $B $keyB
    # expect $pwprompt
    # send -- "$pass\r"
    # expect $newpwprompt
    # send -- "new$pass\r"

    rm -f $msg $msgout
    
    return 0;
}

testfunctionality5 () {
    echo "Test Functionality 5: unsend feature"
    
    # revert pw to original and overwrite original key and cert 
    echo "$A generates new private key and changes password to get a new certificate"
    ./genkey.sh $keyA $keypass
    ./changepw $A $keyA
    # expect $pwprompt
    # send -- "new$pass\r"
    # expect $newpwprompt
    # send -- "$pass\r"
    # expect $certprompt
    # send -- "$certA\n"

    echo "___________________________________________________________________________"

    echo "$B tries to receive message from $A; # expect client signature verification to fail"
    ./recvmsg $certB $keyB
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
        
    rm -f $msg $msgout

    return 0
}

badmsg1="MAIL FROM:<$A>\n
MAIL TO:<bad$B>\n
MAIL TO:<$B>\n
Hello $B!\n
Love,\n
$A\n
"

testfunctionality6 () {
    echo "Test Functionality 6: sendmsg to invalid recipient"
    msg=msg6.txt
    msgout=msg6out.txt
    echo $badmsg1 > $tmp/$msg

    echo "$A sends message to invalid recipient and $B; # expect one invalid recipient error and one success"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi

    rm -f $msg $msgout

    return 0
}

badmsg2="MAIL FROM:<$A>\n
MAIL TO:<$C>\n
Hello $C!\n
Love,\n
$A
"

testfunctionality7 () {
    echo "Test Functionality 7: sendmsg to user who has not getcert'd yet"
    msg=msg7.txt
    msgout=msg7out.txt
    echo $badmsg2 > $tmp/$msg

    echo "$A sends message to uncertified recipient; # expect certificate read error"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$C/00001" ]; then
        echo "Error: message written to uncertified $C's mailbox"
        rm -f $msg $msgout; return 1
    fi

    rm -f $msg $msgout

    return 0
}


testfunctionality () {
    testfunctionality1
    if [ $? -ne 0 ]; then
        echo "Test Functionality 1 FAILED"
        return 
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testfunctionality2
    if [ $? -ne 0 ]; then
        echo "Test Functionality 2 FAILED"
        return 
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testfunctionality3
    if [ $? -ne 0 ]; then
        echo "Test Functionality 3 FAILED"
        return 
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testfunctionality4
    if [ $? -ne 0 ]; then
        echo "Test Functionality 4 FAILED"
        return 
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testfunctionality5
    if [ $? -ne 0 ]; then
        echo "Test Functionality 5 FAILED"
        return 
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testfunctionality6
    if [ $? -ne 0 ]; then
        echo "Test Functionality 6 FAILED"
        return 
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testfunctionality7
    if [ $? -ne 0 ]; then
        echo "Test Functionality 7 FAILED"
        return 
    fi
    
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    
    echo "ALL FUNCTIONALITY TESTS PASSED"
    
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"

    return 0
}

# User Impersonation tests

badmsg3="MAIL FROM:<$B>\n
MAIL TO:<$C>\n
Hello $C!\n
Love,\n
$A
"

testimpersonation () {
    echo "Test Security 1: sendmsg sender impersonation"
    msg=msg8.txt
    msgout=msg8out.txt
    echo $badmsg3 > $tmp/$msg

    echo "$C generates a private key and gets a certificate"
    ./genkey.sh $keyC $keypass
    ./getcert $C $keyC
    # expect $pwprompt
    # send -- "$pass\r"
    # expect $certprompt
    # send -- "$certC\n"

    echo "___________________________________________________________________________"

    echo "$A tries to send message to $C by impersonating $B"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$C/00001" ]; then
        echo "Error: message not written to $C's mailbox"
        rm -f $msg $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$C tries to receive message sent by $A posing as $B; # expect client signature verification to fail"
    ./recvmsg $certC $keyC
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$C/00001" ]; then
        echo "Error: message not deleted from $C's mailbox"
        rm -f $msg $msgout; return 1
    fi
        
    rm -f $msg $msgout

    return 0
}

# TLS tests

# badcert and badkey pair were generated from another CA
badcert=$tmp/bad.$A$certsuffix
badkey=$tmp/bad.$A$keysuffix

# mismatchkey does not correspond to badcert
mismatchkey=$tmp/mismatch.$A$keysuffix

# malformed certificate
invalidcert=$tmp/invalid.$A$certsuffix

# malformed private key
invalidkey=$tmp/invalid.$A$keysuffix

testTLS1 () {
    echo "Test certificate/key mismatch"
    msg=msg9.txt
    msgout=msg9out.txt
    echo $msg1 > $tmp/$msg
    echo "$A tries to send message with mismatched certificate/key pair; # expect client certificate verification to fail"
    ./sendmsg $badcert $mismatchkey $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
    
    rm -f $msg $msgout

    return 0
}

testTLS2 () {
    echo "Test certificate signed by the wrong CA"
    msg=msg10.txt
    msgout=msg10out.txt
    echo $msg1 > $tmp/$msg
    echo "$A tries to send message with certificate signed by another CA; # expect client certificate verification to fail"
    ./sendmsg $badcert $badkey $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
    
    rm -f $msg $msgout

    return 0
}

testTLS3 () {
    echo "Test invalid certificate"
    msg=msg11.txt
    msgout=msg11out.txt
    echo $msg1 > $tmp/$msg
    echo "$A tries to send message with invalid certificate; # expect client certificate verification to fail"
    ./sendmsg $invalidcert $badkey $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
    
    rm -f $msg $msgout

    return 0
}

testTLS4 () {
    echo "Test invalid key"
    msg=msg12.txt
    msgout=msg12out.txt
    echo $msg1 > $tmp/$msg
    echo "$A tries to send message with invalid key; # expect client certificate verification to fail"
    ./sendmsg $badcert $invalidkey $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
    
    rm -f $msg $msgout

    return 0
}

# Volume/DOS tests

testlargemsg () {
    echo "Test send large (>1MB) message"
    msg=msg13.txt
    msgout=msg13out.txt

    echo "write large message"
    echo "MAIL FROM:<$A>\n" >> $tmp/$msg
    echo "MAIL TO:<$B>\n" >> $tmp/$msg
    for i in 1..1000000; do
        echo "." >> $tmp/$msg
    done

    echo "___________________________________________________________________________"

    echo "$A tries to send large message to $B; # expect message too large error"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi

    rm -f $msg $msgout

    return 0
}

smolmsg="MAIL FROM:<$A>\n
MAIL TO:<$B>\n
"

testspamsendmsg () {
    echo "Test spam sendmsg to fill up mailbox"
    msg=msg14.txt
    msgout=msg14out.txt
    echo $smolmsg > $tmp/$msg

    echo "Fill up $B's mailbox with 99999 messages"
    for i in 1..99999; do
        ./sendmsg $certA $keyA $tmp/$msg
        # expect $keypassprompt
        # send -- "$keypass\r"
    done
    if [ ! -f "$mail/$B/99999" ]; then
        echo "Error: messages not written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi
    
    echo "___________________________________________________________________________"

    echo "Try to send 100000th message to $B"    
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00000" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msg $msgout; return 1
    fi

    rm -f $msg $msgout

    return 0
}

testspamchangepw () {
    return 0
}

testsecurity () {
    testimpersonation
    if [ $? -ne 0 ]; then
        echo "Test Impersonation FAILED"
        rm -f $msg $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testTLS1
    if [ $? -ne 0 ]; then
        echo "Test TLS 1 FAILED"
        rm -f $msg $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testTLS2
    if [ $? -ne 0 ]; then
        echo "Test TLS 2 FAILED"
        rm -f $msg $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testTLS3
    if [ $? -ne 0 ]; then
        echo "Test TLS 3 FAILED"
        rm -f $msg $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testTLS4
    if [ $? -ne 0 ]; then
        echo "Test TLS 4 FAILED"
        rm -f $msg $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testlargemsg
    if [ $? -ne 0 ]; then
        echo "Test Large Message FAILED"
        rm -f $msg $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testspamsendmsg
    if [ $? -ne 0 ]; then
        echo "Test Spam sendmsg FAILED"
        rm -f $msg $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testspamchangepw
    if [ $? -ne 0 ]; then
        echo "Test Spam changepw FAILED"
        rm -f $msg $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    
    echo "ALL SECURITY TESTS PASSED"
    
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    
    return 0
}

testfunctionality
testsecurity

rm -f $tmp/msg*.txt
rm -f $tmp/$A* $tmp/$B* $tmp/$C*
