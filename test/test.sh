#!/bin/bash

# run as sudo!
# the tests will handle switching to the correct mail users before running commands
# to ensure that permissions are being honored

# /usr/bin/expect -c "
#         spawn ./sendmsg $certA $keyA $tmp/$msg
#         expect \"Enter PEM pass phrase:\";
#         send \"pass\n\";
#         expect eof;
#         "

tmp=../../../test/tmp
mail=../../server/mail

A=addleness
Ap="$(sudo grep 'addleness' ../$1/creds.txt | cut -d' ' -f3)"
B=muermo
Bp="$(sudo grep 'muermo' ../$1/creds.txt | cut -d' ' -f3)"
C=forfend
Cp="$(sudo grep 'forfend' ../$1/creds.txt | cut -d' ' -f3)"

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

pwprompt="Enter password:"
newpwprompt="Enter new password:"
keypassprompt="Enter PEM pass phrase:"
passphraseprompt="Enter pass phrase for"
certprompt="Enter certificate file path:"
msgoutprompt="Enter message output file path:"

cd ../$1/client/bin

rm -f $tmp/$A* $tmp/$B* $tmp/$C*

# Functionality tests

testfunctionality1 () {
    echo "Test Functionality 1: basic end to end without changepw"
    msg=msg1.txt
    msgout=msg1out.txt

    echo "$A and $B generate private keys and certificates"
    ./genkey.sh $keyA $keypass
    echo "use login password from $tmp/creds.txt"
    echo "use key password: pass"
    ./getcert $A $keyA $certA
    # expect $pwprompt
    # send -- "$pass\r"

    ./genkey.sh $keyB $keypass
    ./getcert $B $keyB $certB
    echo "use login password from $tmp/creds.txt"
    echo "use key password: pass"
    # expect $pwprompt
    # send -- "$pass\r"

    echo "___________________________________________________________________________"

    echo "$A sends message to $B"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$B receives message from $A"
    echo "use key password: pass"
    ./recvmsg $certB $keyB $tmp/$msgout
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$tmp/$msgout" ]; then
        echo "Error: received message not written to path"
        rm -f $msgout; return 1
    fi
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msgout; return 1
    fi
    diff=$(diff --strip-trailing-cr $tmp/$msg $tmp/$msgout)
    if [ "$diff" != "" ]; then
        echo "Error: received message does not match sent message"
        rm -f $msgout; return 1
    fi

    rm -f $msgout

    return 0
}

testfunctionality2 () {
    echo "Test Functionality 2: changepw with no pending messages"
    msg=msg2.txt
    msgout=msg2out.txt

    echo "$A generates new private key and changes password to get a new certificate"
    ./genkey.sh $keyA.new $keypass
    echo "use login password from $tmp/creds.txt"
    echo "use new login password: newpass"
    echo "use key password: pass"
    ./changepw $A $keyA.new $certA.new
    # expect $pwprompt
    # send -- "$pass\r"
    # expect $newpwprompt
    # send -- "new$pass\r"

    echo "___________________________________________________________________________"

    echo "$A tries to login with old pw; # expect login failure"
    echo "try old login password from $tmp/creds.txt"
    echo "use key password: pass"
    ./getcert $A $keyA $tmp/blah
    # expect $pwprompt
    # send -- "$pass\r"

    echo "___________________________________________________________________________"

    echo "$A tries to login with new pw; # expect success with certificate already exists message"
    echo "use new login password: newpass"
    echo "use key password: pass"    
    ./getcert $A $keyA $tmp/blah
    # expect $pwprompt
    # send -- "new$pass\r"

    echo "___________________________________________________________________________"

    echo "$A sends message to $B with old certificate and old key; # expect message to be sent"
    echo "use key password: pass"    
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$B tries to receive message from $A; # expect client signature verification to fail"
    echo "use key password: pass"
    ./recvmsg $certB $keyB $tmp/blah
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$A sends message to $B with new certificate and new key; # expect message to be sent"
    echo "use key password: pass"
    ./sendmsg $certA.new $keyA.new $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$B receives message from $A; # expect success"
    echo "use key password: pass"
    ./recvmsg $certB $keyB $tmp/$msgout
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$tmp/$msgout" ]; then
        echo "Error: received message not written to path"
        rm -f $msgout; return 1
    fi
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msgout; return 1
    fi
    diff=$(diff --strip-trailing-cr $tmp/$msg $tmp/$msgout)
    if [ "$diff" != "" ]; then
        echo "Error: received message does not match sent message"
        rm -f $msgout; return 1
    fi
    
    rm -f $msgout

    return 0
}

testfunctionality3 () {
    echo "Test Functionality 3: getcert idempotency"
    msg=msg3.txt
    msgout=msg3out.txt

    echo "$A generates new private key"
    ./genkey.sh $keyA.newnew $keypass
    
    echo "___________________________________________________________________________"

    echo "$A getcert with new private key; # expect login success with certificate already exists message"
    echo "use login password: newpass"
    echo "use key password: pass"
    ./getcert $A $keyA.newnew $certA.newnew
    # expect $pwprompt
    # send -- "new$pass\r"
    diff=$(diff --strip-trailing-cr $certA.new $certA.newnew)
    if [ "$diff" != "" ]; then
        echo "Error: getcert generated a new certificate"
        rm -f $msgout; return 1
    fi

    echo "___________________________________________________________________________"
    
    echo "check that $A's certificate has not changed in the CA"
    echo "$A sends message to $B"
    echo "use key password: pass"
    ./sendmsg $certA.new $keyA.new $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msgout; return 1
    fi
    
    echo "___________________________________________________________________________"

    echo "$B receives message from $A; # expect success"
    echo "use key password: pass"
    ./recvmsg $certB $keyB $tmp/$msgout
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$tmp/$msgout" ]; then
        echo "Error: received message not written to path"
        rm -f $msgout; return 1
    fi
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msgout; return 1
    fi
    diff=$(diff --strip-trailing-cr $tmp/$msg $tmp/$msgout)
    if [ "$diff" != "" ]; then
        echo "Error: received message does not match sent message"
        rm -f $msgout; return 1
    fi
    
    rm -f $msgout

    return 0
}

testfunctionality4 () {
    echo "Test Functionality 4: changepw with pending message"
    msg=msg4.txt
    msgout=msg4out.txt

    echo "$A sends message to $B"
    echo "use key password: pass"
    ./sendmsg $certA.new $keyA.new $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msgout; return 1
    fi

    echo "$B tries to change password; # expect pending messages failure"
    echo "use old login password from $tmp/creds.txt"
    echo "use new login password: newpass"
    echo "use key password: pass"
    ./changepw $B $keyB $tmp/blah
    # expect $pwprompt
    # send -- "$pass\r"
    # expect $newpwprompt
    # send -- "new$pass\r"

    rm -f $msgout
    
    return 0;
}

testfunctionality5 () {
    echo "Test Functionality 5: unsend feature"
    
    # revert pw to original and overwrite original key and cert 
    echo "$A generates new private key and changes password to get a new certificate"
    ./genkey.sh $keyA $keypass
    echo "use old login password: newpass"
    echo "use new login password: pass"
    echo "use key password: pass"
    ./changepw $A $keyA $certA
    # expect $pwprompt
    # send -- "new$pass\r"
    # expect $newpwprompt
    # send -- "$pass\r"

    echo "___________________________________________________________________________"

    echo "$B tries to receive message from $A; # expect client signature verification to fail"
    echo "use key password: pass"
    ./recvmsg $certB $keyB $tmp/blah
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00001" ]; then
        echo "Error: message not deleted from $B's mailbox"
        rm -f $msgout; return 1
    fi
        
    rm -f $msgout

    return 0
}

testfunctionality6 () {
    echo "Test Functionality 6: sendmsg to invalid recipient"
    msg=msg6.txt
    msgout=msg6out.txt

    echo "$A sends message to invalid recipient and $B; # expect one invalid recipient error and one success"
    echo "use key password: pass"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$B/00001" ]; then
        echo "Error: message not written to $B's mailbox"
        rm -f $msgout; return 1
    fi

    rm -f $msgout

    return 0
}

testfunctionality7 () {
    echo "Test Functionality 7: sendmsg to user who has not getcert'd yet"
    msg=msg7.txt
    msgout=msg7out.txt

    echo "$A sends message to uncertified recipient; # expect certificate read error"
    echo "use key password: pass"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$C/00001" ]; then
        echo "Error: message written to uncertified $C's mailbox"
        rm -f $msgout; return 1
    fi

    rm -f $msgout

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

testimpersonation () {
    echo "Test Security 1: sendmsg sender impersonation"
    msg=msg8.txt
    msgout=msg8out.txt

    echo "$C generates a private key and gets a certificate"
    ./genkey.sh $keyC $keypass
    echo "use login password from $tmp/creds.txt"
    echo "use key password: pass"
    ./getcert $C $keyC $certC
    # expect $pwprompt
    # send -- "$pass\r"

    echo "___________________________________________________________________________"

    echo "$A tries to send message to $C by impersonating $B"
    echo "use key password: pass"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ ! -f "$mail/$C/00001" ]; then
        echo "Error: message not written to $C's mailbox"
        rm -f $msgout; return 1
    fi

    echo "___________________________________________________________________________"

    echo "$C tries to receive message sent by $A posing as $B; # expect client signature verification to fail"
    echo "use key password: pass"
    ./recvmsg $certC $keyC $tmp/blah
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$C/00001" ]; then
        echo "Error: message not deleted from $C's mailbox"
        rm -f $msgout; return 1
    fi
        
    rm -f $msgout

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
    echo "$A tries to send message with mismatched certificate/key pair; # expect client certificate verification to fail"
    echo "use key password: pass"
    ./sendmsg $badcert $mismatchkey $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00002" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msgout; return 1
    fi
    
    rm -f $msgout

    return 0
}

testTLS2 () {
    echo "Test certificate signed by the wrong CA"
    msg=msg10.txt
    msgout=msg10out.txt
    echo "$A tries to send message with certificate signed by another CA; # expect client certificate verification to fail"
    echo "use key password: pass"
    ./sendmsg $badcert $badkey $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00002" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msgout; return 1
    fi
    
    rm -f $msgout

    return 0
}

testTLS3 () {
    echo "Test invalid certificate"
    msg=msg11.txt
    msgout=msg11out.txt
    echo "$A tries to send message with invalid certificate; # expect client certificate verification to fail"
    echo "use key password: pass"
    ./sendmsg $invalidcert $badkey $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00002" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msgout; return 1
    fi
    
    rm -f $msgout

    return 0
}

testTLS4 () {
    echo "Test invalid key"
    msg=msg12.txt
    msgout=msg12out.txt
    echo "$A tries to send message with invalid key; # expect client certificate verification to fail"
    echo "use key password: pass"
    ./sendmsg $badcert $invalidkey $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00002" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msgout; return 1
    fi
    
    rm -f $msgout

    return 0
}

# Volume/DOS tests

testlargemsg () {
    echo "Test send large (>1MB) message"
    msg=msg13.txt
    msgout=msg13out.txt

    echo "write large message"
    echo "MAIL FROM:<$A>" >> $tmp/$msg
    echo "RCPT TO:<$B>" >> $tmp/$msg
    for i in {1..1000000}; do
        printf "." >> $tmp/$msg
    done

    echo "___________________________________________________________________________"

    echo "$A tries to send large message to $B; # expect message too large error"
    echo "use key password: pass"
    ./sendmsg $certA $keyA $tmp/$msg
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00002" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msgout; return 1
    fi

    rm -f $msgout

    return 0
}

testspamsendmsg () {
    echo "Test spam sendmsg to fill up mailbox"
    msg=msg14.txt
    msgout=msg14out.txt

    echo "Empty $B's mailbox"
    rm -f $mail/$B/*

    echo "Fill up $B's mailbox with 99999 messages"
    for i in {1..99999}; do
        /usr/bin/expect -c "
        spawn ./sendmsg $certA $keyA $tmp/$msg
        expect \"$keypassprompt\";
        send \"$keypass\n\";
        expect \"$keypassprompt\";
        send \"$keypass\n\";
        expect eof;
        " >/dev/null 2>&1
        # expect $keypassprompt
        # send -- "$keypass\r"
    done
    if [ ! -f "$mail/$B/99999" ]; then
        echo "Error: messages not written to $B's mailbox"
        rm -f $msgout; return 1
    fi
    
    echo "___________________________________________________________________________"

    echo "Try to send 100000th message to $B"    
    /usr/bin/expect -c "
    spawn ./sendmsg $certA $keyA $tmp/$msg
    expect \"$keypassprompt\";
    send \"$keypass\n\";
    expect \"$keypassprompt\";
    send \"$keypass\n\";
    expect eof;
    "
    # expect $keypassprompt
    # send -- "$keypass\r"
    if [ -f "$mail/$B/00000" ]; then
        echo "Error: message written to $B's mailbox"
        rm -f $msgout; return 1
    fi

    rm -f $msgout

    return 0
}

testspamchangepw () {
    return 0
}

testsecurity () {
    testimpersonation
    if [ $? -ne 0 ]; then
        echo "Test Impersonation FAILED"
        rm -f $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testTLS1
    if [ $? -ne 0 ]; then
        echo "Test TLS 1 FAILED"
        rm -f $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testTLS2
    if [ $? -ne 0 ]; then
        echo "Test TLS 2 FAILED"
        rm -f $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testTLS3
    if [ $? -ne 0 ]; then
        echo "Test TLS 3 FAILED"
        rm -f $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testTLS4
    if [ $? -ne 0 ]; then
        echo "Test TLS 4 FAILED"
        rm -f $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    testlargemsg
    if [ $? -ne 0 ]; then
        echo "Test Large Message FAILED"
        rm -f $msgout; return 1
    fi
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    # testspamsendmsg
    # if [ $? -ne 0 ]; then
    #     echo "Test Spam sendmsg FAILED"
    #     rm -f $msgout; return 1
    # fi
    # echo "___________________________________________________________________________"
    # echo "___________________________________________________________________________"
    # testspamchangepw
    # if [ $? -ne 0 ]; then
    #     echo "Test Spam changepw FAILED"
    #     rm -f $msgout; return 1
    # fi
    # echo "___________________________________________________________________________"
    # echo "___________________________________________________________________________"
    
    echo "ALL SECURITY TESTS PASSED"
    
    echo "___________________________________________________________________________"
    echo "___________________________________________________________________________"
    
    return 0
}

testfunctionality
testsecurity

rm -f $tmp/$A* $tmp/$B* $tmp/$C*
