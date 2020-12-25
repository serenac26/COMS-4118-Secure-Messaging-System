# Tests 

## Run Tests
`sudo rm -rf <tree> && make clean && make install TREE=<tree>`

In one shell:
```
sudo su
cd <tree>/server/bin
./pemithor
```
In another shell:
`sudo ./test.sh <tree>`

Note that you can only run this test script once after installing a new directory. On subsequent runs, the server and CA will not be in the expected initial states anymore and tests will fail. You must start with a fresh directory tree before testing with `test.sh`.

## Functionality Tests

Test Case 1:
end to end with no funny business
* users A and B genkey
* A and B getcert
    * ca should have new cert
    * user should have new cert
* A sendmsg to B
    * message 00001 should be written to B's mailbox
* B recvmsg
    * message 00001 should be deleted from B's mailbox

Test Case 2:
changepw with no pending messages
* user A creates new key with genkey
* A changepw with new pw and new key
    * should get new cert back

check password change
* A tries to login for getcert with old pw and old key (key doesn't matter)
    * credential authentication should fail
* A tries to login for getcert with new pw and old key
    * credential authentication should pass

check certificate change
* A sendmsg to B with old cert and old key
    * message 00001 should be written to B's mailbox
* B recvmsg
    * client signature verification should fail since A used an old certificate to sign its message
    * message 00001 should be deleted from B's mailbox
* A sendmsg to B with new cert and new key
    * message 00001 should be written to B's mailbox
* B recvmsg
    * message 00001 should be deleted from B's mailbox


Test Case 3:
getcert idempotency
* A creates new key with genkey
* A getcert with pw (updated in test 2) and new key
    * should NOT get new cert since one already exists
    * check diff btw old cert and "new" cert files
* A sendmsg to B (using cert from test 2)
    * message 00001 should be written to B's mailbox
* B recvmsg
    * message 00001 should be deleted from B's mailbox

Test Case 4:
changepw with pending messages
* A sendmsg to B using current certificate
    * message 00001 should be written to B's mailbox
* B changepw with new pw and some key
    * should fail since B has an unread msg from A

Test Case 5:
unsend msg easter egg
* user A creates new key with genkey
* A changepw with new pw and new key
    * should get new cert back
* B tries to recvmsg
    * client signature verification should fail since A got a new certificate after sending the msg
    * message 00001 should be deleted from B's mailbox

Test Case 6:
sendmsg to invalid recipient
* A sendmsg to invalid recipient and B
    * should get an error for invalid recipient and successfully write message 00001 to B's mailbox

Test Case 7:
sendmsg to recipients who have not generated a certificate yet
* A sendmsg to C
    * no message should be written to C's mailbox

## Security Tests

### User Impersonation

Test Case 1:
sendmsg sender impersonation
* user C genkey
* C getcert
* A tries to sendmsg to C with "MAIL FROM:\<B\>" header with A's own certificate/key
    * message 00001 should be written to C's mailbox
* C recvmsg
    * client signature verification should fail since true sender A's certificate does not match fake sender B's certificate
    * message 00001 should be deleted from C's mailbox

Test Case 2:
recvmsg recipient impersonation
* with our client certificate verification implementation, a user with someone else's certificate (but not private key) will never be able to receive messages that were sent to the other user; see TLS Test Case 1
* additionally, a user who bypasses the client to send an HTTP response for recvmsg will always be identified by the server from the certificate they used to establish the TLS connection, and since we assume that the impersonator has not stolen another user's private key along with their certificate, they can never impersonate someone else this way

### TLS 

Test Case 1:
Example: A gets a hold of B's certificate but not private key and attempts to sendmsg/recvmsg with it
* A tries to sendmsg with mismatched cert/key pair
    * client certificate verification should fail

Test Case 2:
Example: A gets a certificate signed by a different CA and attempts to sendmsg/recvmsg with it
* A tries to sendmsg with unverifiable certificate
    * client certificate verification should fail

Test Case 3:
Example: A uses a malformed certificate
* A tries to sendmsg with invalid certificate
    * client certificate verification should fail

Test Case 4:
Example: A uses a malformed private key
* A tries to sendmsg with invalid key
    * client certificate verification should fail

### Volume/DOS 

Test Case 1:
* send large message (>1MB)
    * client should get an error from server

Test Case 2:
* spam sendmsg to a single recipient to fill their mailbox with >99999 messages
    * client should get an error from server when the mailbox is full
