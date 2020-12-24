# Tests 

### Functionality Tests

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
* A getcert with new pw (from test 2) and new key
    * should NOT get new cert since one already exists
    * check diff btw old cert and "new" cert files
* A sendmsg to B using same cert (from test 2)
    * message 00001 should be written to B's mailbox

Test Case 4:
changepw with pending messages
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
sendmsg to invalid recipients

Test Case 7:
sendmsg to recipients who have not generated a certificate yet

### Security Tests

Test Case 1:
sendmsg sender impersonation
* user C genkey
* C getcert
* A tries to sendmsg to C with "From: B" header with A's own cert/key
    * message 00001 should be written to C's mailbox
* C recvmsg
    * client signature verification should fail since true sender A's certificate does not match fake sender B's certificate
    * message 00001 should be deleted from C's mailbox

Test Case 2:
* 

### File Permission Tests

Test Case 1:

### Sandbox Tests

Test Case 1:

### Volume/DOS Tests

Test Case 1:
* send large message (>1MB)

Test Case 2:
* spam sendmsg to a single recipient to fill their mailbox with >99999 messages

Test Case 3:
* spam changepw (ca may keep revoked certificate metadata)

### TLS Tests

Test Case 1:
* A tries to sendmsg with mismatched cert/key pair
    * client certificate verification should fail

Test Case 2:
* A tries to sendmsg with invalid cert
    * client certificate verification should fail

Test Case 3:
* A tries to sendmsg with invalid key
    * client certificate verification should fail