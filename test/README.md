# Testing 

### Functionality Tests

Test Case 1:
end to end with no funny business
* users A and B genkey
* A and B get-cert
    * ca should have new cert
    * user should have new cert
* A send-msg to B
    * message 00001 should be written to B's mailbox
* B recv-msg
    * message 00001 should be deleted from B's mailbox

Test Case 2:
change-pw with no pending messages
* user A creates new key with genkey
* A change-pw with new pw and new key
    * should get new cert back
* A tries to login for get-cert with old pw and old key (key doesn't matter)
    * credential authentication should fail
* A tries to login for get-cert with new pw and old key
    * credential authentication should pass

Test Case 3:
get-cert idempotency
* A creates new key with genkey
* A get-cert with new pw (from test 2) and new key
    * should NOT get new cert since one already exists
    * check diff btw old cert and "new" cert files
* A send-msg to B using cert (from test 2)
    * should pass

Test Case 4:
change-pw with pending messages
* B change-pw with new pw and some key
    * should fail since B has an unread msg from A

Test Case 5:
unsend msg easter egg
* user A creates new key with genkey
* A change-pw with new pw and new key
    * should get new cert back
* B tries to recvmsg
    * client signature verification should fail since A got a new certificate after sending the msg

Test Case 6:
* user C genkey
* C get-cert
* A tries to sendmsg to C with B's cert/key
    * should pass
* C recvmsg
    * client signature verification should fail since true sender A's certificate does not match fake sender B's certificate

### File Permission Testing

Test Case 1:

### Sandbox Testing

Test Case 1:

### Volume/DOS Testing

Test Case 1:
* send large message (>1MB)

Test Case 2:
* spam sendmsg to a single recipient to fill their mailbox with >99999 messages

Test Case 3:
* spam changepw (ca may keep revoked certificate metadata)

### TLS Testing

Test Case 1:
* A tries to sendmsg with mismatched cert/key pair
    * client certificate verification should fail

Test Case 2:
* A tries to sendmsg with invalid cert
    * client certificate verification should fail

Test Case 3:
* A tries to sendmsg with invalid key
    * client certificate verification should fail