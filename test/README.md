# Testing 

### Brainstorming test cases

Test Case 1:
end to end with no funny business
* users A and B genkey
* A and B get-cert
* A send-msg to B
* B recv-msg

Test Case 2:
change-pw with no pending messages
* user A creates new key with genkey
* A change-pw with new pw and new key
    * should get new cert back
* A tries to login for get-cert with old pw and old key (key doesn't matter)
    * credential authentication should fail
* A tries to login for get-cert with new pw and invalid key
    * credential authentication should pass, expected error reading csr

Test Case 3:
get-cert with new private key
* A creates new key with genkey
* A get-cert with new pw and new key
    * should get new cert back
* A send-msg to B using old cert
    * should fail certificate verification
* A send-msg to B using new cert
    * should pass

Test Case 4:
change-pw with pending messages
* B change-pw with new pw and some key
    * should fail