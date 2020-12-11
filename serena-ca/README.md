# Test Documentation
There are two test scripts provided, testserver.sh and testclient.sh, that are executed in the main ca.sh script. Please note that the 
test scripts should not be run independently of ca.sh because web server set-up in the main script is required for the tests to run
properly. ca.sh provides code for parts 1-6 on the assignment instruction page before executing the test scripts. The relevant
error codes from the tests are displayed from the server/client outputs.

## testserver.sh
This script consists of 7 test cases, each generating a client certificate that is rejected by the web server upon attempted connection
and file request.
- Test 1: expired certificate (notAfter date has passed)
- Test 2: not yet valid certificate (notBefore date is in the future)
- Test 3: self signed certificate
- Test 4: incorrect purpose certificate (serverAuth instead of clientAuth)
- Test 5: certificate signed by untrusted intermediate certificate
- Test 6: certificate signed by untrusted intermediate certificate, which was signed by untrusted root certificate
- Test 7: corrupted client certificate (a byte in the certificate was illegally modified)

## testclient.sh
This script consists of 1 test case, which generates a server certificate that is rejected by a client upon attempted connection.
- Test 1: expired certificate

Other tests for illegal server certificates that are symmetric to the client certificate tests (Tests 2-7) are not included since the
certificate generation is almost identical and the resulting errors are known to be the same.
