# The Silmailion

Group name: Secur(s)ed

Group members:
* Serena "Froggins Baggins" Cheng (stc2137)
* William "Samgee Gamgee" Chiu (wnc2105)
* Stacy "Pook Took" Tao (syt2111)
* Meribuck "Harrison Wang" Brandybuck (hbw2118)

## Usage

### Setup
`sudo rm -rf <treename> && make clean && make install TREE=<treename>`

### Start the server
```
sudo su
cd <treename>/server/bin
./pemithor
```

### Send client requests
```
cd <treename>/client/bin
./genkey.sh <private-key-output-file> [password]
./getcert <username> <private-key-file> <cert-out-file>
./changepw <username> <private-key-file> <cert-out-file>
./sendmsg <certificate-file> <private-key-file> <message-input-file>
./recvmsg <certificate-file> <private-key-file> <message-output-file>
```

### Terminate server:
To safely terminate the server, send an HTTP post request to it via an OpenSSL client with the keyword 'die'. For example:
```
post https://localhost:4200/getcert die
connection: close
content-length: 0

```
Otherwise, you can CTRL-C the server process directly, however, this will likely result in memory leaks.

## Testing

Refer to `test` directory

## Notes

If you run into an error with `/usr/share/dict/words`, please try:

```sudo apt-get install --reinstall wamerican```

If you are missing libssl-dev ```fatal error: openssl/ssl.h: No such file or directory```, please try:

```sudo apt-get install libssl-dev```

Please make sure `libcrypt` and `libcrypto` are installed as well.

## Design Documentation
### Assumptions
* Attackers cannot sudo
* Mailbox directories are secured via permissions such that the contents (i.e. messages) cannot be tampered with, therefore no HMAC integrity checking is needed
* All users must log in once to generate certificates before being able to receive messages
* Only one message (to possibly multiple recipients) is sent at a time sendmsg
* Messages are limited to 1 MB in size; anything larger will be truncated
* No concurrent client requests

### Sandboxing
* Sandboxing is intended to restrict server privileges to just the subdirectories that it needs to access when handling client requests. In particular, the CA store and mail directory, which contains all of the users’ mailboxes, are sandboxed separately. Beyond providing security in the case of a compromised server, this simulates a system in which the CA and server are on different machines and where the server has to send requests to the CA. For simplicity, our implementation assumes the CA and server are on the same machine.
* Server has lots of privileged functions to access certificate store and mailboxes
sendmsg/recvmsg will need to access restricted mailboxes
getcert/changepw will need to access stored certificates and credentials
* Use chroot() to sandbox client programs’ to client/public or client/tmp
* Use chroot() to sandbox server components according to the below specifications

### Certificates
* Each user has at most one active certificate with appropriate configuration to act as a TLS web-client, file encrypting, and file signing certificate
* The CA revokes a user’s old certificate after changepw is handled successfully and a new certificate is generated for the user

### Server
* Parent process Pemithor fork()s, and the firstborn child process execl()s Boromail. Parent process Pemithor fork()s again, and the lastborn child process execl()s Faramail
* Faramail and Boromail each handle certain HTTP endpoints requested by the client:
* Faramail: Accepts TLS connections without client-side certificate
    * /getcert: login(), getcert()
    * /changepw: login(), checkmail(), changepw(), getcert()
* Boromail: Accepts only TLS connections with CA-issued client-side certificate (issued by getcert), which is verified with openssl
    * /getusercert: getusercert()
    * /sendmsg: sendmessage()
    * /recvmsg: recvmessage()
* There are nine server side functions used by Faramail and Boromail to handle client requests. Each function is sandboxed according to its purpose, the files and directories that it needs to access, and the principle of least privilege
* Faramail uses:
    * login() - verifies username/password against hash password stored in server/credentials/<username>.hashedpw
        * Sandboxed in server/credentials
    * checkmail() - checks if there are any pending messages in a user’s mailbox
        * Sandboxed in server/mail/<username>
    * changepw() - updates the user’s hashed password in server/credentials/username.hashedpw
        * Sandboxed in server/credentials
    * addcsr() - writes a CSR to server/ca/intermediate/csr/<username>.req.pem to prepare getcert()
        * Sandboxed in server/ca
    * getcert() - fulfills a CSR, stores the resulting certificate in server/ca/intermediate/certs/<username>.cert.pem
        * Sandboxed in server/ca
* Boromail uses:
    * getusercert() - retrieves a user’s (either a sender’s or a receiver’s) stored certificate from server/ca/intermediate/certs/<username>.cert.pem
        * Sandboxed in server/ca/intermediate/certs
    * sendmessage() - writes an encrypted and signed message to a recipient’s mailbox with filename ##### (numbering scheme is the same as in HW3, e.g. 00001, 00002, etc.)
        * Sandboxed in server/mail
    * getOldestFileName() - retrieves the path of the oldest pending message in a recipient’s mailbox
        * Sandboxed in server/mail
    * recvmessage() - sends the oldest pending message from the recipient’s mailbox back to the client and deletes it from the mailbox (the recipient is parsed from the peer client certificate used to establish the TLS connection)
        * Sandboxed in server/mail
* Sandboxing is performed by Faramail and Boromail with chroot() before calling these functions

### Client
* getcert
    * Input username and private key file
    * Prompt user for password
    * Create CSR for user with private key
    * Connect to Faramail server via TLS without a client-side certificate
    * Send HTTP request for /getcert with username, password, and CSR
    * Receive the client-side certificate from Faramail if successful otherwise display appropriate error
    * The first time getcert is called, a new certificate will be returned
    * On all subsequent calls of getcert, the same certificate will always be returned no matter the key provided
    * Prompt user for a path to write the resulting client-side certificate to and write it
* changepw
    * Input username and (possibly new) private key file
    * Prompt user for password and new password
    * Create CSR for user with private key
    * Connect to Faramail server via TLS without a client-side certificate
    * Send HTTP request for /changepw with username, password, newpassword, and CSR
    * Receive the client-side certificate from Faramail if successful otherwise display appropriate error
    * Prompt user for a path to write the resulting client-side certificate to
    * Note that if the user had sent messages to others that remain unread before changepw, then the recipients will no longer be able to receive these messages because the signature will not be verifiable against the sender’s new certificate. In this case, the message will simply be deleted from the recipient’s mailbox on recvmsg. We call this feature ‘unsend’ :)
* sendmsg
    * Input certificate file, private key file, and message file
    * Messages are expected to begin with a properly formatted “MAIL FROM:<sender>” line and at least one "RCPT TO:<recipient>” line
    * Verify private key against certificate and connect to Boromail server via TLS after handshake with the client-side certificate
    * Parse recipients from the message
    * For each recipient, send HTTP request for /getusercert with recipient name
    * If recipient is invalid or has not generated a certificate yet, Boromail will respond with proper error code
    * Otherwise, receive the recipient’s certificate from Boromail and write it to a temporary <recipient>.cert.pem file
    * For each recipient, encrypt the message with the recipient’s certificate and then sign the encrypted message with the true sender's certificate
    * The true sender (i.e. the user who owns the provided certificate and its corresponding private key) may be different from the sender specified in the message’s “MAIL FROM:<sender>” header. This will cause a signature verification error in recvmsg, but sendmsg does not check this case
    * For each recipient, send HTTP request for /sendmsg with encrypted and signed message and recipient name
    * Remove all temporary files
* recvmsg
    * Input certificate file and private key file
    * Verify private key against certificate and connect to Boromail server via TLS after handshake with the client-side certificate
    * Send HTTP request for /recvmsg
    * If no message to read, then do nothing
    * Otherwise receive an encrypted and signed message back from Boromail and write it to a temporary file
    * Note that the recipient name is not included in the request because otherwise an attacker could bypass the client to send an HTTP request for /recvmsg to Boromail with any user as the recipient field. Although the attacker may not be able to decrypt the returned message, the message would be deleted from the server, which is not acceptable. Instead, the correct recipient name is parsed from the client certificate by Boromail.
    * Parse the sender name from the message
    * Send HTTP request for /getusercert with sender name
    * If recipient is invalid or has not generated a certificate yet, Boromail will respond with proper error code and client will exit
    * Receive the sender’s certificate from Boromail and write it to a temporary <sender>.cert.pem file
    * Verify the signature on the message against the retrieved sender’s certificate
    * The client must do this verification because it cannot trust the server to verify. The server simply provides a certificate for the client to check against.
    * Write the verified message to a temporary file
    * Prompt user for a path to write the decrypted message to
    * Decrypt the verified message with the recipient’s private key and write the plaintext message to the user-specified path
    * Remove all temporary files

### Message format
* Message files are limited to 1 MB in size.
* Format for messages should begin with a "MAIL FROM:" line (case-insensitive) with the sender name in angle brackets (<,>). Messages that do not follow this format for the first line will be rejected. The following line(s) should be one recipient per line, specified with "RCPT TO:" (case-insensitive) with the recipient name also in angle brackets (<,>). Any lines encountered that do not match this format will stop parsing for recipients.\
* Example:
```
mail from:<sender>
rcpt to:<recipient1>
rcpt to:<recipient2>
the following line is not a valid recipient
rcpt to:<recipient2>
but it is still included in the body of the message
```

### File Layout and Permissions
The server directory and all server files are accessible by root only (permissions are omitted after the first line of the directory below), and the server’s CA store contains all generated client certificates. The client programs escalate permission level to group ring which gives access to the CA chain (root and intermediate certificates) in the client/private directory. Permissions on files written by the client for the user (private key, certificate, received message) are not specifically set, except for on the private key which is set to rwx------.

```
tree
├── [drwxr-xr-x root     ring    ]  client
│   ├── [drwxr-sr-x root     ring    ]  bin
│   │   ├── [-rwxr-S--x root     ring    ]  changepw
│   │   ├── [-rwxr-sr-x root     ring    ]  genkey.sh
│   │   ├── [-rwxr-S--x root     ring    ]  getcert
│   │   ├── [-rwxr-sr-x root     ring    ]  makecsr.sh
│   │   ├── [-rwxr-S--x root     ring    ]  recvmsg
│   │   └── [-rwxr-S--x root     ring    ]  sendmsg
│   ├── [-rwxr--r-- root     ring    ]  ca.cert.pem
│   ├── [-rwxr--r-- root     ring    ]  ca-chain.cert.pem
│   ├── [-rwxr--r-- root     ring    ]  imopenssl.cnf
│   ├── [-rwxr--r-- root     ring    ]  intermediate.cert.pem
│   └── [drwxrwx--- root     ring    ]  tmp
└── [drwx------ root     root    ]  server
    ├── [drwx------ root     root    ]  bin
    │   ├── [-rwx------ root     root    ]  boromail
    │   ├── [-rwx------ root     root    ]  faramail
    │   ├── [-rwx------ root     root    ]  getcert.sh
    │   └── [-rwx------ root     root    ]  pemithor
    ├── [drwx------ root     root    ]  ca
    │   ├── [drwx------ root     root    ]  certs
    │   │   └── [-rwx------ root     root    ]  ca.cert.pem
    │   ├── [-rwx------ root     root    ]  index.txt
    │   ├── [-rwx------ root     root    ]  index.txt.attr
    │   ├── [-rwx------ root     root    ]  index.txt.old
    │   ├── [drwx------ root     root    ]  intermediate
    │   │   ├── [drwx------ root     root    ]  certs
    │   │   │   ├── [-rw-r--r-- root     root    ]  addleness.cert.pem
    │   │   │   ├── [-rwx------ root     root    ]  boromail.cert.pem
    │   │   │   ├── [-rwx------ root     root    ]  ca-chain.cert.pem
    │   │   │   ├── [-rwx------ root     root    ]  faramail.cert.pem
    │   │   │   └── [-rwx------ root     root    ]  intermediate.cert.pem
    │   │   ├── [drwx------ root     root    ]  csr
    │   │   │   ├── [-rw-r--r-- root     root    ]  addleness.req.pem
    │   │   │   ├── [-rwx------ root     root    ]  boromail.csr.pem
    │   │   │   ├── [-rwx------ root     root    ]  faramail.csr.pem
    │   │   │   └── [-rwx------ root     root    ]  intermediate.csr.pem
    │   │   ├── [-rw-r--r-- root     root    ]  index.txt
    │   │   ├── [-rw-r--r-- root     root    ]  index.txt.attr
    │   │   ├── [-rwx------ root     root    ]  index.txt.attr.old
    │   │   ├── [-rwx------ root     root    ]  index.txt.old
    │   │   ├── [drwx------ root     root    ]  newcerts
    │   │   │   ├── [-rwx------ root     root    ]  1000.pem
    │   │   │   ├── [-rwx------ root     root    ]  1001.pem
    │   │   │   └── [-rw-r--r-- root     root    ]  1002.pem
    │   │   ├── [drwx------ root     root    ]  private
    │   │   │   ├── [-rwx------ root     root    ]  boromail.key.pem
    │   │   │   ├── [-rwx------ root     root    ]  faramail.key.pem
    │   │   │   └── [-rwx------ root     root    ]  intermediate.key.pem
    │   │   ├── [-rw-r--r-- root     root    ]  serial
    │   │   └── [-rwx------ root     root    ]  serial.old
    │   ├── [drwx------ root     root    ]  newcerts
    │   │   └── [-rwx------ root     root    ]  1000.pem
    │   ├── [drwx------ root     root    ]  private
    │   │   └── [-rwx------ root     root    ]  ca.key.pem
    │   ├── [-rwx------ root     root    ]  serial
    │   └── [-rwx------ root     root    ]  serial.old
    ├── [drwx------ root     root    ]  credentials
    │   ├── [-rwx------ root     root    ]  addleness.hashedpw
    │   ├── [-rwx------ root     root    ]  analects.hashedpw
     .
     .
     .
    │   └── [-rwx------ root     root    ]  whaledom.hashedpw
    ├── [-rwx------ root     root    ]  imopenssl.cnf
    └── [drwx------ root     root    ]  mail
        ├── [drwx------ root     root    ]  addleness
        │   └── [-rwx------ root     root    ]  00001
        ├── [drwx------ root     root    ]  analects
         .
         .
         .
        └── [drwx------ root     root    ]  whaledom
```
