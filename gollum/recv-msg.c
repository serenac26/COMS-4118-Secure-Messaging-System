#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "bstrlib.h"
#include "utf8util.h"
#include "buniutil.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"

#include "utils.h"
#include "gollumutils.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

// usage: recv-msg <cert-file> <key-file> <msg-out-file>

// 1. give both cert and private key to do SSL handshake verification and connect to server
// 2. gets a signed encrypted message from server and write to temp file signed-msg
// 3. get encrypted message from signed-msg using cms_verify and CMS_NO_SIGNER_CERT_VERIFY flag to temp file encrypted-msg
// 4. decrypt encrypted-msg using recipient's private key and write to temp file decrypted-msg
// 5. parse sender info from decrypted-msg header FROM:
// 6. send sender name to server /getusercert
// 7. gets sender cert and write to temp file sender.cert.pem
// 8. verify sender of signed-message with cms_verify using sender.cert.pem and client's copy of ca-chain
// 9. write the decrypted message to the specified output file
// 10. delete temp files (signed-msg, decrypted-msg, sender-chain.cert.pem)

int main(int argc, char *argv[]) {
	char *certificate = getpass("Enter certificate: ");

	// TODO: Give both cert and private key to do SSL handshake verification
	/*
	SSL_CTX *ctx;
	SSL *ssl;
	const SSL_METHOD *meth; 
	BIO *sbio;
	int err; char *s;

	int ilen;
	char ibuf[512];
	
	struct sockaddr_in sin;
	int sock;
	struct hostent *he;
	SSL_library_init();
	SSL_load_error_strings();

	meth = TLS_client_method();
	ctx = SSL_CTX_new(meth);
	SSL_CTX_set_default_verify_dir(ctx);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(ctx);
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	bzero(&sin, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(443);
	he = gethostbyname("");//edit this

	memcpy(&sin.sin_addr, (struct in_addr *)he->h_addr, he->h_length);
	if (connect(sock, (struct sockaddr *)&sin, sizeof sin) < 0) {
		perror("connect");
		return 2;
	}
	sbio=BIO_new(BIO_s_socket());
	BIO_set_fd(sbio, sock, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);
	err = SSL_connect(ssl);

	if (SSL_connect(ssl) != 1) {
		switch (SSL_get_error(ssl, err)) {
			case SSL_ERROR_NONE: s="SSL_ERROR_NONE"; break;
			case SSL_ERROR_ZERO_RETURN: s="SSL_ERROR_ZERO_RETURN"; break;
			case SSL_ERROR_WANT_READ: s="SSL_ERROR_WANT_READ"; break;
			case SSL_ERROR_WANT_WRITE: s="SSL_ERROR_WANT_WRITE"; break;
			case SSL_ERROR_WANT_CONNECT: s="SSL_ERROR_WANT_CONNECT"; break;
			case SSL_ERROR_WANT_ACCEPT: s="SSL_ERROR_WANT_ACCEPT"; break;
			case SSL_ERROR_WANT_X509_LOOKUP: s="SSL_ERROR_WANT_X509_LOOKUP"; break;
			case SSL_ERROR_WANT_ASYNC: s="SSL_ERROR_WANT_ASYNC"; break;
			case SSL_ERROR_WANT_ASYNC_JOB: s="SSL_ERROR_WANT_ASYNC_JOB"; break;
			case SSL_ERROR_SYSCALL: s="SSL_ERROR_SYSCALL"; break;
			case SSL_ERROR_SSL: s="SSL_ERROR_SSL"; break;
		}
		fprintf(stderr, "SSL error: %s\n", s);
		ERR_print_errors_fp(stderr);
		return 3;
	}

	//writing stuff with http
	//GET /HTTP/1.0
	*/


// Get signed encrypted message from server and write to temp file signed-msg


// Get encrypted message from signed-msg without verifying and write to temp file encrypted-msg


// Decrypt encrypted-msg using recipient's private key and write to temp file decrypted-msg


// Get sender name from decrypted-msg header


// TODO: Send sender name to server /getusercert


// TODO: Get sender cert and write to temp file sender.cert.pem


// Verify sender of signed-message using sender.cert.pem and client's copy of ca-chain


// Write the decrypted message to the specified output file


// Delete temp files (signed-msg, decrypted-msg, sender-chain.cert.pem)

	return 0;
}
