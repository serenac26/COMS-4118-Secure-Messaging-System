#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

// usage: recv-msg <cert-file> <key-file> <msg-out-file>

// 1. read in certificate from input cert file name (argv[1])
// 2. send certificate to server /verifycert
// 3. gets a signed encrypted message from server and write to temp file signed-msg
// 4. get encrypted message from signed-msg using cms_verify and CMS_NO_SIGNER_CERT_VERIFY flag to temp file encrypted-msg
// 5. decrypt encrypted-msg using recipient's private key (argv[2]) and write to temp file decrypted-msg
// 6. parse sender info from decrypted-msg header FROM:
// 7. send sender name to server /verifysign
// 8. gets sender ca chain and write to temp file sender-chain.cert.pem
// 9. verify sender of signed-message with cms_verify using sender-chain.cert.pem
// 9. write the decrypted message to the specified output file (argv[3])
// 10. delete temp files (signed-msg, decrypted-msg, sender-chain.cert.pem)

int main(int argc, char *argv[]) {
    char *certificate = getpass("Enter certificate: ");

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

    return 0;
}
