#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "bstrlib.h"
#include "utf8util.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h""
#include "utils.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

//./get-cert <username> <privatekeyfile>
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "bad arg count; usage: get-cert <username> <key-file\n");
    }
    char *username = argv[1];
    char *password = getpass("Enter password: ");

    if ((strlen(username) > 32 ) || (strlen(password)>32)) {
        printf("input too large: must be 32 or less characters\n");
    }

    char *privatekeyfile = argv[2];
    FILE *fp;
    fp = fopen(privatekeyfile, "r+");
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *privatekey = malloc(fsize + 1);
    fread(privatekey, 1, fsize, fp);
    fclose(fp);
    privatekey[fsize] = 0;
    
    char *tempfile = "temp.txt";
    int pid, wpid;
    int status = 0;
    pid = fork();
    if (pid == 0) {
        execl("./makecsr.sh", "./makecsr.sh", "../imopenssl.cnf", username, privatekey, tempfile);
    }
    while ((wpid = wait(&status)) > 0);
    FILE *temp;
    temp = fopen("temp.txt", "r+");
    fseek(temp, 0, SEEK_END);
    long fsize1 = ftell(temp);
    fseek(temp, 0, SEEK_SET);

    char *csr = malloc(fsize1 + 1);
    fread(csr, 1, fsize1, temp);
    fclose(temp);
    remove("temp.txt");

    SSL_CTX *ctx;
    SSL *ssl;
    const SSL_METHOD *meth; 
    BIO *sbio;
    int err; char *s;

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
	he = gethostbyname("localhost");//edit this

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
    //write to file and give to user. 

    int bytes = (1024*1024);
    int port = 4200;
    char *method = "getcert";
    char *buffer = (char *) malloc(sizeof(char)*bytes);

    char header[100];
    sprintf(header, "post https://localhost:%d/%s HTTP/1.1\n", port, method);
    char *header 2 = "connection: close\n";
    char header3[100];

    char usernameLine[sizeof(username)+strlen("username:\n")];
    sprintf(usernameLine, "username:%s\n", username);
    char passwordLine[sizeof(password)+strlen("password:\n")];
    sprintf(passwordLine, "password:%s\n", password);

    char csrLine[strlen(csr) + strlen("csr:\n")];
    sprintf(csrLine, "csr:%s\n", csr);

    bstring temp = bfromcstr(csrLine);
    encodeMessage(temp);
    char *encodedCsrLine = temp->data;
    bdestroy(temp);

    int contentLength = strlen(usernameLine) + strlen(passwordLine) + strlen(encodedCsrLine) + 1;
    sprintf(buffer, "%s%s%s%s%s%s%s%s", header, header2, header3, "\n", usernameLine, passwordLine, encodedCsrLine, "\n");
    SSL_write(ssl, buffer, strlen(buffer));

    SSL_read()
    printf("Enter a path for cert: \n");
    char ibuf[1000];
    memset(ibuf, '\0', sizeof(ibuf));
    char certif[1000];
    certif[0] = '\0';
    int state = 0;
    char writePath[100];
    char *resultCertif;
    while (1) {
        int readReturn = SSL_read(ssl, ibuf, sizeof(ibuf)-1);
        if (readReturn == 0){
            break;
        }
        if ((strstr(ibuf, "200 OK") != NULL) && (state == 0)) {
            printf("Enter a path for cert: \n");
            scanf("%s", writePath);
            state = 1;
        } else if ((strstr(ibuf, "400") != NULL) && (state == 0)){
            printf("Error 400: Problem with username, password or key.");
            break;
        } else if ((state == 1) && (ibuf[0] == "\n")) {
            state = 2;
        } else if ((state == 2) && (ibuf[0] != "\n")) {
            sprintf(certif+strlen(certif), ibuf);
        } else if ((state == 2) && (ibuf[0] == "\n")) {
            break;
        }
    }
    if ((state == 2) && (certif != NULL)) {
        bstring temp = bfromcstr(certif);
        decodeMessage(temp);
        resultCertif = temp->data;
        FILE *fp;
        fp = fopen(writePath, "w+");
        fputs(resultCertif, fp);
        fclose(fp);
        printf("Wrote certification to: %s\n", writePath);
    }

    free(privatekey);
    free(csr);
    return 0;
}
