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
#include <sys/wait.h>

#include "bstrlib.h"
#include "utf8util.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"
#include "utils.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define BUF_SIZE 100

//./change-pw <username> <privatekeyfile> 
int main(int argc, char *argv[]) {

    if (argc != 3) {
        fprintf(stderr, "bad arg count; usage: change-pw <username> <key-file>\n");
		return 1;
    }
    char *username = argv[1];
    char *password = getpass("Enter old password: ");
    char *newkeyfile = argv[2];
    char *newPassword = getpass("Enter new password: ");
//make csr with new private key and password 
//username /password/newpassword/csr 
//write new certificate
    if ((strlen(username) > 32) || (strlen(password) >32)) {
        printf("input too large: must be 32 or less characters\n");
    }

    char *tempfile = "temp.txt";
    int pid, wpid;
    int status = 0;
    pid = fork();
    //CHANGE int config and directory 
    if (pid == 0) {
        execl("./makecsr.sh", "./makecsr.sh", "../imopenssl.cnf", username, argv[2], tempfile);
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
	sin.sin_port = htons(4200);

	he = gethostbyname("localhost");//update hostbyname
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

    //ssl write stuff, new pass 
    //ssl read confirm new 
    int bytes = (1024*1024);
    int port = 4200;
    char *method = "changepw";

    char *buffer = (char *) malloc(sizeof(char)*bytes);

    char header[BUF_SIZE];
    sprintf(header, "post https://localhost:%d/%s HTTP/1.1\n", port, method);
    char *header2 = "connection: close\n";
    char header3[BUF_SIZE];

    char usernameLine[sizeof(username)+strlen("username:\n")];
    sprintf(usernameLine, "username:%s\n", username);

    char passwordLine[sizeof(password)+strlen("password:\n")];
    sprintf(passwordLine, "password:%s\n", password);

    char newPasswordLine[sizeof(newPassword)+strlen("newpassword:\n")];
    sprintf(newPasswordLine, "newpassword:%s\n", newPassword);
    char csrLine[strlen(csr) + strlen("csr:\n")];
    sprintf(csrLine, "csr:%s\n", csr);
    bstring tempstring = bfromcstr(csrLine);
    bstring bkey = bfromcstr("");
    bstring bvalue = bfromcstr("");
    serializeData(bkey, bvalue, tempstring, 1);
    char *encodedCsrLine = bvalue->data;
    bdestroy(tempstring);
   //+1 for new line
    int contentLength = strlen(usernameLine) + strlen(passwordLine) + strlen(newPasswordLine) + strlen(encodedCsrLine) + 1;
    sprintf(header3, "content-length: %d\n", contentLength);
    sprintf(buffer, "%s%s%s%s%s%s%s%s%s", header, header2, header3, "\n", usernameLine, passwordLine, newPasswordLine, encodedCsrLine, "\n");
    SSL_write(ssl, buffer, strlen(buffer));
    //read buff
    //check for 200 okay
    //if good, read the data (somehow)
    //ask the user for the file they want stored
    //write this data to the file from a buffer
    //output "it is output here" 
    
    char ibuf[1000];
    memset(ibuf, '\0', sizeof(ibuf));
    char certif[bytes];
    certif[0] = '\0';
    int state = 0;
    char writePath[100];
    char *resultCertif = '\0';
    while (1) {
        int readReturn = SSL_read(ssl, ibuf, sizeof(ibuf)-1);
        if (readReturn == 0) {
            break;
        }
        if ((strstr(ibuf, "200 OK") != NULL) && (state == 0)) {
            printf("Enter a path for cert: \n");
            scanf("%s", writePath);
            state = 1;
        } else if ((strstr(ibuf, "400") != NULL) && (state == 0)) {
            printf("Error 400: Bad Request");
            break;
        } else if ((state == 1) && (ibuf[0] == '\n')) {
            state = 2;
        } else if ((state == 2) && (ibuf[0] != '\n')) {
            sprintf(certif + strlen(certif), ibuf);
        } else if ((state == 2) && (ibuf[0] == '\n')) {
            break;
        }
    }

    if ((state == 2) && (certif != NULL)) {
        bstring temp1 = bfromcstr(certif);
        bstring bkey1 = bfromcstr("");
        bstring bvalue1 = bfromcstr("");
        deserializeData(bkey1, bvalue1, temp1, 1);
        resultCertif = bvalue1->data;
        FILE *fp;
        fp = fopen(writePath, "w+");
        fputs(resultCertif+12, fp);
        fclose(fp);
        bdestroy(temp1);
        bdestroy(bkey1);
        bdestroy(bvalue1);
        printf("Wrote certification to: %s\n", writePath);
    }
    free(csr);
    free(buffer);
    free(sbio);
    bdestroy(bkey);
    bdestroy(bvalue);
    return 0;
}
