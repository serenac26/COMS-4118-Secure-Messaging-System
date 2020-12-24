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
#include<sys/wait.h>


#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
//./change-pw <username> <privatekeyfile> 
int main(int argc, char *argv[]) {

    if (argc != 2) {
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

    FILE *fp;
    fp = fopen(newkeyfile, "r+");
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *privatekey = malloc(fsize +1);
    fread(privatekey, 1, fsize, fp);
    fclose(fp);
    privatekey[fsize] = 0;

    char *tempfile = "temp.txt";
    int pid, wpid;
    int status = 0;
    pid = fork();
    //CHANGE int config and directory 
    if (pid == 0) {
        execl("./makecsr.sh", "./makecsr.sh", "../imopenssl.cnf", username, privatekey, tempfile);
    }
    while ((wpid = wait(&status)) > 0);
    FILE *temp; 
    temp = fopen("temp.txt", "r+");
    fseek(temp, 0, SEEK_END);
    long fsize1 = ftell(temp);
    fseek(temp, 0, SEEK_SET);

    char *csr = malloc(fsize + 1);
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

    char header[100];
    sprintf(header, "post https://localhost:%d/%s HTTP/1.1\n", port, method);
    char *header2 = "connection: close\n";
    char header3[100];

    char usernameLine[sizeof(username)+strlen("username:\n")];
    sprintf(usernameLine, "username:%s\n", username);

    char passwordLine[sizeof(password)+strlen("password:\n")];
    sprintf(passwordLine, "password:%s\n", password);

    char newPasswordLine[sizeof(newPassword)+strlen("newpassword:\n")];
    sprintf(newPasswordLine, "newpassword:%s\n", newPassword);
    char csrLine[strlen(csr) + strlen("csr:\n")];
    sprintf(csrLine, "csr:%s\n", csr);

   //+1 for new line
    int contentLength = strlen(usernameLine) + strlen(passwordLine) + strlen(newPasswordLine) + strlen(csrLine) + 1;
    sprintf(header3, "content-length: %d\n", contentLength);
    sprintf(buffer, "%s%s%s%s%s%s%s%s%s", header, header2, header3, "\n", usernameLine, passwordLine, newPasswordLine, csrLine, "\n");
    SSL_write(ssl, buffer, strlen(buffer));
    //read buff
    //check for 200 okay
    //if good, read the data (somehow)
    //ask the user for the file they want stored
    //write this data to the file from a buffer
    //output "it is output here" 
    free(privatekey);
    free(csr);
    return 0;
}
