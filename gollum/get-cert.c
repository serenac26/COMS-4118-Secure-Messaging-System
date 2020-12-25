#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bsafe.h"
#include "bstraux.h"
#include "bstrlib.h"
#include "bstrlibext.h"
#include "utf8util.h"
#include "utils.h"

int create_socket(int port) {
  int s;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  int err = connect(s, (struct sockaddr *)&addr, sizeof(addr));
  if (err < 0) {
    perror("Error connecting");
    exit(EXIT_FAILURE);
  }

  return s;
}

//./get-cert <username> <privatekeyfile>
int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "bad arg count; usage: get-cert <username> <key-file\n");
  }
  char *username = argv[1];
  char *password = getpass("Enter password: ");

  if ((strlen(username) > 32) || (strlen(password) > 32)) {
    printf("input too large: must be 32 or less characters\n");
  }

  char *privatekeyfile = argv[2];

  char *tempfile = "temp.txt";
  int pid, wpid;
  int status = 0;
  pid = fork();
  if (pid == 0) {
    execl("./makecsr.sh", "./makecsr.sh", "../imopenssl.cnf", username,
          privatekeyfile, tempfile, '\0');
  }
  if ((wpid = wait(&status)) < 0) exit(1);
  FILE *temp;
  temp = fopen(tempfile, "r+");
  fseek(temp, 0, SEEK_END);
  long fsize1 = ftell(temp);
  fseek(temp, 0, SEEK_SET);

  char *csr = malloc(fsize1 + 1);
  memset(csr, '\0', fsize1 + 1);
  fread(csr, 1, fsize1, temp);
  fclose(temp);
  remove("temp.txt");

  // SSL handshake verification

  SSL_library_init();       /* load encryption & hash algorithms for SSL */
  SSL_load_error_strings(); /* load the error strings for good error reporting
                             */

  // TLSv1_1_server_method is deprecated
  // Can switch back if inconvenient
  const SSL_METHOD *mamamethod = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(mamamethod);

  // Only accept the LATEST and GREATEST in TLS
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

  //   if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) != 1) {
  //     ERR_print_errors_fp(stderr);
  //     exit(EXIT_FAILURE);
  //   }

  //   // TODO: need to input password
  //   if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
  //     ERR_print_errors_fp(stderr);
  //     exit(EXIT_FAILURE);
  //   }

  //   if (SSL_CTX_load_verify_locations(ctx, CA_CHAIN, NULL) != 1) {
  //     ERR_print_errors_fp(stderr);
  //     exit(EXIT_FAILURE);
  //   }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  /* Set the verification depth to 1 */

  //   SSL_CTX_set_verify_depth(ctx, 1);

  int sock = create_socket(4200);

  SSL *ssl = SSL_new(ctx);

  SSL_set_fd(ssl, sock);

  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    free(password);
    return 0;
  }

  // writing stuff with http
  // GET /HTTP/1.0
  // write to file and give to user.

  int bytes = (1024 * 1024);
  int port = 4200;
  char *method = "getcert";
  char *buffer = (char *)malloc(sizeof(char) * bytes);

  char header[100];
  sprintf(header, "post https://localhost:%d/%s HTTP/1.1\n", port, method);
  char *header2 = "connection: close\n";
  char header3[100];

  char usernameLine[strlen(username) + strlen("username:\n") + 1];
  usernameLine[strlen(username) + strlen("username:\n")] = '\0';
  sprintf(usernameLine, "username:%s\n", username);
  char passwordLine[strlen(password) + strlen("password:\n") + 1];
  passwordLine[strlen(password) + strlen("password:\n")] = '\0';
  sprintf(passwordLine, "password:%s\n", password);

  bstring encoded = bfromcstr("");
  bstring bkey = bfromcstr("csr");
  bstring bvalue = bfromcstr(csr);
  serializeData(bkey, bvalue, encoded, 1);
  char *encodedCsrLine = encoded->data;
  bdestroy(bkey);
  bdestroy(bvalue);

  int contentLength =
      strlen(usernameLine) + strlen(passwordLine) + strlen(encodedCsrLine) + 1;
  sprintf(header3, "content-length: %d\n", contentLength);
  sprintf(buffer, "%s%s%s%s%s%s%s%s", header, header2, header3, "\n",
          usernameLine, passwordLine, encodedCsrLine, "\n");
  SSL_write(ssl, buffer, strlen(buffer));

  bdestroy(encoded);

  // printf("Enter a path for cert: \n");
  bstring certif = bfromcstr("");
  int state = 0;
  char writePath[100];
  char *resultCertif = '\0';
  while (1) {
		char ibuf[1000];
		memset(ibuf, '\0', sizeof(ibuf));
    int readReturn = 0;
    while (readReturn < sizeof(ibuf) - 1) {
      int i = SSL_read(ssl, ibuf + readReturn++, 1);
			if (i == 0) readReturn--;
      if (i != 1 || ibuf[readReturn - 1] == '\n') break;
    }
    if (readReturn == 0) {
      break;
    }
    if ((strstr(ibuf, "200 OK") != NULL) && (state == 0)) {
      printf("Enter a path for cert: \n");
      scanf("%s", writePath);
      state = 1;
    } else if ((strstr(ibuf, "400") != NULL) && (state == 0)) {
      printf("Error 400: Problem with username, password or key.");
      break;
    } else if ((strstr(ibuf, "-2") != NULL) && (state == 0)) {
      printf("Error -2: Wrong Password");
      break;
    } else if ((strstr(ibuf, "-1") != NULL) && (state == 0)) {
      printf("Error -1: Bad Username");
      break;
    } else if ((strstr(ibuf, "-3") != NULL) && (state == 0)) {
      printf("Error -3: Opening file or directory error");
    } else if ((strstr(ibuf, "-5") != NULL) && (state == 0)) {
      printf("Warning: Certificate exists already!");
      printf("Enter a path for cert: \n");
      scanf("%s", writePath);
      state = 1;
    } else if ((state == 1) && (ibuf[0] == '\n')) {
      state = 2;
    } else if ((state == 2) && (ibuf[0] != '\n')) {
      bstring _ibuf = bfromcstr(ibuf);
      bconcat(certif, _ibuf);
      bdestroy(_ibuf);
    } else if ((state == 2) && (ibuf[0] == '\n')) {
      break;
    }
  }
  if ((state == 2) && (certif->slen > 0)) {
    bstring bkey1 = bfromcstr("");
    bstring bvalue1 = bfromcstr("");
    deserializeData(bkey1, bvalue1, certif, 1);
    resultCertif = bvalue1->data;
    FILE *fp;
    fp = fopen(writePath, "w+");
    fputs(resultCertif, fp);
    fclose(fp);
    printf("Wrote certification to: %s\n", writePath);
    bdestroy(bkey1);
    bdestroy(bvalue1);
  }

  bdestroy(certif);
  free(csr);
  free(buffer);

  // Cleanup at the end
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sock);
  SSL_CTX_free(ctx);
  EVP_cleanup();
  free(password);
  return 0;
}
