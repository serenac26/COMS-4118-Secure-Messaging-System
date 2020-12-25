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

#define BUF_SIZE 100

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

//./change-pw <username> <privatekeyfile>
int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "bad arg count; usage: change-pw <username> <key-file>\n");
    return 1;
  }
  char *username = argv[1];
  char *__password = getpass("Enter old password: ");
  bstring _password = bfromcstr(__password);
  char *password = _password->data;
  char *newkeyfile = argv[2];
  char *newPassword = getpass("Enter new password: ");
  // make csr with new private key and password
  // username /password/newpassword/csr
  // write new certificate
  if ((strlen(username) > 32) || (strlen(password) > 32)) {
    printf("input too large: must be 32 or less characters\n");
  }
  char *privatekeyfile = argv[2];
  struct stat filestatus;
  if (stat(privatekeyfile, &filestatus) != 0) {
    fprintf(stderr, "Private key file does not exist\n");
    return 1;
  }
  BIO *keybio = BIO_new_file(privatekeyfile, "r");
  EVP_PKEY *key = NULL;
  key = PEM_read_bio_PrivateKey(keybio, NULL, 0, NULL);
  if (!key) {
    fprintf(stderr, "Error reading private key file\n");
    BIO_free(keybio);
    EVP_PKEY_free(key);
    return 1;
  }
  BIO_free(keybio);
  EVP_PKEY_free(key);
  char *tempfile = "../tmp/temp.txt";
  int pid, wpid;
  int status = 0;
  pid = fork();
  // CHANGE int config and directory
  if (pid == 0) {
    execl("./makecsr.sh", "./makecsr.sh", "../imopenssl.cnf", username, privatekeyfile,
          tempfile, (char *)NULL);
    fprintf(stderr, "execl failed\n");
    return 1;
  }
  if ((wpid = wait(&status)) < 0) exit(1);
  FILE *temp;
  temp = fopen(tempfile, "r+");
  if (!temp) {
    fprintf(stderr, "File open error\n");
    return 1;
  }
  fseek(temp, 0, SEEK_END);
  long fsize1 = ftell(temp);
  fseek(temp, 0, SEEK_SET);

  char *csr = malloc(fsize1 + 1);
  memset(csr, '\0', fsize1 + 1);
  fread(csr, 1, fsize1, temp);
  fclose(temp);
  remove(tempfile);

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
    bdestroy(_password);
    free(newPassword);
    return 0;
  }

  // writing stuff with http
  // GET /HTTP/1.0
  // write to file and give to user.

  // ssl write stuff, new pass
  // ssl read confirm new
  int bytes = (1024 * 1024);
  int port = 4200;
  char *method = "changepw";

  char *buffer = (char *)malloc(sizeof(char) * bytes);

  char header[BUF_SIZE];
  sprintf(header, "post https://localhost:%d/%s HTTP/1.1\n", port, method);
  char *header2 = "connection: close\n";
  char header3[BUF_SIZE];

  char usernameLine[strlen(username) + strlen("username:\n") + 1];
  usernameLine[strlen(username) + strlen("username:\n")] = '\0';
  sprintf(usernameLine, "username:%s\n", username);

  char passwordLine[strlen(password) + strlen("password:\n") + 1];
  passwordLine[strlen(password) + strlen("password:\n")] = '\0';
  sprintf(passwordLine, "password:%s\n", password);

  char newPasswordLine[strlen(newPassword) + strlen("newpassword:\n") + 1];
  newPasswordLine[strlen(newPassword) + strlen("newpassword:\n")] = '\0';
  sprintf(newPasswordLine, "newpassword:%s\n", newPassword);

  bstring encoded = bfromcstr("");
  bstring bkey = bfromcstr("csr");
  bstring bvalue = bfromcstr(csr);
  serializeData(bkey, bvalue, encoded, 1);
  char *encodedCsrLine = encoded->data;
  bdestroy(bkey);
  bdestroy(bvalue);
  //+1 for new line
  int contentLength = strlen(usernameLine) + strlen(passwordLine) +
                      strlen(newPasswordLine) + strlen(encodedCsrLine) + 1;
  sprintf(header3, "content-length: %d\n", contentLength);
  sprintf(buffer, "%s%s%s%s%s%s%s%s%s", header, header2, header3, "\n",
          usernameLine, passwordLine, newPasswordLine, encodedCsrLine, "\n");
  SSL_write(ssl, buffer, strlen(buffer));

  bdestroy(encoded);

  // read buff
  // check for 200 okay
  // if good, read the data (somehow)
  // ask the user for the file they want stored
  // write this data to the file from a buffer
  // output "it is output here"

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
    } else if ((strstr(ibuf, "-1") != NULL) && (state == 0)) {
      printf("Error -1: Bad Username");
      break;
    } else if ((strstr(ibuf, "-2") != NULL) && (state == 0)) {
      printf("Error -2: Wrong Password");
      break;
    } else if ((strstr(ibuf, "-3") != NULL) && (state == 0)) {
      printf("Error -3: Opening file or directory error");
      break;
    } else if ((strstr(ibuf, "-4") != NULL) && (state == 0)) {
      printf("Error -4: Pending message in mailbox. Password not changed.");
      break;
    } else if ((strstr(ibuf, "400") != NULL) && (state == 0)) {
      printf("Error 400: Bad Request");
      break;
    } else if ((state == 1) && (ibuf[0] == '\n')) {
      state = 2;
    } else if ((state == 2) && (ibuf[0] != '\n')) {
      bstring _ibuf = bfromcstr(ibuf);
      bconcat(certif, _ibuf);
      bdestroy(_ibuf);
    } else if ((state == 2) && (ibuf[0] == '\n')) {
      break;
    } else {
      printf("not handled\n");
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
    if (!fp) {
      fprintf(stderr, "File write error\n");
    } else {
      fputs(resultCertif, fp);
      fclose(fp);
      printf("Wrote certification to: %s\n", writePath);
    }
    bdestroy(bkey1);
    bdestroy(bvalue1);
  }

    // Cleanup at the end
  SSL_shutdown(ssl);
  SSL_free(ssl);
  bdestroy(certif);
  free(csr);
  free(buffer);
  close(sock);
  SSL_CTX_free(ctx);
  EVP_cleanup();
  bdestroy(_password);
  free(newPassword);
  return 0;
}
