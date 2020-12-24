#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <regex.h>

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

// usage: send-msg <cert-file> <key-file> <msg-in-file>

int main(int argc, char *argv[]) {
  struct stat st;
  char *certfile, *keyfile, *msginfile, *buffer;
  char *line = NULL;
  size_t size = 0;
  FILE *fp;
  char *r_certfile = "recipient.cert.pem"; 
  char *unsigned_encrypted_file = "unsigned.encrypted.msg";
  char *signed_encrypted_file = "signed.encrypted.msg";

  if (argc != 4) {
    fprintf(stderr, "bad arg count; usage: send-msg <cert-file> <key-file> <msg-in-file>\n");
    return 1;
  }
  certfile = argv[1];
  keyfile = argv[2];
  msginfile = argv[3];


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


  // Read in message from file (limit size to 1 MB)
  if (!(stat(msginfile, &st) == 0 && S_ISREG(st.st_mode) && st.st_size < MB)) {
    fprintf(stderr, "%s\n", msginfile);
    perror("Invalid file");
    return -2;
  }

  fp = fopen(msginfile, "r");
  if (!fp) {
    fprintf(stderr, "%s\n", msginfile);
    perror("File open error");
    return -2;
  }

  regex_t mailfrom;
  if (0 != regcomp(&mailfrom, "^\\.?mail from:<([a-z0-9\\+\\-_]+)>[\r]*\n$", REG_EXTENDED | REG_ICASE)) {
    perror("Regex did not compile successfully");
    fclose(fp);
    return -2;
  }

  // Read sender line
  bstring inp = bgets_limit((bNgetc)fgetc, fp, '\n', MB);
  if (!inp) {
    perror("Invalid message.");
    bdestroy(inp);
    regfree(&mailfrom);
    fclose(fp);
    return -2;
  }
  int ismblong = inp->slen == MB;
  if (ismblong) {
    perror("Invalid message.");
    bdestroy(inp);
    regfree(&mailfrom);
    fclose(fp);
    return -2;
  }
  regmatch_t mailfrommatch[2];
  int mailfromtest = regexec(&mailfrom, (char *)inp->data, 2, mailfrommatch, 0);
  if (mailfromtest == REG_NOMATCH) {
    perror("Invalid message.");
    bdestroy(inp);
    regfree(&mailfrom);
    fclose(fp);
    return -2;
  }
  bdestroy(inp);
  regfree(&mailfrom);
  

  // Read recipient lines
  regex_t rcptto;
  if (regcomp(&rcptto, "^\\.?rcpt to:<([a-z0-9\\+\\-_]+)>[\r]*\n$", REG_EXTENDED | REG_ICASE) != 0) {
    perror("Regex did not compile successfully");
    fclose(fp);
    return -2;
  }

  struct Node *rcpts = createList();
  if (rcpts == NULL) {
    regfree(&rcptto);
    fclose(fp);
    return -2;
  }

  while (1) {
    bstring inp = bgets_limit((bNgetc)fgetc, fp, '\n', MB);
    if (!inp) {
      bdestroy(inp);
      break;
    }
    int ismblong = inp->slen == MB;
    if (ismblong) {
      perror("Invalid message.");
      regfree(&rcptto);
      bdestroy(inp);
      freeList(rcpts);
      fclose(fp);
      return -2;
    }
    regmatch_t rcpttomatch[2];
    int rcpttotest = regexec(&rcptto, (char *)inp->data, 2, rcpttomatch, 0);
    if (rcpttotest == REG_NOMATCH) {
      bdestroy(inp);
      break;
    }
    bstring _rcpt = bmidstr(inp, rcpttomatch[1].rm_so, rcpttomatch[1].rm_eo - rcpttomatch[1].rm_so);
    if (!inList(rcpts, _rcpt)) {
      appendList(&rcpts, _rcpt);
    }
    else {
      bdestroy(_rcpt);
    }
    bdestroy(inp);
  }
  regfree(&rcptto);
  fclose(fp);
  fp = NULL;


  // Encrypt, sign, and send message to each recipient
  struct Node *curr = rcpts;
  int i = 0;
  while (curr != NULL) {
    // TODO: Send recipient name to server /sendto
    bstring r = curr->str;
    if (r == NULL) {
      curr = curr->next;
      continue;
    }
    i++;
    fprintf(stdout, "recipient: %s\n", (char *)r->data);

    // TODO: Server sends back recipient certificate which we write to temp file r_certfile 
    // or do error handling (i.e. `continue`)



    // Encrypt the message with recipient cert and write to temp file unsigned.encrypted.msg
    encryptmsg(r_certfile, msginfile, unsigned_encrypted_file);


    // Sign the encrypted message with the sender's private key and write to temp file signed.encrypted.msg
    signmsg(certfile, keyfile, unsigned_encrypted_file, signed_encrypted_file);
    

    // Read the signed, encrypted message into buffer
    buffer = (char *)malloc(MB);
    *buffer = '\0';
    fp = fopen(signed_encrypted_file, "r");
    if (!fp) {
        fprintf(stderr, "%s\n", signed_encrypted_file);
        perror("File open error");
        free(buffer);
        freeList(rcpts);
        return -3;
    }
    while (0 < getline(&line, &size, fp)) {
      strncat(buffer, line, size);
    }
    free(line);
    line = NULL;
    fclose(fp);


    //  TODO: Send the signed message to the server /msgin
    fprintf(stdout, "%s", buffer);

    free(buffer);
    buffer = NULL;


    //  TODO: Get response back from server
    


    // Delete temp files
    remove(r_certfile);
    remove(unsigned_encrypted_file);
    remove(signed_encrypted_file);
    curr = curr->next;
  }

  freeList(rcpts);
  return 0;
}
