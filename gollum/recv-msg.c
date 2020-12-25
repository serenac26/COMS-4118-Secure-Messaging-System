#include <stdio.h>
#include <strings.h>
#include <string.h>
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

// usage: recv-msg <cert-file> <key-file> <msg-out-file>

int main(int argc, char *argv[]) {
  struct stat st;
  char *certfile, *keyfile, *msgoutfile, *buffer;
  char *line = NULL;
  size_t size = 0;
  FILE *fp;
  char *s_certfile = "sender.cert.pem"; 
  char *unsigned_encrypted_file = "unsigned.encrypted.msg";
  char *unsigned_decrypted_file = "unsigned.decrypted.msg";
  char *signed_encrypted_file = "signed.encrypted.msg";

  if (argc != 4) {
    fprintf(stderr, "bad arg count; usage: recv-msg <cert-file> <key-file> <msg-out-file>\n");
    return 1;
  }
  certfile = argv[1];
  keyfile = argv[2];
  msgoutfile = argv[3];

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


  // TODO: Get signed encrypted message from server and write to temp file signed.encrypted.msg
  // Error handling:
      // return -1;


  // Get encrypted message from signed.encrypted.msg without verifying and write to temp file unsigned.encrypted.msg
  if (0 != verifyunsign(signed_encrypted_file, unsigned_encrypted_file)) {
    // remove(signed_encrypted_file);
    remove(unsigned_encrypted_file);
    return -1;
  }


  // Decrypt unsigned.encrypted.msg using recipient's private key and write to temp file unsigned.decrypted.msg
  if (0 != decryptmsg(certfile, keyfile, unsigned_encrypted_file, unsigned_decrypted_file)) {
    // remove(signed_encrypted_file);
    remove(unsigned_encrypted_file);
    remove(unsigned_decrypted_file);
    return -1;
  }
  remove(unsigned_encrypted_file);


  // Get sender name from unsigned.decrypted.msg header
  fp = fopen(unsigned_decrypted_file, "r");
  if (!fp) {
    fprintf(stderr, "%s\n", unsigned_decrypted_file);
    perror("File open error");
    remove(unsigned_decrypted_file);
    // remove(signed_encrypted_file);
    return -1;
  }

  regex_t mailfrom;
  if (0 != regcomp(&mailfrom, "^\\.?mail from:<([a-z0-9\\+\\-_]+)>[\r]*\n$", REG_EXTENDED | REG_ICASE)) {
    perror("Regex did not compile successfully");
    regfree(&mailfrom);
    fclose(fp);
    remove(unsigned_decrypted_file);
    // remove(signed_encrypted_file);
    return -1;
  }

  bstring inp = bgets_limit((bNgetc)fgetc, fp, '\n', MB);
  if (!inp) {
    perror("Invalid message.");
    bdestroy(inp);
    regfree(&mailfrom);
    fclose(fp);
    remove(unsigned_decrypted_file);
    // remove(signed_encrypted_file);
    return -1;
  }
  int ismblong = inp->slen == MB;
  if (ismblong) {
    perror("Invalid message.");
    bdestroy(inp);
    regfree(&mailfrom);
    fclose(fp);
    remove(unsigned_decrypted_file);
    // remove(signed_encrypted_file);
    return -1;
  }
  regmatch_t mailfrommatch[2];
  int mailfromtest = regexec(&mailfrom, (char *)inp->data, 2, mailfrommatch, 0);
  if (mailfromtest == REG_NOMATCH) {
    perror("Invalid message.");
    bdestroy(inp);
    regfree(&mailfrom);
    fclose(fp);
    remove(unsigned_decrypted_file);
    // remove(signed_encrypted_file);
    return -1;
  }
  bstring sender = bmidstr(inp, mailfrommatch[1].rm_so, mailfrommatch[1].rm_eo - mailfrommatch[1].rm_so);
  bdestroy(inp);
  regfree(&mailfrom);
  fclose(fp);
  remove(unsigned_decrypted_file);


  // TODO: Send sender name to server /getusercert



  // TODO: Get sender cert and write to temp file sender.cert.pem
  // Error handling:
    // remove(signed_encrypted_file);
    // remove(s_certfile);
    // bdestroy(sender);
    // return -1;


  // TODO: Close connection with server
  // Error handling:
    // remove(signed_encrypted_file);
    // remove(s_certfile);
    // bdestroy(sender);
    // return -1;


  // Verify sender of signed-message using sender.cert.pem and 
  // write the decrypted message to the specified output file
  if (0 != verifysign(s_certfile, signed_encrypted_file, msgoutfile)) {
    // remove(signed_encrypted_file);
    // remove(s_certfile);
    bdestroy(sender);
    return -1;
  }

  // remove(signed_encrypted_file);
  // remove(s_certfile);
  bdestroy(sender);
  return 0;
}
