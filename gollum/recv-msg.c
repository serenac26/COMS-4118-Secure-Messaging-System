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

#define CA_CHAIN "../ca-chain.cert.pem"
#define SENDER_CERTIFICATE "../tmp/sender.cert.pem"
#define UNSIGNED_ENCRYPTED_MSG "../tmp/unsigned.encrypted.msg"
#define UNSIGNED_DECRYPTED_MSG "../tmp/unsigned.decrypted.msg"
#define SIGNED_ENCRYPTED_MSG "../tmp/signed.encrypted.msg"

#define GETUSERCERT "getusercert"
#define RECEIVEMESSAGE "receivemessage"

#define MAILFROM_REGEX "^\\.?mail from:<([a-z0-9\\+\\-_]+)>[\r]*\n$"

#define READBUF_SIZE 1000
#define WRITEBUF_SIZE 1000

// usage: recv-msg <cert-file> <key-file> <msg-out-file>

int verify_callback(int ok, X509_STORE_CTX *ctx) {
  /* Tolerate certificate expiration */
  if (!ok) {
    fprintf(stderr, "verify callback error: %d\n", X509_STORE_CTX_get_error(ctx));
  }
  /* Otherwise don't override */
  return ok;
}

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

int main(int argc, char *argv[]) {
  char *certfile, *keyfile, *msgoutfile, *response;
  FILE *fp;
  char *s_certfile = SENDER_CERTIFICATE; 
  char *unsigned_encrypted_file = UNSIGNED_ENCRYPTED_MSG;
  char *unsigned_decrypted_file = UNSIGNED_DECRYPTED_MSG;
  char *signed_encrypted_file = SIGNED_ENCRYPTED_MSG;

  if (argc != 4) {
    fprintf(stderr, "bad arg count; usage: recv-msg <cert-file> <key-file> <msg-out-file>\n");
    return 1;
  }
  certfile = argv[1];
  keyfile = argv[2];
  msgoutfile = argv[3];


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

  if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // TODO: need to input password
  if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  

  if (SSL_CTX_load_verify_locations(ctx, CA_CHAIN, NULL) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  

  SSL_CTX_set_verify(ctx,
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                         SSL_VERIFY_CLIENT_ONCE,
                     verify_callback);
  /* Set the verification depth to 1 */
  
  SSL_CTX_set_verify_depth(ctx, 1);

  int sock = create_socket(6969);

  SSL *ssl = SSL_new(ctx);

  SSL_set_fd(ssl, sock);
  

  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
  }

  char rbuf[READBUF_SIZE];
  char wbuf[WRITEBUF_SIZE];

  memset(rbuf, '\0', sizeof(rbuf));
  memset(wbuf, '\0', sizeof(wbuf));
  

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
  if (0 != regcomp(&mailfrom, MAILFROM_REGEX, REG_EXTENDED | REG_ICASE)) {
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


  // Send sender name to server /getusercert

    char gucheader[snprintf(0, 0, "post https://localhost:%d/%s HTTP/1.1\n", BOROMAIL_PORT, GETUSERCERT)];
    sprintf(gucheader, "post https://localhost:%d/%s HTTP/1.1\n", BOROMAIL_PORT, GETUSERCERT);
    char *gucheader2 = "connection: keep-alive\n";
    char gucrecipientLine[snprintf(0, 0, "recipient:%s\n", (char *)sender->data)];
    sprintf(gucrecipientLine, "recipient:%s\n", (char *)sender->data);
    char gucheader3[snprintf(0, 0, "content-length: %ld\n", strlen(gucrecipientLine))];
    sprintf(gucheader3, "content-length: %ld\n", strlen(gucrecipientLine));
    
    SSL_write(ssl, gucheader, strlen(gucheader));
    SSL_write(ssl, gucheader2, strlen(gucheader2));
    SSL_write(ssl, gucheader3, strlen(gucheader3));
    SSL_write(ssl, "\n", strlen("\n"));
    SSL_write(ssl, gucrecipientLine, strlen(gucrecipientLine));
    SSL_write(ssl, "\n", strlen("\n"));


    // Server sends back recipient certificate which we write to temp file s_certfile 
    response = (char *)malloc(MB);
    if (!response) {
      remove(s_certfile);
      bdestroy(sender);
      free(response);
      response = NULL;
      return -1;
    }
    *response = '\0';
    char code[4];
    int readReturn = SSL_peek(ssl, code, sizeof(code)-1);
    if (readReturn == 0) {
      remove(s_certfile);
      bdestroy(sender);
      free(response);
      response = NULL;
      return -1;
    }
    code[sizeof(code)-1] = '\0';
    int state = 0;
    while ((strstr(code, "200") != NULL)) {
      state = 1;
      char buf[2];
      readReturn = SSL_read(ssl, buf, 1);
      buf[1] = '\0';
      if (readReturn == 0) {
        break;
      }
      sprintf(response+strlen(response), "%s", buf);
    }
    if ((state == 1) && (response != NULL)) {
      bstring bresponse = bfromcstr(response);
      struct bstrList *lines = bsplit(bresponse, '\n');
      bstring bkey = bfromcstr("");
      bstring bvalue = bfromcstr("");
      if (0 != deserializeData(bkey, bvalue, lines->entry[4], 1)) {
        remove(s_certfile);
        free(response);
        response = NULL;
        bdestroy(bresponse);
        bdestroy(bkey);
        bdestroy(bvalue);
        bstrListDestroy(lines);
        bdestroy(sender);
        return -1;
      }
      if (0 != bstrccmp(bkey, "certificate")) {
        remove(s_certfile);
        free(response);
        response = NULL;
        bdestroy(bresponse);
        bdestroy(bkey);
        bdestroy(bvalue);
        bstrListDestroy(lines);
        bdestroy(sender);
        return -1;
      }
      fp = fopen(s_certfile, "w");
      fputs((char *)bvalue->data, fp);
      fclose(fp);
      fp = NULL;
      free(response);
      response = NULL;
      bdestroy(bresponse);
      bdestroy(bkey);
      bdestroy(bvalue);
      bstrListDestroy(lines);
      printf("Wrote certificate to: %s\n", s_certfile);
    }


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

  // Cleanup at the end
  close(sock);
  SSL_CTX_free(ctx);
  EVP_cleanup();
  return 0;
}
