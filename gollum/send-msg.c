#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bsafe.h"
#include "bstraux.h"
#include "bstrlib.h"
#include "bstrlibext.h"
#include "buniutil.h"
#include "gollumutils.h"
#include "utf8util.h"
#include "utils.h"

#define CA_CHAIN "../ca-chain.cert.pem"
#define RECIPIENT_CERTIFICATE "../tmp/recipient.cert.pem"
#define UNSIGNED_ENCRYPTED_MSG "../tmp/unsigned.encrypted.msg"
#define SIGNED_ENCRYPTED_MSG "../tmp/signed.encrypted.msg"

#define RCPTTO_REGEX "^\\.?rcpt to:<([a-z0-9\\+\\-_]+)>[\r]*\n$"
#define MAILFROM_REGEX "^\\.?mail from:<([a-z0-9\\+\\-_]+)>[\r]*\n$"

#define READBUF_SIZE 1000
#define WRITEBUF_SIZE 1000

// usage: send-msg <cert-file> <key-file> <msg-in-file>

int verify_callback(int ok, X509_STORE_CTX *ctx) {
  /* Tolerate certificate expiration */
  fprintf(stderr, "verify callback error: %d\n", X509_STORE_CTX_get_error(ctx));
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
  struct stat st;
  char *certfile, *keyfile, *msginfile, *buffer, *request;
  char *line = NULL;
  size_t size = 0;
  FILE *fp;
  char *r_certfile = RECIPIENT_CERTIFICATE;
  char *unsigned_encrypted_file = UNSIGNED_ENCRYPTED_MSG;
  char *signed_encrypted_file = SIGNED_ENCRYPTED_MSG;

  if (argc != 4) {
    fprintf(stderr,
            "bad arg count; usage: send-msg <cert-file> <key-file> "
            "<msg-in-file>\n");
    return 1;
  }
  certfile = argv[1];
  keyfile = argv[2];
  msginfile = argv[3];

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
    goto cleanup;
  }

  char rbuf[READBUF_SIZE];
  char wbuf[WRITEBUF_SIZE];

  memset(rbuf, '\0', sizeof(rbuf));
  memset(wbuf, '\0', sizeof(wbuf));
  



  // Read in message from file (limit size to 1 MB)
  if (!(stat(msginfile, &st) == 0 && S_ISREG(st.st_mode) && st.st_size < MB)) {
    fprintf(stderr, "%s\n", msginfile);
    perror("Invalid file");
    return -1;
  }

  fp = fopen(msginfile, "r");
  if (!fp) {
    fprintf(stderr, "%s\n", msginfile);
    perror("File open error");
    return -1;
  }

  regex_t mailfrom;
  if (0 != regcomp(&mailfrom, MAILFROM_REGEX, REG_EXTENDED | REG_ICASE)) {
    perror("Regex did not compile successfully");
    fclose(fp);
    return -1;
  }

  // Read sender line
  bstring inp = bgets_limit((bNgetc)fgetc, fp, '\n', MB);
  if (!inp) {
    perror("Invalid message.");
    bdestroy(inp);
    regfree(&mailfrom);
    fclose(fp);
    return -1;
  }
  int ismblong = inp->slen == MB;
  if (ismblong) {
    perror("Invalid message.");
    bdestroy(inp);
    regfree(&mailfrom);
    fclose(fp);
    return -1;
  }
  regmatch_t mailfrommatch[2];
  int mailfromtest = regexec(&mailfrom, (char *)inp->data, 2, mailfrommatch, 0);
  if (mailfromtest == REG_NOMATCH) {
    perror("Invalid message.");
    bdestroy(inp);
    regfree(&mailfrom);
    fclose(fp);
    return -1;
  }
  bdestroy(inp);
  regfree(&mailfrom);

  // Read recipient lines
  regex_t rcptto;
  if (regcomp(&rcptto, RCPTTO_REGEX, REG_EXTENDED | REG_ICASE) != 0) {
    perror("Regex did not compile successfully");
    fclose(fp);
    return -1;
  }

  struct Node *rcpts = createList();
  if (rcpts == NULL) {
    regfree(&rcptto);
    fclose(fp);
    return -1;
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
      return -1;
    }
    regmatch_t rcpttomatch[2];
    int rcpttotest = regexec(&rcptto, (char *)inp->data, 2, rcpttomatch, 0);
    if (rcpttotest == REG_NOMATCH) {
      bdestroy(inp);
      break;
    }
    bstring _rcpt = bmidstr(inp, rcpttomatch[1].rm_so,
                            rcpttomatch[1].rm_eo - rcpttomatch[1].rm_so);
    if (!inList(rcpts, _rcpt)) {
      appendList(&rcpts, _rcpt);
    } else {
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
    // Send recipient name to server /getusercert
    bstring r = curr->str;
    if (r == NULL) {
      curr = curr->next;
      continue;
    }
    i++;
    // fprintf(stdout, "recipient: %s\n", (char *)r->data);

    
    int bytes = (1024*1024);
    char *method = "getusercert";
    char *request = (char *) malloc(sizeof(char)*bytes);
    
    char header[100];
    sprintf(header, "post https://localhost:%d/%s HTTP/1.1\n", BOROMAIL_PORT, method);
    char *header2 = "connection: close\n"; // TODO: change to keep-alive
    char header3[100];
    char recipientLine[strlen((char *)r->data)+strlen("recipient:\n")+1];
    sprintf(recipientLine, "recipient:%s\n", (char *)r->data);
    sprintf(header3, "content-length: %ld\n", strlen(recipientLine));
    
    sprintf(request, "%s%s%s%s%s%s", header, header2, header3, "\n", recipientLine, "\n");
    fprintf(stdout, "Buffer:\n%s", request);
    SSL_write(ssl, header, strlen(header));
    SSL_write(ssl, header2, strlen(header2));
    SSL_write(ssl, header3, strlen(header3));
    SSL_write(ssl, "\n", strlen("\n"));
    SSL_write(ssl, recipientLine, strlen(recipientLine));
    SSL_write(ssl, "\n", strlen("\n"));
    free(request);
    request = NULL;


    // Server sends back recipient certificate which we write to temp file r_certfile 
    // Error handling:
      // remove(r_certfile);
      // curr = curr->next;
      // continue;
    char *response = (char *)malloc(MB);
    if (!response) {
      remove(r_certfile);
      curr = curr->next;
      free(response);
      response = NULL;
      continue;
    }
    *response = '\0';
    char code[4];
    int readReturn = SSL_peek(ssl, code, sizeof(code)-1);
    if (readReturn == 0) {
      break;
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
        remove(r_certfile);
        curr = curr->next;
        free(response);
        response = NULL;
        bdestroy(bresponse);
        bdestroy(bkey);
        bdestroy(bvalue);
        freeList(lines);
        continue;
      }
      if (0 != bstrccmp(bkey, "certificate")) {
        remove(r_certfile);
        curr = curr->next;
        free(response);
        response = NULL;
        bdestroy(bresponse);
        bdestroy(bkey);
        bdestroy(bvalue);
        freeList(lines);
        continue;
      }
      fp = fopen(r_certfile, "w");
      fputs((char *)bvalue->data, fp);
      fclose(fp);
      fp = NULL;
      bdestroy(bresponse);
      bdestroy(bkey);
      bdestroy(bvalue);
      bstrListDestroy(lines);
      printf("Wrote certificate to: %s\n", r_certfile);
    }


    // Encrypt the message with recipient cert and write to temp file
    // unsigned.encrypted.msg
    if (0 != encryptmsg(r_certfile, msginfile, unsigned_encrypted_file)) {
      remove(r_certfile);
      remove(unsigned_encrypted_file);
      curr = curr->next;
      continue;
    }
    remove(r_certfile);

    // Sign the encrypted message with the sender's private key and write to
    // temp file signed.encrypted.msg
    if (0 != signmsg(certfile, keyfile, unsigned_encrypted_file,
                     signed_encrypted_file)) {
      remove(unsigned_encrypted_file);
      remove(signed_encrypted_file);
      curr = curr->next;
      continue;
    }
    remove(unsigned_encrypted_file);

    // Read the signed, encrypted message into buffer
    buffer = (char *)malloc(MB);
    *buffer = '\0';
    fp = fopen(signed_encrypted_file, "r");
    if (!fp) {
      fprintf(stderr, "File open error: %s\n", signed_encrypted_file);
      remove(signed_encrypted_file);
      free(buffer);
      buffer = NULL;
      curr = curr->next;
      continue;
    }
    while (0 < getline(&line, &size, fp)) {
      strncat(buffer, line, size);
    }
    free(line);
    line = NULL;
    fclose(fp);
    fp = NULL;
    remove(signed_encrypted_file);


    // TODO: Send the signed message to the server /msgin
    // int bytes = (1024*1024);
    // char *method = "getusercert";
    // *request = (char *) malloc(sizeof(char)*bytes);
    
    // char header[100];
    // sprintf(header, "post https://localhost:%d/%s HTTP/1.1\n", BOROMAIL_PORT, method);
    // char *header2 = "connection: close\n"; // TODO: change to keep-alive
    // char header3[100];
    // char recipientLine[strlen((char *)r->data)+strlen("recipient:\n")+1];
    // sprintf(recipientLine, "recipient:%s\n", (char *)r->data);
    // sprintf(header3, "content-length: %ld\n", strlen(recipientLine));
    
    // sprintf(buffer, "%s%s%s%s%s%s", header, header2, header3, "\n", recipientLine, "\n");
    // fprintf(stdout, "Buffer:\n%s", buffer);
    // SSL_write(ssl, buffer, strlen(buffer));
    
    // TODO: Check if curr->next == NULL and close connection with server
    // Error handling:
      // freeList(rcpts);
      // return -1;
    fprintf(stdout, "%s", buffer);

    // TODO: Get response back from server
    // Error handling:
    // free(buffer);
    // buffer = NULL;
    // curr = curr->next;
    // continue;

    free(buffer);
    buffer = NULL;
    curr = curr->next;
  }

  freeList(rcpts);

cleanup:
  // Cleanup at the end
  close(sock);
  SSL_CTX_free(ctx);
  EVP_cleanup();
  return 0;
}
