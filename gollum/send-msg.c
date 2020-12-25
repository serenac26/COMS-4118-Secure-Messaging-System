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

#define GETUSERCERT "getusercert"
#define SENDMESSAGE "sendmsg"

#define RCPTTO_REGEX "^\\.?rcpt to:<([a-z0-9\\+\\-_]+)>[\r]*\n$"
#define MAILFROM_REGEX "^\\.?mail from:<([a-z0-9\\+\\-_]+)>[\r]*\n$"

#define READBUF_SIZE 1000
#define WRITEBUF_SIZE 1000

// usage: send-msg <cert-file> <key-file> <msg-in-file>

int verify_callback(int ok, X509_STORE_CTX *ctx) {
  /* Tolerate certificate expiration */
  if (!ok) {
    fprintf(stderr, "verify callback error: %d\n",
            X509_STORE_CTX_get_error(ctx));
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
  struct stat st;
  char *certfile, *keyfile, *msginfile, *buffer, *response;
  char *line = NULL;
  size_t size = 0;
  int sent = 0;
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

    char gucheader[snprintf(0, 0, "post https://localhost:%d/%s HTTP/1.1\n",
                            BOROMAIL_PORT, GETUSERCERT)+1];
    sprintf(gucheader, "post https://localhost:%d/%s HTTP/1.1\n", BOROMAIL_PORT,
            GETUSERCERT);
    char *gucheader2 = "connection: keep-alive\n";
    char gucrecipientLine[snprintf(0, 0, "recipient:%s\n", (char *)r->data)+1];
    sprintf(gucrecipientLine, "recipient:%s\n", (char *)r->data);
    char gucheader3[snprintf(0, 0, "content-length: %ld\n",
                             strlen(gucrecipientLine))+1];
    sprintf(gucheader3, "content-length: %ld\n", strlen(gucrecipientLine));

    // printf("=======\n");
    // printf("%s", gucheader);
    // printf("%s", gucheader2);
    // printf("%s", gucheader3);
    // printf("%s", "\n");
    // printf("%s", gucrecipientLine);
    // printf("=======\n");

    SSL_write(ssl, gucheader, strlen(gucheader));
    SSL_write(ssl, gucheader2, strlen(gucheader2));
    SSL_write(ssl, gucheader3, strlen(gucheader3));
    SSL_write(ssl, "\n", strlen("\n"));
    SSL_write(ssl, gucrecipientLine, strlen(gucrecipientLine));

    // Server sends back recipient certificate which we write to temp file
    // r_certfile
    response = (char *)malloc(MB);
    if (!response) {
      remove(r_certfile);
      curr = curr->next;
      free(response);
      response = NULL;
      continue;
    }
    *response = '\0';
    char code[4];
    int readReturn = SSL_peek(ssl, code, sizeof(code) - 1);
    if (readReturn == 0) {
      remove(r_certfile);
      curr = curr->next;
      free(response);
      response = NULL;
      continue;
    }
    code[sizeof(code) - 1] = '\0';
    int state = 0;
    if (strstr(code, "200") != NULL) {
      while (1) {
        state = 1;
        char buf[2];
        readReturn = SSL_read(ssl, buf, 1);
        buf[1] = '\0';
        if (SSL_pending(ssl) == 0) {
          break;
        }
        sprintf(response + strlen(response), "%s", buf);
      }
    } else if (strstr(code, "-2") != NULL) {
      fprintf(stderr, "Error: Invalid Recipient\n");
      // remove(r_certfile);
      // free(response);
      // response = NULL;
      // curr = curr->next;
      // continue;
    } else if (strstr(code, "-3") != NULL) {
      fprintf(stderr, "Error: Could not retrieve certificate\n");
      // remove(r_certfile);
      // free(response);
      // response = NULL;
      // curr = curr->next;
      // continue;
    }
    
    if ((state == 1) && (response != NULL)) {
      bstring bresponse = bfromcstr(response);
      struct bstrList *lines = bsplit(bresponse, '\n');
      bstring bkey = bfromcstr("");
      bstring bvalue = bfromcstr("");
      if (0 != deserializeData(bkey, bvalue, lines->entry[4], 1)) {
        remove(r_certfile);
        free(response);
        response = NULL;
        bdestroy(bresponse);
        bdestroy(bkey);
        bdestroy(bvalue);
        bstrListDestroy(lines);
        curr = curr->next;
        continue;
      }
      if (0 != bstrccmp(bkey, "certificate")) {
        remove(r_certfile);
        free(response);
        response = NULL;
        bdestroy(bresponse);
        bdestroy(bkey);
        bdestroy(bvalue);
        bstrListDestroy(lines);
        curr = curr->next;
        continue;
      }
      fp = fopen(r_certfile, "w");
      fputs((char *)bvalue->data, fp);
      fclose(fp);
      fp = NULL;
      free(response);
      response = NULL;
      bdestroy(bresponse);
      bdestroy(bkey);
      bdestroy(bvalue);
      bstrListDestroy(lines);
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
    if (!buffer) {
      remove(signed_encrypted_file);
      curr = curr->next;
      continue;
    }
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

    // Send the signed message to the server /sendmsg
    char smheader[snprintf(0, 0, "post https://localhost:%d/%s HTTP/1.1\n",
                           BOROMAIL_PORT, SENDMESSAGE)+1];
    sprintf(smheader, "post https://localhost:%d/%s HTTP/1.1\n", BOROMAIL_PORT,
            SENDMESSAGE);
    char *smheader2 = "connection: keep-alive\n";
    char smrecipientLine[snprintf(0, 0, "recipient:%s\n", (char *)r->data)+1];
    sprintf(smrecipientLine, "recipient:%s\n", (char *)r->data);
    char *smmessageLine = (char *)malloc(MB);
    if (!smmessageLine) {
      fprintf(stderr, "Malloc failed.\n");
      free(buffer);
      buffer = NULL;
      curr = curr->next;
      continue;
    }
    bstring bsmessage = bfromcstr("");
    bstring bsmessagekey = bfromcstr("message");
    bstring bsmessagevalue = bfromcstr(buffer);
    serializeData(bsmessagekey, bsmessagevalue, bsmessage, 1);
    sprintf(smmessageLine, "%s\n", bsmessage->data);
    char smheader3[snprintf(0, 0, "content-length: %ld\n",
                            strlen(smrecipientLine) + strlen(smmessageLine))+1];
    sprintf(smheader3, "content-length: %ld\n",
            strlen(smrecipientLine) + strlen(smmessageLine));

    // fprintf(stdout, "%s%s%s%s%smessage-length: %ld\n%s", smheader, smheader2,
    // smheader3, "\n", smrecipientLine, strlen(smmessageLine), "\n");
    // printf("%s", smheader);
    // printf("%s", smheader2);
    // printf("%s", smheader3);
    // printf("%s", "\n");
    // printf("%s", smrecipientLine);
    // printf("%s", smmessageLine);

    SSL_write(ssl, smheader, strlen(smheader));
    SSL_write(ssl, smheader2, strlen(smheader2));
    SSL_write(ssl, smheader3, strlen(smheader3));
    SSL_write(ssl, "\n", strlen("\n"));
    SSL_write(ssl, smrecipientLine, strlen(smrecipientLine));
    SSL_write(ssl, smmessageLine, strlen(smmessageLine));

    free(smmessageLine);
    bdestroy(bsmessage);
    bdestroy(bsmessagekey);
    bdestroy(bsmessagevalue);

    // Parse response
    char codesm[4];
    readReturn = SSL_peek(ssl, codesm, sizeof(codesm) - 1);
    if (readReturn == 0) {
      break;
    }
    codesm[sizeof(codesm) - 1] = '\0';
    if (strstr(codesm, "200") != NULL) {
      sent++;
    } else if (strstr(codesm, "-3") != NULL) {
      fprintf(stderr, "Error: Could not send message\n");      
    } else if (strstr(codesm, "-4") != NULL) {
      fprintf(stderr, "Error: Mailbox Full\n");      
    } 

    free(buffer);
    buffer = NULL;
    curr = curr->next;
  }

  if (sent > 0) {
    printf("Success: message successfully to %d mailbox(es).\n", sent);
  } else {
    printf("Error: message was not successfully sent to any mailboxes.\n");
  }
  freeList(rcpts);
  close(sock);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  EVP_cleanup();
  return 0;

cleanup:
  if (sent > 0) {
    printf("Partial error: message successfully to %d mailbox(es).\n", sent);
  } else {
    printf("Error: message was not successfully sent to any mailboxes.\n");
  }
  // Cleanup at the end
  close(sock);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  EVP_cleanup();
  return 0;
}
