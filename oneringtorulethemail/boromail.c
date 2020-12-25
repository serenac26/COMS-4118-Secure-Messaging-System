#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "boromailutils.h"
#include "bsafe.h"
#include "bstraux.h"
#include "bstrlib.h"
#include "bstrlibext.h"
#include "buniutil.h"
#include "utf8util.h"
#include "utils.h"

#define DEBUG 1
#define READBUF_SIZE 1000
#define WRITEBUF_SIZE 1000
#define ERR_TOO_LONG "One or more of your fields were too loooooooooong\n"
#define ERR_INVALID_LINE "Unexpected line encountered\n"
#define ERR_MISSING_CONTENT_LENGTH "Content length must be supplied\n"
#define ERR_INVALID_CONTENT_LENGTH "Content length must be a number\n"
#define ERR_INVALID_CONNECTION_VALUE \
  "Connection must be either close or keep-alive\n"
#define ERR_INSUFFICIENT_CONTENT_SENT \
  "Send more content you stingy fuck nOoo~ you're so sexy aha 😘\n"
#define ERR_ABUNDANT_CONTENT_SENT \
  "Send less content you liberal fuck nOoo~ you're so sexy aha 😘\n"
#define ERR_MALFORMED_REQUEST "Your request body was malformed\n"

#define ERR_NO_MSG (-1)
#define ERR_INVALID_RCPT (-2)
#define ERR_OPEN (-3)
#define ERR_MAILBOX_FULL (-4)

#define KEYPASS "pass"

#define pb(...)           \
  if (DEBUG) {            \
    printf("\033[0;32m"); \
    printf("Boromail: "); \
    printf(__VA_ARGS__);  \
    printf("\033[0m");    \
  }

struct VerbLine {
  char verb[5];
  char port[10];
  char path[100];
  char version[10];
};

struct OptionLine {
  char header[50];
  char value[50];
};

/*
 * Writes the action requested to buf
 * ===
 * 2 match too LOOONG
 * 1 no match found
 * 0 match found and action written to buf
 */
int parseVerbLine(char *data, struct VerbLine *vl) {
  regex_t reg;
  int value;

  value = regcomp(&reg,
                  "(post|get) https://[a-z0-9.]+(:([0-9]+))*([^[:space:]]+) "
                  "([^[:space:]]+)\n",
                  REG_EXTENDED | REG_ICASE);
  if (value != 0) {
    pb("Regex did not compile successfully\n");
  }
  regmatch_t match[6];
  int test = regexec(&reg, data, 6, match, 0);

  regfree(&reg);

  if (test == REG_NOMATCH)
    return 1;
  else if (match[1].rm_eo - match[1].rm_so >= sizeof(vl->verb))
    return 2;
  else if (match[3].rm_eo - match[3].rm_so >= sizeof(vl->port))
    return 2;
  else if (match[4].rm_eo - match[4].rm_so >= sizeof(vl->path))
    return 2;
  else if (match[5].rm_eo - match[5].rm_so >= sizeof(vl->version))
    return 2;

  memset(vl->verb, '\0', sizeof(vl->verb));
  memset(vl->port, '\0', sizeof(vl->port));
  memset(vl->path, '\0', sizeof(vl->path));
  memset(vl->version, '\0', sizeof(vl->version));

  for (int i = 0; i < match[1].rm_eo - match[1].rm_so; i++) {
    int j = i + match[1].rm_so;
    vl->verb[i] = data[j];
  }

  for (int i = 0; i < match[3].rm_eo - match[3].rm_so; i++) {
    int j = i + match[3].rm_so;
    vl->port[i] = data[j];
  }

  for (int i = 0; i < match[4].rm_eo - match[4].rm_so; i++) {
    int j = i + match[4].rm_so;
    vl->path[i] = data[j];
  }

  for (int i = 0; i < match[5].rm_eo - match[5].rm_so; i++) {
    int j = i + match[5].rm_so;
    vl->version[i] = data[j];
  }
  
  return 0;
}

/*
 * Writes the option line requested to buf
 * Unlike specified in
 * https://www.cs.columbia.edu/~smb/classes/f20/Files/simple-http.html Looks for
 * a semicolon
 * ===
 * 2 match too LOOONG
 * 1 no match found
 * 0 match found and action written to buf
 */
int parseOptionLine(char *data, struct OptionLine *ol) {
  regex_t reg;
  int value;

  value = regcomp(&reg,
                  "[[:space:]]*(.*)[[:space:]]*:[[:space:]]*(.*)[[:space:]]*\n",
                  REG_EXTENDED | REG_ICASE);
  if (value != 0) {
    pb("Regex did not compile successfully\n");
  }
  regmatch_t match[3];
  int test = regexec(&reg, data, 3, match, 0);

  regfree(&reg);

  if (test == REG_NOMATCH)
    return 1;
  else if (match[1].rm_eo - match[1].rm_so >= sizeof(ol->header))
    return 2;
  else if (match[2].rm_eo - match[2].rm_so >= sizeof(ol->value))
    return 2;

  memset(ol->header, '\0', sizeof(ol->header));
  memset(ol->value, '\0', sizeof(ol->value));

  for (int i = 0; i < match[1].rm_eo - match[1].rm_so; i++) {
    int j = i + match[1].rm_so;
    ol->header[i] = data[j];
  }

  for (int i = 0; i < match[2].rm_eo - match[2].rm_so; i++) {
    int j = i + match[2].rm_so;
    ol->value[i] = data[j];
  }

  return 0;
}

/*
 * Writes the option line requested to buf
 * Unlike specified in
 * https://www.cs.columbia.edu/~smb/classes/f20/Files/simple-http.html Looks for
 * a semicolon
 * ===
 * 1 no match found
 * 0 match found and written to result
 */
int parseSubject(char *data, bstring result) {
  regex_t reg;
  int value;

  value = regcomp(&reg, ".*/CN=(.*)",
                  REG_EXTENDED | REG_ICASE);
  if (value != 0) {
    pb("Regex did not compile successfully\n");
  }
  regmatch_t match[2];
  int test = regexec(&reg, data, 2, match, 0);

  regfree(&reg);

  if (test == REG_NOMATCH) return 1;

  bstring bdata = bfromcstr(data);
  bstring _result =
      bmidstr(bdata, match[1].rm_so, match[1].rm_eo - match[1].rm_so);
  bdestroy(bdata);
  bassign(result, _result);
  bdestroy(_result);

  return 0;
}

int create_socket(int port) {
  int s;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
  }

  if (listen(s, 1) < 0) {
    perror("Unable to listen");
    exit(EXIT_FAILURE);
  }

  return s;
}

int verify_callback(int ok, X509_STORE_CTX *ctx) {
  /* Tolerate certificate expiration */
  pb("verify callback error: %d\n", X509_STORE_CTX_get_error(ctx));
  /* Otherwise don't override */
  return ok;
}

void testParsers(int mama, char **moo) {
  struct VerbLine vl;
  char *yeet = "post https://www.rbbridge.com:8080/sendmsg/goodgod HTTP/1.1";
  int result = parseVerbLine(yeet, &vl);
  pb("%d %s\n", result, vl.verb);
  pb("%d %s\n", result, vl.port);
  pb("%d %s\n", result, vl.path);
  pb("%d %s\n", result, vl.version);

  struct OptionLine ol;
  char *yeet2 = "connection: keep-alive";
  int result2 = parseOptionLine(yeet2, &ol);
  pb("%d %s\n", result2, ol.header);
  pb("%d %s\n", result2, ol.value);
}

// these do not necessarily need to be in their own function but they are
// temporarily for compilation

int handleGetUserCert(char *cert, bstring recipient) {
  int ret = getusercert(cert, recipient);
  if (ret == 1) {
    return ERR_INVALID_RCPT;
  } else if (ret == 2) {
    return ERR_OPEN;
  }
  return 0;
}

int handleSendMsg(bstring recipient, bstring msg) {
  int ret = sendmessage(recipient, msg);
  if (ret == -1) {
    return ERR_OPEN;
  } else if (ret == -2) {
    return ERR_MAILBOX_FULL;
  }
  return 0;
}

// msg must be free()d by caller
// char *msg;
// handleRecvMsg(recipient, &msg);
int handleRecvMsg(bstring recipient, char **msg) {
  bstring filename = bfromcstr("");
  if (getOldestFilename(recipient, filename) == -1) {
    fprintf(stderr, "No message to receive\n");
    return ERR_NO_MSG;
  }
  int ret = recvmessage(filename, msg);
  if (ret == -1) {
    return ERR_OPEN;
  }
  return 0;
}
// free(msg);

void sendGood(SSL *ssl, int connection, void *content, int code) {
  bstring toSend = bformat("%d OK\nconnection: %s\ncontent-length: %d\n\n%s\n",
                           code, connection == 2 ? "close" : "keep-alive",
                           strlen(content) + 1, content);
  SSL_write(ssl, toSend->data, toSend->slen);
  bdestroy(toSend);
}

void sendBad(SSL *ssl, void *content) {
  bstring toSend =
      bformat("400 Bad Request \nconnection: close\ncontent-length: %d\n\n%s\n",
              strlen(content) + 1, content);
  SSL_write(ssl, toSend->data, toSend->slen);
  bdestroy(toSend);
}

int pw_cb(char *buf, int size, int rwflag, void *u)
{
  strncpy(buf, (char *)u, size);
  buf[size - 1] = '\0';
  return strlen(buf);
}

// Refer to:
// http://h30266.www3.hpe.com/odl/axpos/opsys/vmsos84/BA554_90007/ch04s03.html
// and https://wiki.openssl.org/index.php/Simple_TLS_Server for more information
int main(int mama, char **moo) {
  SSL_library_init();       /* load encryption & hash algorithms for SSL */
  SSL_load_error_strings(); /* load the error strings for good error reporting
                             */

  // TLSv1_1_server_method is deprecated
  // Can switch back if inconvenient
  const SSL_METHOD *mamamethod = TLS_server_method();
  SSL_CTX *ctx = SSL_CTX_new(mamamethod);

  // Only accept the LATEST and GREATEST in TLS
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

  SSL_CTX_set_default_passwd_cb(ctx, pw_cb);
  SSL_CTX_set_default_passwd_cb_userdata(ctx, KEYPASS);

  if (SSL_CTX_use_certificate_file(ctx,
                                   "../ca/intermediate/certs/boromail.cert.pem",
                                   SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx,
                                  "../ca/intermediate/private/boromail.key.pem",
                                  SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_load_verify_locations(
          ctx, "../ca/intermediate/certs/ca-chain.cert.pem", NULL) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  SSL_CTX_set_client_CA_list(
      ctx,
      SSL_load_client_CA_file("../ca/intermediate/certs/ca-chain.cert.pem"));

  SSL_CTX_set_verify(ctx,
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                         SSL_VERIFY_CLIENT_ONCE,
                     verify_callback);
  /* Set the verification depth to 1 */
  SSL_CTX_set_verify_depth(ctx, 1);

  int sock = create_socket(6969);

  while (1) {
    struct sockaddr_in addr;
    uint len = sizeof(addr);
    SSL *ssl = SSL_new(ctx);

    int client = accept(sock, (struct sockaddr *)&addr, &len);

    if (client < 0) {
      perror("Unable to accept");
      exit(EXIT_FAILURE);
    }

    pb("Connection from %x, port %x\n", addr.sin_addr.s_addr, addr.sin_port);

    SSL_set_fd(ssl, client);

    if (SSL_accept(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      SSL_shutdown(ssl);
      SSL_free(ssl);
      close(client);
      continue;
    }

    char rbuf[READBUF_SIZE];
    char wbuf[WRITEBUF_SIZE];

    memset(rbuf, '\0', sizeof(rbuf));
    memset(wbuf, '\0', sizeof(wbuf));

    /*
     * Welcome to state shenanigans part 3
     * ===
     * 0  Expecting <verb> <url> <version>
     * 1  Expecting <option-lines> or <newline>
     * 2  Expecting data
     */
    int state = 0;

    /*
     * Only one verb line
     */
    struct VerbLine vl;

    /*
     * Set by a verb line
     * ===
     * -1 Unset
     * 1 Get
     * 2 Post
     */
    int action = -1;

    /*
     * Set by an option line
     * ===
     * -1 Unset
     */
    int contentLength = -1;

    /*
     * Set by an option line. Default to close
     * ===
     * 1 keep-alive
     * 2 close
     */
    int connection = 2;

    char *data;

    while (1) {
      memset(rbuf, '\0', sizeof(rbuf));
      int readReturn = 0;
      while (readReturn < sizeof(rbuf) - 1) {
        int i = SSL_read(ssl, rbuf + readReturn++, 1);
        if (i == 0) readReturn--;
        if (i != 1 || rbuf[readReturn - 1] == '\n') break;
      }
      pb("state: %d bytes-read: %d line: %s\n", state, readReturn, rbuf);
      if (readReturn <= 0) {
        pb("error: %d %d\n", SSL_get_error(ssl, readReturn), errno);
        break;
      } else if (readReturn == sizeof(rbuf) - 1 && state != 2) {
        SSL_write(ssl, ERR_TOO_LONG, strlen(ERR_TOO_LONG));
        break;
      } else if (state == 0) {
        int result = parseVerbLine(rbuf, &vl);
        if (result == 2) {
          SSL_write(ssl, ERR_TOO_LONG, strlen(ERR_TOO_LONG));
          break;
        } else if (result == 1) {
          SSL_write(ssl, ERR_INVALID_LINE, strlen(ERR_INVALID_LINE));
          break;
        } else {
          if (strcmp(vl.verb, "post") == 0)
            action = 2;
          else
            action = 1;
          state = 1;
        }
      } else if (state == 1) {
        struct OptionLine ol;
        int result = parseOptionLine(rbuf, &ol);

        if (result == 2) {
          SSL_write(ssl, ERR_TOO_LONG, strlen(ERR_TOO_LONG));
          break;
        } else if (result == 1) {
          if (strlen(rbuf) == 1 && rbuf[0] == '\n')
            state = 2;
          else {
            SSL_write(ssl, ERR_INVALID_LINE, strlen(ERR_INVALID_LINE));
            break;
          }
        } else if (strcmp(ol.header, "content-length") == 0) {
          int invalidContentLengthFound = 0;
          for (int i = 0; i < strlen(ol.value); i++) {
            if (!isdigit(ol.value[i])) {
              invalidContentLengthFound = 1;
              break;
            }
          }

          if (invalidContentLengthFound) {
            SSL_write(ssl, ERR_INVALID_CONTENT_LENGTH,
                      strlen(ERR_INVALID_CONTENT_LENGTH));
            break;
          }

          // atoi does no error checking. may need to use another function
          int parsedContentLength = atoi(ol.value);
          contentLength = parsedContentLength;
        } else if (strcmp(ol.header, "connection") == 0) {
          if (strcmp(ol.value, "keep-alive") == 0)
            connection = 1;
          else if (strcmp(ol.value, "close") == 0)
            connection = 2;
          else {
            SSL_write(ssl, ERR_INVALID_CONNECTION_VALUE,
                      strlen(ERR_INVALID_CONNECTION_VALUE));
            break;
          }
        }
      } else if (state == 2) {
        if (contentLength == -1) {
          SSL_write(ssl, ERR_MISSING_CONTENT_LENGTH,
                    strlen(ERR_MISSING_CONTENT_LENGTH));
          break;
        }

        data = (char *)malloc(contentLength + 1);
        memset(data, '\0', contentLength);

        // pb("%ld %ld %s\n", strlen(rbuf), sizeof(rbuf), rbuf);
        memcpy(data, rbuf, strlen(rbuf));
        int contentReceived = strlen(rbuf);

        while (contentReceived < contentLength) {
          memset(rbuf, '\0', sizeof(rbuf));
          readReturn = SSL_read(ssl, rbuf, sizeof(rbuf) - 1);
          if (readReturn == 0)
            break;
          else {
            memcpy(data + contentReceived, rbuf, strlen(rbuf));
            contentReceived += readReturn;
          }
        }

        if (contentReceived < contentLength) {
          SSL_write(ssl, ERR_INSUFFICIENT_CONTENT_SENT,
                    strlen(ERR_INSUFFICIENT_CONTENT_SENT));
          break;
        } else if (contentReceived > contentLength) {
          SSL_write(ssl, ERR_ABUNDANT_CONTENT_SENT,
                    strlen(ERR_ABUNDANT_CONTENT_SENT));
          break;
        }

        data[contentLength] = '\0';

        /*
         * TODO: We write the shit to handle the finished request here
         *
         * state
         * ===
         * 0  Expecting <verb> <url> <version>
         * 1  Expecting <option-lines> or <newline>
         * 2  Expecting data
         *
         * action
         * ===
         * -1 Unset
         * 1 Get
         * 2 Post
         *
         * contentLength
         * ===
         * -1 Unset
         *
         * connection
         * ===
         * 1 keep-alive
         * 2 close
         *
         * data
         * ===
         * Stores the data received
         *
         * Examples:
         * ===
         get https://fuck:443/fuckity fuck
         connection: close
         content-length: 5

         yeet

         * ===
         get https://fuck:443/fuckity fuck
         connection: keep-alive
         content-length: 5

         yeet

         */
        pb("state: %d\naction: %d\ncontentLength: %d\nconnection: %d\n%s\n",
           state, action, contentLength, connection, data);

        bstring bdata = bfromcstr(data);

        int code = 200;

        bstring path = bfromcstr(vl.path);
        if (action == 2 && bstrccmp(path, "/getusercert") == 0) {
          struct bstrList *lines = bsplit(bdata, '\n');
          if (lines->qty != 2) {
            SSL_write(ssl, ERR_MALFORMED_REQUEST,
                      strlen(ERR_MALFORMED_REQUEST));
            bstrListDestroy(lines);
            connection = 2;
            goto cleanup;
          }
          bstring recipientkey = bfromcstr("");
          bstring recipientvalue = bfromcstr("");
          if (deserializeData(recipientkey, recipientvalue, lines->entry[0],
                              0) != 0 ||
              bstrccmp(recipientkey, "recipient") != 0) {
            SSL_write(ssl, ERR_MALFORMED_REQUEST,
                      strlen(ERR_MALFORMED_REQUEST));
            bdestroy(recipientkey);
            bdestroy(recipientvalue);
            bstrListDestroy(lines);
            connection = 2;
            goto cleanup;
          }
          char cert[MAX_CERT_SIZE];
          memset(cert, '\0', sizeof(cert));
          int r;
          if ((r = handleGetUserCert(cert, recipientvalue)) != 0) {
            bstring err = bformat("Handler returned with error %d\n", r);
            sendBad(ssl, err->data);
            bdestroy(err);
            bdestroy(recipientkey);
            bdestroy(recipientvalue);
            bstrListDestroy(lines);
            connection = 2;
            goto cleanup;
          }

          bstring certKey = bfromcstr("certificate");
          bstring certValue = bfromcstr(cert);
          bstring certData = bfromcstr("");
          if (serializeData(certKey, certValue, certData, 1) != 0) {
            bdestroy(certKey);
            bdestroy(certValue);
            bdestroy(certData);
            sendBad(ssl, ERR_MALFORMED_REQUEST);
            connection = 2;
            goto cleanup;
          };
          bdestroy(certKey);
          bdestroy(certValue);
          sendGood(ssl, 2, certData->data, code);
          bdestroy(certData);
        } else if (action == 2 && bstrccmp(path, "/sendmsg") == 0) {
          struct bstrList *lines = bsplit(bdata, '\n');
          if (lines->qty != 3) {
            SSL_write(ssl, ERR_MALFORMED_REQUEST,
                      strlen(ERR_MALFORMED_REQUEST));
            bstrListDestroy(lines);
            connection = 2;
            goto cleanup;
          }
          bstring recipientkey = bfromcstr("");
          bstring recipientvalue = bfromcstr("");
          bstring messagekey = bfromcstr("");
          bstring messagevalue = bfromcstr("");

          if (deserializeData(recipientkey, recipientvalue, lines->entry[0],
                              0) != 0 ||
              deserializeData(messagekey, messagevalue, lines->entry[1], 1) !=
                  0 ||
              bstrccmp(recipientkey, "recipient") != 0 ||
              bstrccmp(messagekey, "message") != 0) {
            SSL_write(ssl, ERR_MALFORMED_REQUEST,
                      strlen(ERR_MALFORMED_REQUEST));
            bdestroy(recipientkey);
            bdestroy(recipientvalue);
            bdestroy(messagekey);
            bdestroy(messagevalue);
            bstrListDestroy(lines);
            connection = 2;
            goto cleanup;
          }
          int r;
          if ((r = handleSendMsg(recipientvalue, messagevalue)) != 0) {
            bstring err = bformat("Handler returned with error %d\n", r);
            sendBad(ssl, err->data);
            bdestroy(err);
            bdestroy(recipientkey);
            bdestroy(recipientvalue);
            bdestroy(messagekey);
            bdestroy(messagevalue);
            bstrListDestroy(lines);
            connection = 2;
            goto cleanup;
          }

          sendGood(ssl, connection, "", code);
        } else if (action == 2 && bstrccmp(path, "/receivemsg") == 0) {
          X509 *cert = SSL_get_peer_certificate(ssl);
          X509_NAME *certname = X509_get_subject_name(cert);
          char *_subject = X509_NAME_oneline(certname, NULL, 0);

          bstring recipient = bfromcstr("");
          if (parseSubject(_subject, recipient) != 0) {
            SSL_write(ssl, ERR_MALFORMED_REQUEST,
                      strlen(ERR_MALFORMED_REQUEST));
            free(_subject);
            connection = 2;
            goto cleanup;
          }
          free(_subject);

          struct bstrList *lines = bsplit(bdata, '\n');
          if (lines->qty != 1) {
            SSL_write(ssl, ERR_MALFORMED_REQUEST,
                      strlen(ERR_MALFORMED_REQUEST));
            bstrListDestroy(lines);
            connection = 2;
            goto cleanup;
          }
          int r;
          char *msg;
          if ((r = handleRecvMsg(recipient, &msg)) != 0) {
            bstring err = bformat("Handler returned with error %d\n", r);
            sendBad(ssl, err->data);
            bstrListDestroy(lines);
            connection = 2;
            goto cleanup;
          }

          sendGood(ssl, connection, msg, code);
          free(msg);
        } else {
          sendBad(ssl, ERR_MALFORMED_REQUEST);
          connection = 2;
        }

      cleanup:
        bdestroy(bdata);
        bdestroy(path);

        //

        if (connection == 1) {
          state = 0;
          action = -1;
          contentLength = -1;
          connection = 2;
          free(data);
          continue;
        } else {
          free(data);
          break;
        }
      }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    if (DEBUG && strcmp(vl.version, "die") == 0) break;
  }

  close(sock);
  SSL_CTX_free(ctx);
  EVP_cleanup();
}