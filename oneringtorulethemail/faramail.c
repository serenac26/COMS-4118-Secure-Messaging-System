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
#include "bstrlib.h"
#include "utf8util.h"
#include "buniutil.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"
#include "faramailutils.h"

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

#define ERR_BAD_USERNAME (-1)
#define ERR_WRONG_PASSWORD (-2)
#define ERR_OPEN (-3)
#define ERR_PENDING_MSG (-4)
#define ERR_CERT_EXISTS (-5)


#define p(...)            \
  if (DEBUG) {            \
    printf("\033[0;34m"); \
    printf("Faramail: "); \
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
    p("Regex did not compile successfully\n");
  }
  regmatch_t match[6];
  int test = regexec(&reg, data, 6, match, 0);

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

  regfree(&reg);
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
    p("Regex did not compile successfully\n");
  }
  regmatch_t match[3];
  int test = regexec(&reg, data, 3, match, 0);

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

  regfree(&reg);
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

void testParsers(int mama, char **moo) {
  struct VerbLine vl;
  char *yeet = "post https://www.rbbridge.com:8080/sendmsg/goodgod HTTP/1.1";
  int result = parseVerbLine(yeet, &vl);
  p("%d %s\n", result, vl.verb);
  p("%d %s\n", result, vl.port);
  p("%d %s\n", result, vl.path);
  p("%d %s\n", result, vl.version);

  struct OptionLine ol;
  char *yeet2 = "connection: keep-alive";
  int result2 = parseOptionLine(yeet2, &ol);
  p("%d %s\n", result2, ol.header);
  p("%d %s\n", result2, ol.value);
}

// caller should allocate MAX_CERT_SIZE bytes to cert
// cert will be filled with the new certificate contents
// cert will be written to ca/intermediate/certs/username.cert.pem
// n is the length of the cert
int handleGetCert(char *cert, bstring busername, bstring bpw, bstring bcsr, int *n) {
  char *username = (char *)busername->data;
  char *pw = (char *)bpw->data;
  char *csr = (char *)bcsr->data;
  
  int lret = login(username, pw);
  if (lret == 1) {
    fprintf(stderr, "Login failed: bad username\n");
    return ERR_BAD_USERNAME;
  } else if (lret == 2) {
    fprintf(stderr, "Login failed: incorrect password\n");
    return ERR_WRONG_PASSWORD;
  }
  printf("Login successful\n");
  if (addcsr(csr, username) == -1) {
    fprintf(stderr, "Could not generate certificate\n");
    return ERR_OPEN;
  }
  int ret = getcert(cert, username, n, 0);
  if (ret == -1) {
    fprintf(stderr, "Could not generate certificate\n");
    return ERR_OPEN;
  } else if (ret == 1) {
    return ERR_CERT_EXISTS;
  } else {
    return 0;
  }
}

// caller should allocate MAX_CERT_SIZE bytes to cert
// change password only if mailbox is empty
// cert will be filled with the new certificate contents
// cert will be written to ca/intermediate/certs/username.cert.pem
// n is the length of the cert
int handleChangePw(char *cert, bstring busername, bstring boldpw, bstring bnewpw, bstring bcsr, int *n) {
  char *username = (char *)busername->data;
  char *oldpw = (char *)boldpw->data;
  char *newpw = (char *)bnewpw->data;
  char *csr = (char *)bcsr->data;
  
  int lret = login(username, oldpw);
  if (lret == 1) {
    fprintf(stderr, "Login failed: bad username\n");
    return ERR_BAD_USERNAME;
  } else if (lret == 2) {
    fprintf(stderr, "Login failed: incorrect password\n");
    return ERR_WRONG_PASSWORD;
  }
  int cret = checkmail(username);
  if (cret == 1) {
    fprintf(stderr, "Error checking mailbox. Password not changed.\n");
    return ERR_OPEN;
  } else if (cret == 2) {
    fprintf(stderr, "Mailbox is not empty. Password not changed.\n");
    return ERR_PENDING_MSG;
  }
  if (changepw(username, newpw) != 0) {
    fprintf(stderr, "Error changing password\n");
    return ERR_OPEN;
  }
  if (addcsr(csr, username) == -1) {
    fprintf(stderr, "Could not generate certificate\n");
    return ERR_OPEN;
  }
  int ret = getcert(cert, username, n, 1);
  if (ret == -1) {
    fprintf(stderr, "Could not generate certificate\n");
    return ERR_OPEN;
  } else if (ret == 1) {
    return ERR_CERT_EXISTS;
  } else {
    return 0;
  }
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

  if (SSL_CTX_use_certificate_file(ctx,
                                   "../ca/intermediate/certs/faramail.cert.pem",
                                   SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  // TODO: need to input password
  if (SSL_CTX_use_PrivateKey_file(ctx,
                                  "../ca/intermediate/private/faramail.key.pem",
                                  SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  int sock = create_socket(4200);

  while (1) {
    struct sockaddr_in addr;
    uint len = sizeof(addr);
    SSL *ssl = SSL_new(ctx);

    int client = accept(sock, (struct sockaddr *)&addr, &len);

    if (client < 0) {
      perror("Unable to accept");
      exit(EXIT_FAILURE);
    }

    p("Connection from %x, port %x\n", addr.sin_addr.s_addr, addr.sin_port);

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
     * Set by an option line
     * ===
     * -1 Unset
     * 1 Get
     * 2 Post
     */
    int action = -1;

    /*
     * Set by a verb line
     * ===
     * -1 Unset
     */
    int contentLength = -1;

    /*
     * Set by a verb line. Default to close
     * ===
     * 1 keep-alive
     * 2 close
     */
    int connection = 2;

    char *data;

    while (1) {
      memset(rbuf, '\0', sizeof(rbuf));
      int readReturn = SSL_read(ssl, rbuf, sizeof(rbuf) - 1);
      p("state: %d bytes-read: %d line: %s\n", state, readReturn, rbuf);
      if (readReturn == 0) {
        p("0 bytes read\n");
        break;
      } else if (readReturn == sizeof(rbuf) - 1 && state != 2) {
        SSL_write(ssl, ERR_TOO_LONG, strlen(ERR_TOO_LONG));
        break;
      } else if (state == 0) {
        struct VerbLine vl;
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

        data = (char *)malloc(contentLength);
        memset(data, '\0', contentLength);

        // p("%ld %ld %s\n", strlen(rbuf), sizeof(rbuf), rbuf);
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
        p("state: %d\naction: %d\ncontentLength: %d\nconnection: %d\n%s\n",
          state, action, contentLength, connection, data);

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
  }

  close(sock);
  SSL_CTX_free(ctx);
  EVP_cleanup();
}