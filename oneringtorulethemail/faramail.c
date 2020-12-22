#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define READBUF_SIZE 1000
#define WRITEBUF_SIZE 1000

struct Solar
{
  char action[10];
  char url[100];
  char version[10];
};

struct Wheein
{
  char header[100];
  char value[100];
};

int parseSolar()
{
  regex_t solarRegex;
  int value;
  value = regcomp(&solarRegex, "^\\.?mail from:<([a-z0-9\\+\\-_]+)>\n$", REG_EXTENDED | REG_ICASE);
  if (value != 0)
  {
    printf("Regex did not compile successfully\n");
  }
  regmatch_t match[2];
}

int create_socket(int port)
{
  int s;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
  {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
  }

  if (listen(s, 1) < 0)
  {
    perror("Unable to listen");
    exit(EXIT_FAILURE);
  }

  return s;
}

// Refer to:
// http://h30266.www3.hpe.com/odl/axpos/opsys/vmsos84/BA554_90007/ch04s03.html and
// https://wiki.openssl.org/index.php/Simple_TLS_Server
// for more information
int main(int mama, char **moo)
{

  SSL_library_init();       /* load encryption & hash algorithms for SSL */
  SSL_load_error_strings(); /* load the error strings for good error reporting */

  // TLSv1_1_server_method is deprecated
  // Can switch back if inconvenient
  const SSL_METHOD *mamamethod = TLS_server_method();
  SSL_CTX *ctx = SSL_CTX_new(mamamethod);

  // Only accept the LATEST and GREATEST in TLS
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

  if (SSL_CTX_use_certificate_file(ctx, "root/ca/intermediate/certs/www.moonchild.com.cert.pem", SSL_FILETYPE_PEM) != 1)
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "root/ca/intermediate/private/www.moonchild.com.key.pem", SSL_FILETYPE_PEM) != 1)
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  int sock = create_socket(4200);

  while (1)
  {
    struct sockaddr_in addr;
    uint len = sizeof(addr);
    SSL *ssl = SSL_new(ctx);
    const char reply[] = "test\n";

    int client = accept(sock, (struct sockaddr *)&addr, &len);

    if (client < 0)
    {
      perror("Unable to accept");
      exit(EXIT_FAILURE);
    }

    printf("Connection from %x, port %x\n", addr.sin_addr.s_addr, addr.sin_port);

    SSL_set_fd(ssl, client);

    if (SSL_accept(ssl) <= 0)
    {
      ERR_print_errors_fp(stderr);
    }

    char rbuf[READBUF_SIZE];
    char wbuf[WRITEBUF_SIZE];

    /*
     * Welcome to state shenanigans part 3
     * ===
     * 0  Expecting <verb> <url> <version>
     * 1  Expecting <option-lines>
     */
    // int state = 0;
    // while (1)
    // {
      
    // }
    int readReturn = SSL_read(ssl, rbuf, sizeof(rbuf) - 1);

    int err = SSL_write(ssl, rbuf, readReturn);

    printf("%s\n", rbuf);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
  }

  close(sock);
  SSL_CTX_free(ctx);
  EVP_cleanup();
}