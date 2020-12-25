#ifndef __UTILS_H__
#define __UTILS_H__

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include "bstrlib.h"
#include "utf8util.h"
#include "buniutil.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"
#include "base64.h"

#define HASHEDPW_PATH "../credentials"
#define HASHEDPW_SUFFIX ".hashedpw"

#define MAIL_PATH "../mail"

#define CERT_PATH "../ca/intermediate/certs"
#define CERT_SUFFIX ".cert.pem"
#define CSR_PATH "../ca/intermediate/csr"
#define CSR_SUFFIX ".req.pem"

#define FARAMAIL_PORT 4200
#define BOROMAIL_PORT 6969

#define MAX_CERT_SIZE 2048

#define IMCNF "imopenssl.cnf"

#define GB 1000000000
#define MB 1000000

#define p(...)           \
  if (DEBUG)             \
  {                      \
    printf(__VA_ARGS__); \
  }

struct Node
{
  bstring str;
  struct Node *next;
};

struct Node *createList();

int freeList(struct Node *list);

int inList(struct Node *list, bstring str);

int prependList(struct Node **list, bstring str);

int appendList(struct Node **list, bstring str);

bstring printList(struct Node *list, const char *delim);

int recipExists(bstring recip);

int getMessageFilename(bstring recip, bstring filename);

void encodeMessage(bstring message);

void decodeMessage(bstring message);

int serializeData(bstring key, bstring value, bstring result, int encode);

int deserializeData(bstring key, bstring value, bstring result, int decode);

#endif