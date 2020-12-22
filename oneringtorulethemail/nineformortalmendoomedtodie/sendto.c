#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "utils.h"

// cannot use this program on its own
// need to move this directly into boromail as a helper function

struct Node *recipientcerts(struct Node *recipients)
{
    struct Node *certs = createList();
    struct Node *curr = recipients;
    while (curr != NULL) {
        bstring recipient = curr->str;
        char cert_path[100];
        char buf[MAX_CERT_SIZE];
        bstring cert;
        FILE *fp;
        sprintf(cert_path, "%s/%s%s", CERT_PATH, recipient->data, CERT_SUFFIX);
        fp = fopen(cert_path, "r");
        if (!fp) {
            fprintf(stderr, "%s\n", cert_path);
            perror("File open error");
            appendList(&certs, NULL);
            continue;
        }
        if (!fgets(buf, sizeof(MAX_CERT_SIZE), fp)) {
            fprintf(stderr, "%s\n", cert_path);
            perror("File read error");
            appendList(&certs, NULL);
            continue;
        }
        cert = bfromcstr(buf);
        appendList(&certs, cert);
    }
    return certs;
}

int main() {return 0;}