#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "utils.h"

// probably need to move this directly into boromail as a helper function

int main(int argc, char *argv[])
{
    char *certs[argc];
    for (int i = 1; i < argc; i++) {
        char *recipient = argv[i];
        char cert_path[100];
        FILE *fp;
        certs[i] = malloc(MAX_CERT_SIZE);
        if (!certs[i]) {
            perror("malloc error");
            return 1;
        }
        sprintf(cert_path, "%s/%s%s", CERT_PATH, recipient, CERT_SUFFIX);
        fp = fopen(cert_path);
        if (!fp) {
            fprintf(stderr, "%s\n", cert_path);
            perror("File open error");
            return 1;
        }
        if (!fgets(certs[i], sizeof(MAX_CERT_SIZE), fp)) {
            fprintf(stderr, "%s\n", cert_path);
            perror("File read error");
            return 1;
        }
    }
    //return certs;
    return 0;
}
