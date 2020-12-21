#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "utils.h"

int main(int argc, char *argv[])
{
    char *c;
    char *username;
    char *pw;
    char hashedpw_file[100];
    char hashedpw[256];
    FILE *fp;
    if (argc != 3) {
        fprintf(stderr, "bad arg count; usage: login <username> <password>\n");
        return 1;
    }
    username = argv[1];
    pw = argv[2];
    sprintf(hashedpw_file, "%s/%s%s", HASHEDPW_PATH, username, HASHEDPW_SUFFIX);
    fp = fopen(hashedpw_file, "r");
    if (!fp) {
        fprintf(stderr, "%s\n", hashedpw_file);
        perror("File open error");
        return 1;
    }
    if (!fgets(hashedpw, sizeof(hashedpw), fp)) {
        fclose(fp);
        fprintf(stderr, "%s\n", hashedpw_file);
        perror("File read error");
        return 1;
    }
    fclose(fp);
    c = crypt(pw, hashedpw);
    if (strcmp(c, hashedpw) == 0) {
        printf("ok\n");
        return 0;
    }
    else {
        printf("bad\n");
        return 1;
    }
}
