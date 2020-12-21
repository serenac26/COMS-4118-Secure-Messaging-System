#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "utils.h"
#include <crypt.h>
// char *crypt_gensalt(const char *prefix, unsigned long count, const char *rbytes, int nrbytes);

int main(int argc, char *argv[])
{
    char *username;
    char *pw;
    char *salt;
    char *hashedpw;
    char hashedpw_file[100];
    FILE *fp;
    if (argc != 3) {
        fprintf(stderr, "bad arg count; usage: changepw <username> <password>\n");
        return 1;
    }
    username = argv[1];
    pw = argv[2];
    salt = crypt_gensalt(NULL, 0, NULL, 0);
    hashedpw = crypt(pw, salt);
    printf("%s\n", hashedpw);
    sprintf(hashedpw_file, "%s/%s%s", HASHEDPW_PATH, username, HASHEDPW_SUFFIX);
    fp = fopen(hashedpw_file, "w");
    if (!fp) {
        fprintf(stderr, "%s\n", hashedpw_file);
        perror("File open error");
        return 1;
    }
    if (fputs(hashedpw, fp) != strlen(hashedpw)) {
        fprintf(stderr, "%s\n", hashedpw_file);
        fprintf(stderr, "File write error\n");
        return 1;
    }
    fclose(fp);
    return 0;
}