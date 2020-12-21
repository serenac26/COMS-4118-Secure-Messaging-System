#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <crypt.h>
#include "utils.h"

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
    fputs(hashedpw, fp);
    fclose(fp);
    return 0;
}
