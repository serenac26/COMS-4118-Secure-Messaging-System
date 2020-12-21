#include <unistd.h>
#include <string.h>
#include <stdio.h>

const char *HASHEDPW_PATH = "server/private/credentials";
const char *HASHEDPW_SUFFIX = ".hashedpw";

int main(int argc, char *argv[])
{
    char cwd[256];
    getcwd(cwd, sizeof(cwd));
    printf("%s\n", cwd);
    char *c;
    char *username = argv[1];
    char *pw = argv[2];
    char *treedir = argv[3];
    char hashedpw_file[100];
    char hashedpw[256];
    FILE *fp;
    if (argc != 4) {
        fprintf(stderr, "bad arg count; usage: login <username> <password> <treedir>\n");
        return 1;
    }
    sprintf(hashedpw_file, "%s/%s/%s%s", treedir, HASHEDPW_PATH, username, HASHEDPW_SUFFIX);
    fp = fopen(hashedpw_file, "r");
    if (!fp) {
        printf("%s\n", hashedpw_file);
        perror ("File open error");
        return 1;
    }
    if (!fgets(hashedpw, sizeof(hashedpw), fp)) {
        printf("%s\n", hashedpw_file);
        printf("File read error\n");
        return 1;
    }
    fclose(fp);
    strtok(hashedpw, "\n");
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
