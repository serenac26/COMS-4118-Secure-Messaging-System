#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>

const char *MAIL_PATH = "../mail";

int main(int argc, char *argv[])
{
    char *username;
    char mailbox_path[100];
    DIR *dp;
    struct dirent *entry;
    if (argc != 2) {
        fprintf(stderr, "bad arg count; usage: checkmail <username>\n");
        return 1;
    }
    username = argv[1];
    sprintf(mailbox_path, "%s/%s", MAIL_PATH, username);
    dp = opendir(mailbox_path);
    if (!dp) {
        fprintf(stderr, "%s\n", mailbox_path);
        perror("Directory open error");
        return 1;
    }
    while ((entry = readdir(dp))) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            closedir(dp);
            printf("Mailbox not empty\n");
            return 1;
        }
    }
    closedir(dp);
    printf("Mailbox empty\n");
    return 0;
}