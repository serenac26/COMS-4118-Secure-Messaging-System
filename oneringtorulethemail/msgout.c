#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "utils.h"

// inputs:
// message file in mailbox
    // parse From and To headers
// verified output file (temp file somewhere in mail directory)
    // read entire file for message body
// output:
// combined message of headers + message body
int main(int argc, char *argv[]) {
    char *msgout = malloc(MB);
    char *line = NULL;
    size_t size = 0;
    FILE *fp;
    
    // mailbox message
    char *msg_file;
    // temp file created by verifysign
    char *ver_out_file;

    if (argc != 3) {
        fprintf(stderr, "bad arg count; usage: verifysign <msgfile> <veroutfile>\n");
        free(msgout);
        return 1;
    }
    msg_file = argv[1];
    ver_out_file = argv[2];
    
    // Get headers from signed message file
    fp = fopen(msg_file, "r");
    if (!fp) {
        fprintf(stderr, "%s\n", msg_file);
        perror("File open error");
        free(msgout);
        return -1;
    }
    // FROM line
    if (0 == getline(&line, &size, fp)) {
        fprintf(stderr, "%s\n", msg_file);
        perror("Message read error");
        free(msgout);
        return -1;
    }
    strncat(msgout, line, size);

    // TO line
    if (0 == getline(&line, &size, fp)) {
        fprintf(stderr, "%s\n", msg_file);
        perror("Message read error");
        free(msgout);
        return -1;
    }
    fclose(fp);
    strncat(msgout, line, size);
    
    // Get message body from verified file
    fp = fopen(ver_out_file, "r");
    if (!fp) {
        fprintf(stderr, "%s\n", ver_out_file);
        perror("File open error");
        free(msgout);
        return -1;
    }
    while (0 < getline(&line, &size, fp)) {
        strncat(msgout, line, size);
    }
    fclose(fp);

    fprintf(stdout, "%s", msgout);

    // Remove msg and temp ver files
    remove(msg_file);
    remove(ver_out_file);
    
    free(line);
    free(msgout);
    return 0;
}