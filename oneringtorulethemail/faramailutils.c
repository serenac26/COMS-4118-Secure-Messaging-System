#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <crypt.h>
#include <openssl/pem.h>
#include "utils.h"
#include "faramailutils.h"

int login(char *username, char *pw)
{
    char *c;
    char hashedpw_file[100];
    char hashedpw[256];
    FILE *fp;
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
        return 2;
    }
}

int checkmail(char *username)
{
    char mailbox_path[100];
    DIR *dp;
    struct dirent *entry;
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
            return 2;
        }
    }
    closedir(dp);
    printf("Mailbox empty\n");
    return 0;
}

int changepw(char *username, char *pw)
{
    char *salt;
    char *hashedpw;
    char hashedpw_file[100];
    FILE *fp;
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

// on success returns length of certificate
int getcert(char *cert, char *username) {
    // path relative to server directory
    char relclientcert[50];
    // path relative to current directory
    char clientcert[53];
    char relclientreq[50];
    // DO NOT use CERT_PATH macro here
    sprintf(relclientcert, "ca/intermediate/certs/%s.cert.pem", username);
    sprintf(clientcert, "../%s", relclientcert);
    sprintf(relclientreq, "ca/intermediate/csr/%s.req.pem", username);
    char *args[5] = {"getcert.sh", relclientcert, relclientreq, IMCNF, NULL};
    pid_t pid = fork();
    if (pid == 0) {
        fflush(stdout);
        execv("./getcert.sh", args);
    } else {
        int status;
        if (wait(&status) >= 0) {
            printf("getcert process exited with %d status\n", WEXITSTATUS(status));
            int fd = open(clientcert, O_RDONLY);
            if (fd == -1) {
                fprintf(stderr, "%s\n", clientcert);
                perror("File open error");
                return -1;
            }
            BIO *certbio = NULL;
            certbio = BIO_new_file(clientcert, "r");
            if (!certbio) {
                BIO_free(certbio);
            }
            int nread = BIO_read(certbio, cert, MAX_CERT_SIZE);
            printf("%s\n", clientcert);
            printf("%s\n", cert);
            BIO_free(certbio);
            return nread;
        }
    }
    return -1;
}

// Testing
// int main(int argc, char *argv[]) {
//     char *op;
//     if (argc < 2) {
//         fprintf(stderr, "bad arg count; usage: faramailutils <operation>\nsupported operations: login checkmail changepw");
//         return 1;
//     }
//     op = argv[1];

//     if (strcmp(op, "login") == 0) {
//         char *username;
//         char *pw;
//         if (argc != 4) {
//             fprintf(stderr, "bad arg count; usage: faramailutils login <username> <password>\n");
//             return 1;
//         }
//         username = argv[2];
//         pw = argv[3];
//         return login(username, pw);
//     }
    
//     if (strcmp(op, "checkmail") == 0) {
//         char *username;
//         if (argc != 3) {
//             fprintf(stderr, "bad arg count; usage: faramailutils checkmail <username>\n");
//             return 1;
//         }
//         username = argv[2];
//         return checkmail(username);
//     }

//     if (strcmp(op, "changepw") == 0) {
//         char *username;
//         char *pw;
//         if (argc != 4) {
//             fprintf(stderr, "bad arg count; usage: faramailutils changepw <username> <password>\n");
//             return 1;
//         }
//         username = argv[2];
//         pw = argv[3];
//         return changepw(username, pw);
//     }
    
//     if (strcmp(op, "getcert") == 0) {
//         char *cert;
//         char *username;
//         if (argc != 3) {
//             fprintf(stderr, "bad arg count; usage: faramailutils getcert <username>\n");
//             return 1;
//         }
//         username = argv[2];
//         cert = malloc(MAX_CERT_SIZE);
//         if (!cert) {
//             perror("malloc error");
//             return 1;
//         }
//         memset(cert, '\0', MAX_CERT_SIZE);
//         return getcert(cert, username);
//     }

//     fprintf(stderr, "operation %s not supported\n", op);
//     return 1;
// }
