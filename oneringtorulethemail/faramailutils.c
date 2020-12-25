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

int addcsr(char *csr, char *username) {
    char relclientreq[50];
    FILE *fp;
    sprintf(relclientreq, "%s/%s%s", CSR_PATH, username, CSR_SUFFIX);
    fp = fopen(relclientreq, "w");
    if (!fp) {
        perror("File open error");
        return -1;
    }
    fputs(csr, fp);
    fclose(fp);
    return 0;
}

// cert MUST be at least MAX_CERT_SIZE
// revoke: 0 do not replace certificate if it already exists
// revoke: 1 replace certificate
// sets n to length of certificate
// return 0 if certificate replaced, 1 if certificate not changed, -1 on error
int getcert(char *cert, char *username, int *n, int revoke) {
    // path relative to server directory
    char relclientcert[50];
    // path relative to current directory
    char clientcert[53];
    char relclientreq[50];
    struct stat filestat;
    memset(cert, '\0', MAX_CERT_SIZE);
    // DO NOT use CERT_PATH and CSR_PATH macros here
    sprintf(relclientcert, "ca/intermediate/certs/%s.cert.pem", username);
    sprintf(clientcert, "../%s", relclientcert);
    sprintf(relclientreq, "ca/intermediate/csr/%s.req.pem", username);
    if (revoke == 0 && stat(clientcert, &filestat) == 0) {
        printf("Certificate already exists. To update your private key, please use changepw.\n");
        BIO *certbio = NULL;
        certbio = BIO_new_file(clientcert, "r");
        if (!certbio) {
            fprintf(stderr, "File open error: %s\n", clientcert);
            return -1;
        }
        int nread = BIO_read(certbio, cert, MAX_CERT_SIZE);
        printf("%s\n", clientcert);
        printf("%s\n", cert);
        BIO_free(certbio);
        *n = nread;
        return 1;
    } else {
        char *args[5] = {"getcert.sh", relclientcert, relclientreq, IMCNF, NULL};
        pid_t pid = fork();
        if (pid == 0) {
            execv("./getcert.sh", args);
            perror("execv error");
            return -1;
        } else {
            int status;
            if (wait(&status) >= 0) {
                BIO *certbio = NULL;
                certbio = BIO_new_file(clientcert, "r");
                if (!certbio) {
                    fprintf(stderr, "File open error: %s\n", clientcert);
                    return -1;
                }
                int nread = BIO_read(certbio, cert, MAX_CERT_SIZE);
                printf("%s\n", clientcert);
                printf("%s\n", cert);
                BIO_free(certbio);
                *n = nread;
                return 0;
            }
            return -1;
        }
    }
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
//         int n;
//         if (argc != 3) {
//             fprintf(stderr, "bad arg count; usage: faramailutils getcert <username>\n");
//             return 1;
//         }
//         username = argv[2];
//         cert = (char *)malloc(MAX_CERT_SIZE);
//         if (!cert) {
//             perror("malloc error");
//             return 1;
//         }
//         return getcert(cert, username, &n, 1);
//     }

//     fprintf(stderr, "operation %s not supported\n", op);
//     return 1;
// }
