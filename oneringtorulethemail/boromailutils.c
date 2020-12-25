#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include "bstrlib.h"
#include "utf8util.h"
#include "buniutil.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"
#include "utils.h"
#include "boromailutils.h"

// cert MUST be at least MAX_CERT_SIZE
int getusercert(char *cert, bstring recipient)
{
    char cert_path[100];
    memset(cert, '\0', MAX_CERT_SIZE);
    // check that the recipient is valid, i.e. has a mailbox
    if (recipExists(recipient) != 1) {
        fprintf(stderr, "Invalid recipient\n");
        return 1;
    }
    sprintf(cert_path, "%s/%s%s", CERT_PATH, recipient->data, CERT_SUFFIX);
    BIO *certbio = NULL;
    certbio = BIO_new_file(cert_path, "r");
    if (!certbio) {
        fprintf(stderr, "%s\n", cert_path);
        fprintf(stderr, "File open error");
        return 2;
    }
    BIO_read(certbio, cert, MAX_CERT_SIZE);
    BIO_free(certbio);
    return 0;
}

int sendmessage(bstring recipient, bstring msg) {
    bstring filename;
    FILE *fp;
    filename = bfromcstr("");
    int ret = getMessageFilename(recipient, filename);
    if (ret != 1) {
        if (ret == -2) {
            fprintf(stderr, "Mailbox full\n");
            bdestroy(filename);
            return -2;
        }
        fprintf(stderr, "Error getting filename\n");        
        bdestroy(filename);
        return -1;
    }
  
    fp = fopen((char *)filename->data, "w");
    if (!fp) {
        fprintf(stderr, "%s\n", filename->data);
        perror("File open error");
        bdestroy(filename);
        return -1;
    }
    fwrite((char *)msg->data, 1, msg->slen, fp);
    fclose(fp);
    
    bdestroy(filename);
    return 0;
}

// msgout needs to be freed
int recvmessage(bstring msgfile, char** msgout) {
    char *line = NULL;
    size_t size = 0;
    FILE *fp;
    
    // Get message body from message file
    fp = fopen((char *)msgfile->data, "r");
    if (!fp) {
        fprintf(stderr, "%s\n", msgfile->data);
        perror("File open error");
        return -1;
    }
    
    *msgout = (char *)malloc(MB);
    if (!*msgout) {
        perror("Malloc error");
        return -1;
    }
    *msgout = '\0';
    while (0 < getline(&line, &size, fp)) {
        strncat(*msgout, line, size);
    }
    fclose(fp);

    // Remove message file
    remove((char *)msgfile->data);
    
    free(line);
    return 0;
}

int getOldestFilename(bstring recip, bstring filename) {
  char mailbox_path[100];
  DIR *dp;
  struct dirent *entry;
  sprintf(mailbox_path, "%s/%s", MAIL_PATH, recip->data);
  dp = opendir(mailbox_path);
  if (!dp) {
    fprintf(stderr, "%s\n", mailbox_path);
    perror("Directory open error");
    return -1;
  }
  while ((entry = readdir(dp))) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      closedir(dp);
      int file_count = 1;
      struct stat filestat;

      bstring _filename = bformat("../mail/%s/%05d", recip->data, file_count);
      while (stat((char *) _filename->data, &filestat) != 0) {
        bdestroy(_filename);
        file_count++;
        _filename = bformat("../mail/%s/%05d", recip->data, file_count);
      }
      
      int _i = bassign(filename, _filename);
      bdestroy(_filename);

      if (_i == BSTR_ERR)
      {
        return -1;
      }
      return 0;
    }
  }
  closedir(dp);
  return -1;
}

// Testing
// int main(int argc, char *argv[]) {
//     char *op;
//     if (argc < 2) {
//         fprintf(stderr, "bad arg count; usage: boromailutils <operation>\nsupported operations: getusercert sendmsg recvmessage");
//         return 1;
//     }
//     op = argv[1];

//     if (strcmp(op, "getuser") == 0) {
//         char cert[MAX_CERT_SIZE];
//         char *recipient;
//         int i = 0;
//         if (argc < 3) {
//             fprintf(stderr, "bad arg count; usage: boromailutils getusercert <recipient>\n");
//             return 1;
//         }
//         recipient = argv[2];
//         bstring brec = bfromcstr(recipient);
//         int ret = getusercert(cert, brec);
//         if (ret == 0) {
//             printf("%s\n", cert);
//         }
//         bdestroy(brec);
//         return ret;
//     }

//     if (strcmp(op, "sendmsg") == 0) {
//         char *msg, *recipient;
//         int i = 0;
//         if (argc < 4) {
//             fprintf(stderr, "bad arg count; usage: boromailutils sendmsg <msg> <recipient>\n");
//             return 1;
//         }
//         msg = argv[2];
//         recipient = argv[3];
//         bstring bmsg = bfromcstr(msg);
//         bstring brecipient = bfromcstr(recipient);
//         printf("send to: %s\n", brecipient->data);
//         if (sendmsg(brecipient, bmsg) == -1) {
//             fprintf(stderr, "Error sending message to %s\n", brecipient->data);
//         }
//         bdestroy(brecipient);
//         bdestroy(bmsg);
//         return 0;
//     }

//     if (strcmp(op, "recvmessage") == 0) {
//         char *msgfile;
//         char *msgout;

//         if (argc != 3) {
//             fprintf(stderr, "bad arg count; usage: boromailutils recvmessage <msgfile>\n");
//             return 1;
//         }
//         msgfile = argv[2];
//         int value = recvmessage(msgfile, &msgout);
//         printf("%s", msgout);
//         free(msgout);
//         return value;
//     }
// }
