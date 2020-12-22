#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "bstrlib.h"
#include "utf8util.h"
#include "buniutil.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"
#include "utils.h"
#include "boromailutils.h"

struct Node *recipientcerts(struct Node *recipients)
{
    struct Node *certs = createList();
    struct Node *curr = recipients;
    while (curr != NULL) {
        bstring recipient = curr->str;
        char cert_path[100];
        char buf[MAX_CERT_SIZE];
        bstring cert;
        FILE *fp;
        sprintf(cert_path, "%s/%s%s", CERT_PATH, recipient->data, CERT_SUFFIX);
        fp = fopen(cert_path, "r");
        if (!fp) {
            fprintf(stderr, "%s\n", cert_path);
            perror("File open error");
            appendList(&certs, NULL);
            continue;
        }
        if (!fgets(buf, sizeof(MAX_CERT_SIZE), fp)) {
            fprintf(stderr, "%s\n", cert_path);
            perror("File read error");
            appendList(&certs, NULL);
            continue;
        }
        cert = bfromcstr(buf);
        appendList(&certs, cert);
    }
    return certs;
}

int sendmsg(bstring sender, struct Node *recipient, struct Node *recipients, bstring msgin)
{
    char *msgout = malloc(MB);
    bstring recipient_str;
    bstring recipients_str;
    int msglen;
    bstring filename;
    FILE *fp;
    if (!msgout) {
        perror("malloc error");
        return -1;
    }
    recipient_str = recipient->str;
    recipients_str = printList(recipients);
    msglen = sprintf(msgout, "%s%s\n%s%s\n%s", FROM, sender->data, TO, recipients_str->data, msgin->data);
    filename = bfromcstr("");
    if (getMessageFilename(recipient_str, filename) == 0) {
        bdestroy(filename);
        bdestroy(recipients_str);
        free(msgout);
        return -1;
    }
  
    fp = fopen((char *)filename->data, "w");
    if (!fp) {
        fprintf(stderr, "%s\n", filename->data);
        perror("File open error");
        bdestroy(filename);
        bdestroy(recipients_str);
        free(msgout);
        return -1;
    }
    fwrite(msgout, 1, msglen, fp);
    fclose(fp);
    
    bdestroy(filename);
    bdestroy(recipients_str);
    free(msgout);
    return 0;
}

// add verify sign and msgout