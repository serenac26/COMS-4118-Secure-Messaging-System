#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include "bstrlib.h"
#include "utf8util.h"
#include "buniutil.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"
#include "utils.h"
#include "boromailutils.h"

struct Node *getrecipientcerts(struct Node *recipients)
{
    struct Node *certs = createList();
    struct Node *curr = recipients;
    while (curr != NULL) {
        if (curr->str == NULL) {
            curr = curr->next;
            continue;
        }
        bstring recipient = curr->str;
        char cert_path[100];
        char cert[MAX_CERT_SIZE];
        FILE *fp;
        memset(cert, '\0', sizeof(cert));
        // check that the recipient is valid, i.e. has a mailbox
        if (recipExists(recipient) != 1) {
            fprintf(stderr, "Invalid recipient\n");
            curr = curr->next;
            continue;
        }
        sprintf(cert_path, "%s/%s%s", CERT_PATH, recipient->data, CERT_SUFFIX);
        BIO *certbio = NULL;
        certbio = BIO_new_file(cert_path, "r");
        if (!certbio) {
            fprintf(stderr, "%s\n", cert_path);
            fprintf(stderr, "File open error");
            curr = curr->next;
            continue;
        }
        int nread = BIO_read(certbio, cert, MAX_CERT_SIZE);
        // clone recipient bstring
        bstring brecipient = bstrcpy(recipient);
        appendList(&certs, brecipient);
        bstring bcert = bfromcstr(cert);
        appendList(&certs, bcert);
        BIO_free(certbio);
        curr = curr->next;
    }
    curr = certs;
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
    recipients_str = printList(recipients, ", ");
    // TOOD: remove From and To headers (msgin should already include them in the encrypted and signed text)
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

int main(int argc, char *argv[]) {
    char *op;
    if (argc < 2) {
        fprintf(stderr, "bad arg count; usage: boromailutils <operation>\nsupported operations: getrecipientcerts sendmsg");
        return 1;
    }
    op = argv[1];

    if (strcmp(op, "getrecipientcerts") == 0) {
        struct Node *certs;
        char **recipients;
        struct Node *recipients_list;
        int i = 0;
        if (argc < 3) {
            fprintf(stderr, "bad arg count; usage: boromailutils getrecipientcerts <recipients..>\n");
            return 1;
        }
        recipients = argv + 2;
        recipients_list = createList();
        while (recipients[i] != NULL) {
            appendList(&recipients_list, bfromcstr(recipients[i++]));
        }
        certs = getrecipientcerts(recipients_list);
        bstring bcerts = printList(certs, "\n");
        printf("%s\n", bcerts->data);
        bdestroy(bcerts);
        freeList(recipients_list);
        freeList(certs);
        return 0;
    }

    if (strcmp(op, "sendmsg") == 0) {
        char *msg;
        char *sender;
        char **recipients;
        struct Node *recipients_list;
        struct Node *recipient;
        int i = 0;
        if (argc < 5) {
            fprintf(stderr, "bad arg count; usage: boromailutils sendmsg <msg> <sender> <recipients..>\n");
            return 1;
        }
        msg = argv[2];
        sender = argv[3];
        recipients = argv + 4;
        recipients_list = createList();
        bstring bsender = bfromcstr(sender);
        bstring bmsg = bfromcstr(msg);
        while (recipients[i] != NULL) {
            appendList(&recipients_list, bfromcstr(recipients[i++]));
        }
        recipient = recipients_list;
        while (recipient != NULL)
        {
            if (recipient->str != NULL) {
                bstring brecipient = recipient->str;
                printf("send to: %s\n", brecipient->data);
                if (sendmsg(bsender, recipient, recipients_list, bmsg) == -1) {
                    fprintf(stderr, "Error sending message to %s\n", brecipient->data);
                }
            }
            recipient = recipient->next;
        }
        bdestroy(bsender);
        bdestroy(bmsg);
        freeList(recipients_list);
        return 0;
    }
}