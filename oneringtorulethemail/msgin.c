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

// need to move this directly into boromail as a helper function to avoid piping/writing message to a temp file

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

int main(int argc, char *argv[]) {
    char *msg;
    char *sender;
    char **recipients;
    struct Node *recipients_list;
    struct Node *recipient;
    int i = 0;
    if (argc < 4) {
        fprintf(stderr, "bad arg count; usage: faramailutils login <username> <password>\n");
        return 1;
    }
    msg = argv[1];
    sender = argv[2];
    recipients = argv + 3;
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
