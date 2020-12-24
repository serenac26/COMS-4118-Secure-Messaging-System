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
int getrecipientcert(char *cert, bstring recipient)
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

/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Based off simple S/MIME verification example */
int verifysign(char *sender, char *msg_file, char *ver_out_file)
{
    BIO *in = NULL, *out = NULL, *rootbio = NULL, *intmbio = NULL, *senderbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *rootcert = NULL;
    X509 *intermedcert = NULL;
    X509 *sendercert = NULL;
    STACK_OF(X509) *certs;
    CMS_ContentInfo *cms = NULL;

    int ret = 1;
    char sender_cert_path[100];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */

    st = X509_STORE_new();

    /* Read in certificates */
    rootbio = BIO_new_file(ROOT_CERTIFICATE, "r");

    if (!rootbio)
        goto err;

    rootcert = PEM_read_bio_X509(rootbio, NULL, 0, NULL);

    if (!rootcert)
        goto err;

    if (!X509_STORE_add_cert(st, rootcert))
        goto err;

    intmbio = BIO_new_file(INTERMED_CERTIFICATE, "r");

    if (!intmbio)
        goto err;

    intermedcert = PEM_read_bio_X509(intmbio, NULL, 0, NULL);

    if (!intermedcert)
        goto err;

    if (!X509_STORE_add_cert(st, intermedcert))
        goto err;

    sprintf(sender_cert_path, "%s/%s%s", CERT_PATH, sender, CERT_SUFFIX);

    senderbio = BIO_new_file(sender_cert_path, "r");

    if (!senderbio)
        goto err;

    sendercert = PEM_read_bio_X509(senderbio, NULL, 0, NULL);

    if (!sendercert)
        goto err;

    if (!X509_STORE_add_cert(st, sendercert))
        goto err;

    // add sender certificate to list of certificates to check
    if ((certs = sk_X509_new_null()) == NULL)
		goto err;
    
    if ((sk_X509_push(certs, sendercert)) == 0) {
        goto err;
    }

    /* Open message being verified */

    in = BIO_new_file(msg_file, "r");

    if (!in)
        goto err;

    /* parse message */
    cms = SMIME_read_CMS(in, &cont);

    if (!cms)
        goto err;

    /* File to output verified content to */
    out = BIO_new_file(ver_out_file, "w");
    if (!out)
        goto err;

    if (!CMS_verify(cms, certs, st, cont, out, CMS_NOINTERN)) {
        fprintf(stderr, "Verification Failure\n");
        goto err;
    }

    fprintf(stderr, "Verification Successful\n");

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }

    X509_STORE_free(st);
    CMS_ContentInfo_free(cms);
    sk_X509_pop_free(certs, X509_free);
    X509_free(rootcert);
    X509_free(intermedcert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(cont);
    BIO_free(rootbio);
    BIO_free(intmbio);
    BIO_free(senderbio);
    return ret;
}

// TODO: add msgout

// Testing
// int main(int argc, char *argv[]) {
//     char *op;
//     if (argc < 2) {
//         fprintf(stderr, "bad arg count; usage: boromailutils <operation>\nsupported operations: getrecipientcert sendmsg");
//         return 1;
//     }
//     op = argv[1];

//     if (strcmp(op, "getrecipientcert") == 0) {
//         char cert[MAX_CERT_SIZE];
//         char *recipient;
//         int i = 0;
//         if (argc < 3) {
//             fprintf(stderr, "bad arg count; usage: boromailutils getrecipientcert <recipient>\n");
//             return 1;
//         }
//         recipient = argv[2];
//         bstring brec = bfromcstr(recipient);
//         int ret = getrecipientcert(cert, brec);
//         if (ret == 0) {
//             printf("%s\n", cert);
//         }
//         bdestroy(brec);
//         return ret;
//     }

//     if (strcmp(op, "sendmsg") == 0) {
//         char *msg;
//         char *sender;
//         char **recipients;
//         struct Node *recipients_list;
//         struct Node *recipient;
//         int i = 0;
//         if (argc < 5) {
//             fprintf(stderr, "bad arg count; usage: boromailutils sendmsg <msg> <sender> <recipients..>\n");
//             return 1;
//         }
//         msg = argv[2];
//         sender = argv[3];
//         recipients = argv + 4;
//         recipients_list = createList();
//         bstring bsender = bfromcstr(sender);
//         bstring bmsg = bfromcstr(msg);
//         while (recipients[i] != NULL) {
//             appendList(&recipients_list, bfromcstr(recipients[i++]));
//         }
//         recipient = recipients_list;
//         while (recipient != NULL)
//         {
//             if (recipient->str != NULL) {
//                 bstring brecipient = recipient->str;
//                 printf("send to: %s\n", brecipient->data);
//                 if (sendmsg(bsender, recipient, recipients_list, bmsg) == -1) {
//                     fprintf(stderr, "Error sending message to %s\n", brecipient->data);
//                 }
//             }
//             recipient = recipient->next;
//         }
//         bdestroy(bsender);
//         bdestroy(bmsg);
//         freeList(recipients_list);
//         return 0;
//     }

//     if (strcmp(op, "verifysign") == 0) {
//         char *sender;
//         // calling process should write message to tmp file in ca sandbox
//         char *msg_file;
//         // calling process should create tmp file for verification output in ca sandbox
//         char *ver_out_file;

//         if (argc != 5) {
//             fprintf(stderr, "bad arg count; usage: boromailutils verifysign <username> <msgfile> <veroutfile>\n");
//             return 1;
//         }
//         sender = argv[2];
//         msg_file = argv[3];
//         ver_out_file = argv[4];
//         return verifysign(sender, msg_file, ver_out_file);
//     }
// }