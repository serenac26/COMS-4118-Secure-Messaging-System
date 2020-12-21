/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Based off simple S/MIME verification example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include "utils.h"

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL,/* *tbio = NULL, *senderbio = NULL,*/ *cont = NULL;
    X509_STORE *st = NULL;
    X509 *rootcert = NULL;
    X509 *intermedcert = NULL;
    X509 *sendercert = NULL;
    CMS_ContentInfo *cms = NULL;

    char *sender;
    char sender_cert_path[100];
    // calling process should write message to tmp file in ca sandbox
    char *msg_file;
    // calling process should create tmp file for verification output in ca sandbox
    char *ver_out_file;

    int ret = 1;

    if (argc != 4) {
        fprintf(stderr, "bad arg count; usage: verifysign <username> <msgfile> <veroutfile>\n");
        return 1;
    }
    sender = argv[1];
    msg_file = argv[2];
    ver_out_file = argv[3];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */

    st = X509_STORE_new();

    /* Read in certificates */
    tbio = BIO_new_file(ROOT_CERTIFICATE, "r");

    if (!tbio)
        goto err;

    rootcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!rootcert)
        goto err;

    if (!X509_STORE_add_cert(st, rootcert))
        goto err;

    // TODO: add intermediate, and sender certs to store
    tbio = BIO_new_file(INTERMED_CERTIFICATE, "r");

    if (!tbio)
        goto err;

    intermedcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!intermedcert)
        goto err;

    if (!X509_STORE_add_cert(st, intermedcert))
        goto err;

    sprintf(sender_cert_path, "%s/%s%s", CERT_PATH, sender, CERT_SUFFIX);
    tbio = BIO_new_file(sender_cert_path, "r");

    if (!tbio)
        goto err;

    sendercert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!sendercert)
        goto err;

    if (!X509_STORE_add_cert(st, sendercert))
        goto err;

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

    // TODO: replace NULL with sender certificate and add CMS_NOINTERN flag
    if (!CMS_verify(cms, sendercert, st, cont, out, CMS_NOINTERN)) {
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

    CMS_ContentInfo_free(cms);
    X509_free(rootcert);
    X509_free(intermedcert);
    X509_free(sendercert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}