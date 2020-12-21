/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Based off simple S/MIME signing example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *certbio = NULL, *keybio = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    CMS_ContentInfo *cms = NULL;

    char *cert_file;
    char *pkey_file;
    char *msg_in;
    char *msg_out;

    int ret = 1;

    /*
     * For simple S/MIME signing use CMS_DETACHED. On OpenSSL 1.0.0 only: for
     * streaming detached set CMS_DETACHED|CMS_STREAM for streaming
     * non-detached set CMS_STREAM
     */
    int flags = CMS_DETACHED | CMS_STREAM | CMS_TEXT;

    if (argc != 5) {
        fprintf(stderr, "bad arg count; usage: signmsg <msgin> <certificatefile> <msgout>\n");
        return 1;
    }
    msg_in = argv[1];
    cert_file = argv[2];
    pkey_file = argv[3];
    msg_out = argv[4];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key */
    certbio = BIO_new_file(cert_file, "r");

    if (!certbio)
        goto err;

    scert = PEM_read_bio_X509(certbio, NULL, 0, NULL);

    keybio = BIO_new_file(pkey_file, "r");

    skey = PEM_read_bio_PrivateKey(keybio, NULL, 0, NULL);

    if (!scert || !skey)
        goto err;

    /* Open content being signed */

    in = BIO_new_file(msg_in, "r");

    if (!in)
        goto err;

    /* Sign content */
    cms = CMS_sign(scert, skey, NULL, in, flags);

    if (!cms)
        goto err;

    out = BIO_new_file(msg_out, "w");
    if (!out)
        goto err;

    if (!(flags & CMS_STREAM))
        BIO_reset(in);

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(scert);
    EVP_PKEY_free(skey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(certbio);
    BIO_free(keybio);    
    return ret;
}