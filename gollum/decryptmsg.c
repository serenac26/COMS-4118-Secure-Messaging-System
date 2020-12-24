/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Based on simple S/MIME decryption example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int decryptmsg(char *cert_file, char *private_key_file, char *ciphertext_file, char *plaintext_file)
{
    BIO *in = NULL, *out = NULL, *certbio = NULL, *keybio = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate and private key */
    certbio = BIO_new_file(cert_file, "r");

    if (!certbio)
        goto err;

    rcert = PEM_read_bio_X509(certbio, NULL, 0, NULL);

    keybio = BIO_new_file(private_key_file, "r");

    rkey = PEM_read_bio_PrivateKey(keybio, NULL, 0, NULL);

    if (!rcert || !rkey)
        goto err;

    /* Open S/MIME message to decrypt */

    in = BIO_new_file(ciphertext_file, "r");

    if (!in)
        goto err;

    /* Parse message */
    cms = SMIME_read_CMS(in, NULL);

    if (!cms)
        goto err;

    out = BIO_new_file(plaintext_file, "w");
    if (!out)
        goto err;

    /* Decrypt S/MIME message */
    if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(certbio);
    BIO_free(keybio);
    return ret;
}

// int main(int argc, char *argv[]) {
//     if (argc != 5) {
//         fprintf(stderr, "bad arg count; usage: decryptmsg <certfile> <keyfile> <ciphertxtfile> <plaintxtfile>\n");
//         return 1;
//     }
//     return decryptmsg(argv[1], argv[2], argv[3], argv[4]);
// }
