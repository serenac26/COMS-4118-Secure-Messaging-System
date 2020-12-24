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
#include "gollumutils.h"

#define ROOT_CERTIFICATE "../ca.cert.pem"
#define INTERMED_CERTIFICATE "../intermediate.cert.pem"

/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Based on simple S/MIME encrypt example */
int encryptmsg(char *cert_file, char *plaintext_file, char *ciphertext_file)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    /*
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    tbio = BIO_new_file(cert_file, "r");

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();

    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /*
     * sk_X509_pop_free will free up recipient STACK and its contents so set
     * rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */

    in = BIO_new_file(plaintext_file, "r");

    if (!in)
        goto err;

    /* encrypt content */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);

    if (!cms)
        goto err;

    out = BIO_new_file(ciphertext_file, "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}

/* Based on simple S/MIME decryption example */
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

/* Based off simple S/MIME signing example */
int signmsg(char *cert_file, char *private_key_file, char *unsigned_file, char *signed_file)
{
    BIO *in = NULL, *out = NULL, *certbio = NULL, *keybio = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    CMS_ContentInfo *cms = NULL;

    int ret = 1;

    /*
     * For simple S/MIME signing use CMS_DETACHED. On OpenSSL 1.0.0 only: for
     * streaming detached set CMS_DETACHED|CMS_STREAM for streaming
     * non-detached set CMS_STREAM
     */
    int flags = CMS_DETACHED | CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key */
    certbio = BIO_new_file(cert_file, "r");

    if (!certbio)
        goto err;

    scert = PEM_read_bio_X509(certbio, NULL, 0, NULL);

    keybio = BIO_new_file(private_key_file, "r");

    skey = PEM_read_bio_PrivateKey(keybio, NULL, 0, NULL);

    if (!scert || !skey)
        goto err;

    /* Open content being signed */

    in = BIO_new_file(unsigned_file, "r");

    if (!in)
        goto err;

    /* Sign content */
    cms = CMS_sign(scert, skey, NULL, in, flags);

    if (!cms)
        goto err;

    out = BIO_new_file(signed_file, "w");
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

/* Based off simple S/MIME verification example */
int verifysign(char *sender_cert_path, char *signed_file, char *verified_file) {
    BIO *in = NULL, *out = NULL, *rootbio = NULL, *intmbio = NULL, *senderbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *rootcert = NULL;
    X509 *intermedcert = NULL;
    X509 *sendercert = NULL;
    STACK_OF(X509) *certs;
    CMS_ContentInfo *cms = NULL;

    int ret = 1;

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

    in = BIO_new_file(signed_file, "r");

    if (!in)
        goto err;

    /* parse message */
    cms = SMIME_read_CMS(in, &cont);

    if (!cms)
        goto err;

    /* File to output verified content to */
    out = BIO_new_file(verified_file, "w");
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


/* Based off simple S/MIME verification example */
int verifyunsign(char *signed_file, char *unverified_file) {
    BIO *in = NULL, *out = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    CMS_ContentInfo *cms = NULL;

    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */

    st = X509_STORE_new();

    /* Open message being verified */

    in = BIO_new_file(signed_file, "r");

    if (!in)
        goto err;

    /* parse message */
    cms = SMIME_read_CMS(in, &cont);

    if (!cms)
        goto err;

    /* File to output unverified content to */
    out = BIO_new_file(unverified_file, "w");
    if (!out)
        goto err;

    if (!CMS_verify(cms, NULL, st, cont, out, CMS_NOVERIFY)) {
        fprintf(stderr, "Unsigning Failure\n");
        goto err;
    }

    fprintf(stderr, "Unsigning Successful\n");

    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }

    X509_STORE_free(st);
    CMS_ContentInfo_free(cms);
    BIO_free(in);
    BIO_free(out);
    BIO_free(cont);
    return ret;
}

// Testing
int main(int argc, char *argv[]) {
    char *op;
    if (argc < 2) {
        fprintf(stderr, "bad arg count; usage: gollumutils <operation>\nsupported operations: encryptmsg decryptmsg signmsg verifysign");
        return 1;
    }
    op = argv[1];

    if (strcmp(op, "encryptmsg") == 0) {
        if (argc < 5) {
            fprintf(stderr, "bad arg count; usage: gollumutils encryptmsg <certfile> <plaintxtfile> <ciphertxtfile>\n");
            return 1;
        }
        return encryptmsg(argv[2], argv[3], argv[4]);
    }

    if (strcmp(op, "decryptmsg") == 0) {
        if (argc < 6) {
            fprintf(stderr, "bad arg count; usage: gollumutils decryptmsg <certfile> <keyfile> <ciphertxtfile> <plaintxtfile>\n");
            return 1;
        }
        return decryptmsg(argv[2], argv[3], argv[4], argv[5]);
    }

    if (strcmp(op, "signmsg") == 0) {
        if (argc < 6) {
            fprintf(stderr, "bad arg count; usage: gollumutils signmsg <certfile> <keyfile> <msgin> <msgout>\n");
            return 1;
        }
        return signmsg(argv[2], argv[3], argv[4], argv[5]);
    }

    if (strcmp(op, "verifysign") == 0) {
        if (argc != 5) {
            fprintf(stderr, "bad arg count; usage: gollumutils verifysign <certfile> <msgfile> <veroutfile>\n");
            return 1;
        }
        return verifysign(argv[2], argv[3], argv[4]);
    }

    if (strcmp(op, "verifyunsign") == 0) {
        if (argc != 4) {
            fprintf(stderr, "bad arg count; usage: gollumutils verifyunsign <msgfile> <unveroutfile>\n");
            return 1;
        }
        return verifyunsign(argv[2], argv[3]);
    }
}
