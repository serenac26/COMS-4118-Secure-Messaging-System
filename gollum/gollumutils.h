#ifndef __BOROMAILUTILS_H__
#define __BOROMAILUTILS_H__

int encryptmsg(char *cert_file, char *plaintext_file, char *ciphertext_file);

int decryptmsg(char *cert_file, char *private_key_file, char *ciphertext_file, char *plaintext_file);

int signmsg(char *cert_file, char *private_key_file, char *unsigned_file, char *signed_file);

int verifysign(char *sender_cert_path, char *signed_file, char *verified_file);

int verifyunsign(char *signed_file, char *unverified_file);

#endif