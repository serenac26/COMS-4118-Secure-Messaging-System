#ifndef __BOROMAILUTILS_H__
#define __BOROMAILUTILS_H__

int encryptmsg(char *recipient_cert_file, char *plaintext_file, char *ciphertext_file);

int decryptmsg(char *cert_file, char *private_key_file, char *ciphertext_file, char *plaintext_file);

int signmsg(char *cert_file, char *pkey_file, char *msg_in, char *msg_out);

int verifysign(char *sender_cert_path, char *msg_file, char *ver_out_file);

int verifynoverify(char *msg_file, char *unver_out_file);

#endif