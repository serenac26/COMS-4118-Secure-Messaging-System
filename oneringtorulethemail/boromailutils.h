#ifndef __BOROMAILUTILS_H__
#define __BOROMAILUTILS_H__

int getrecipientcert(char *cert, bstring recipient);

int sendmsg(bstring recipient, bstring msgin);

int verifysign(char *sender, char *msg_file, char *ver_out_file);

int recvmsg(char* msgfile, char** msgout);

#endif