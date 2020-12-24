#ifndef __BOROMAILUTILS_H__
#define __BOROMAILUTILS_H__

int getusercert(char *cert, bstring recipient);

int sendmessage(bstring recipient, bstring msgin);

int verifysign(char *sender, char *msg_file, char *ver_out_file);

int recvmessage(bstring msgfile, char** msgout);

int getOldestFilename(bstring recip, bstring filename);

#endif