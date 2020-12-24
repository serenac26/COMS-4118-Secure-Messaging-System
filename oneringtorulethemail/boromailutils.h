#ifndef __BOROMAILUTILS_H__
#define __BOROMAILUTILS_H__

#include "bstrlib.h"
#include "utf8util.h"
#include "buniutil.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"
#include "base64.h"

int getusercert(char *cert, bstring recipient);

int sendmessage(bstring recipient, bstring msgin);

int verifysign(char *sender, char *msg_file, char *ver_out_file);

int recvmessage(bstring msgfile, char** msgout);

int getOldestFilename(bstring recip, bstring filename);

#endif