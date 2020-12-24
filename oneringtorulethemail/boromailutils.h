#ifndef __BOROMAILUTILS_H__
#define __BOROMAILUTILS_H__

struct Node *getrecipientcerts(struct Node *recipients);

int sendmsg(bstring sender, struct Node *recipient, struct Node *recipients, bstring msgin);

// add verify sign and msgout

#endif