#ifndef __FARAMAILUTILS_H__
#define __FARAMAILUTILS_H__

int login(char *username, char *pw);

int checkmail(char *username);

int changepw(char *username, char *pw);

int getcert(char *cert, char *username, int revoke);

#endif