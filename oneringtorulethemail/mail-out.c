#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <math.h>
#include <regex.h>
#include "bstrlib.h"
#include "utf8util.h"
#include "buniutil.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"

#define DEBUG 0
#define GB 1000000000

#define p(...)           \
  if (DEBUG)             \
  {                      \
    printf(__VA_ARGS__); \
  }

/*
 * Returns
 * ===
 * 1      recip exists
 * 0      recip does not exist or could not be accessed
 * -1     error setting egid
 */
int recipExists(bstring recip)
{
  struct stat folderstat;
  bstring path = bformat("../mail/%s", recip->data);
  int statresult = stat((char *) path->data, &folderstat);
  bdestroy(path);

  if (statresult == 0)
  {
    return 1;
  }
  return 0;
}

/*
 * Returns
 * ===
 * 1     filename successfully written to filename
 * 0     recip does not exist or could not be accessed
 * -1    bassign failed
 */
int getMessageFilename(bstring recip, bstring filename)
{
  int file_count = 1;
  struct stat filestat;

  bstring _filename = bformat("../mail/%s/%05d", recip->data, file_count);

  while (stat((char *) _filename->data, &filestat) == 0) {
    file_count++;
    _filename = bformat("../mail/%s/%05d", recip->data, file_count);
  }
  
  int _i = bassign(filename, _filename);
  bdestroy(_filename);

  if (_i == BSTR_ERR)
  {
    return 1;
  }
  return 1;
}

/*
 * Returns
 * ===
 * 0      success
 * 1     too many args
 * 2     if too few args
 * 3     recipient does not exist or could not be accessed
 * 4     input is greater than a gigabyte
 * 5     recipient does not exist or could not be accessed while constructing message filename
 */
int main(int argc, char *argv[])
{
  if (argc > 2)
  {
    return 1;
  }
  else if (argc < 2)
  {
    return 2;
  }

  bstring recip = bfromcstr(argv[1]);
  if (!recipExists(recip))
  {
    bdestroy(recip);
    return 3;
  }

  bstring inp = bgets_limit((bNgetc)fgetc, stdin, '\0', GB+1);

  int _inpsize = inp->slen;
  if (_inpsize == GB+1)
  {
    bdestroy(recip);
    bdestroy(inp);
    return 4;
  }

  bstring filename = bfromcstr("");

  int r = getMessageFilename(recip, filename);
  if (r == 0)
  {
    bdestroy(recip);
    bdestroy(inp);
    bdestroy(filename);
    return 5;
  }
  bdestroy(recip);

  mode_t perms = 0777;
  FILE *fp = fopen((char *)filename->data, "w");

  fwrite(inp->data, 1, inp->slen, fp);

  fclose(fp);
  chmod((char *)filename->data, perms);
  bdestroy(filename);
  bdestroy(inp);
  return 0;
}