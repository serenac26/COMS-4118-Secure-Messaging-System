#include "bstrlib.h"

int bgetsa_limit(bstring b, bNgetc getcPtr, void *parm, char terminator, int limit)
{
  int c=0, d, e;

  if (b == NULL || b->mlen <= 0 || b->slen < 0 || b->mlen < b->slen ||
      getcPtr == NULL)
    return BSTR_ERR;
  d = b->slen;
  e = b->mlen - 2;

  // + int count = 0;
  int count = 0;

  // + && count++ <= limit
  while (count++ < limit && (c = getcPtr(parm)) >= 0)
  {
    if (d > e)
    {
      b->slen = d;
      if (balloc(b, d + 2) != BSTR_OK)
        return BSTR_ERR;
      e = b->mlen - 2;
    }
    b->data[d] = (unsigned char)c;
    d++;
    if (c == terminator)
      break;
  }

  b->data[d] = (unsigned char)'\0';
  b->slen = d;

  return d == 0 && c < 0;
}

/*  bstring bgets (bNgetc getcPtr, void * parm, char terminator)
 *
 *  Use an fgetc-like single character stream reading function (getcPtr) to
 *  obtain a sequence of characters which are concatenated into a bstring.
 *  The stream read is terminated by the passed in terminator function.
 *
 *  If getcPtr returns with a negative number, or the terminator character
 *  (which is appended) is read, then the stream reading is halted and the
 *  result obtained thus far is returned.  If no characters are read, or
 *  there is some other detectable error, NULL is returned.
 */
bstring bgets_limit(bNgetc getcPtr, void *parm, char terminator, int limit)
{
  bstring buff;

  // + , limit
  if (0 > bgetsa_limit(buff = bfromcstr(""), getcPtr, parm, terminator, limit) ||
      0 >= buff->slen)
  {
    bdestroy(buff);
    buff = NULL;
  }
  return buff;
}