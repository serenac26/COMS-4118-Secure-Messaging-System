#include "utils.h"
#include "base64.h"

struct Node *createList()
{
  struct Node *node = (struct Node *)malloc(sizeof(struct Node));
  if (node == NULL)
  {
    return NULL;
  }
  node->next = NULL;
  node->str = NULL;
  return node;
}

int freeList(struct Node *list)
{
  struct Node *curr = list;
  while (curr != NULL)
  {
    struct Node *prev = curr;
    curr = curr->next;
    bdestroy(prev->str);
    free(prev);
  }
  return 1;
}

int inList(struct Node *list, bstring str)
{
  struct Node *curr = list;
  while (curr != NULL)
  {
    if (biseq(str, curr->str) == 1)
      return 1;
    curr = curr->next;
  }
  return 0;
}

int prependList(struct Node **list, bstring str)
{
  struct Node *node = (struct Node *)malloc(sizeof(struct Node));
  if (node == NULL)
  {
    return 1;
  }
  node->next = *list;
  node->str = str;
  *list = node;
  return 1;
}

int appendList(struct Node **list, bstring str)
{
  struct Node *curr = *list;
  while (curr->next != NULL)
  {
    curr = curr->next;
  }
  struct Node *node = (struct Node *)malloc(sizeof(struct Node));
  if (node == NULL)
  {
    return 1;
  }
  node->next = NULL;
  node->str = str;
  curr->next = node;
  return 1;
}

bstring printList(struct Node *list, const char *delim)
{
  struct Node *curr = list;
  bstring result = bfromcstr("");
  int first = 1;
  while (curr != NULL)
  {
    if (curr->str != NULL)
    {
      if (!first)
      {
        bcatcstr(result, delim);
      }
      else
      {
        first = 0;
      }
      bconcat(result, curr->str);
    }
    curr = curr->next;
  }
  return result;
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
  bstring path = bformat("%s/%s", MAIL_PATH, recip->data);
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
    bdestroy(_filename);
    file_count++;
    _filename = bformat("../mail/%s/%05d", recip->data, file_count);
  }
  
  int _i = bassign(filename, _filename);
  bdestroy(_filename);

  if (_i == BSTR_ERR)
  {
    return -1;
  }
  return 1;
}

/*
 * Encodes a bstring in-place
 */
void encodeMessage(bstring message) {
  char *result = base64_encode((char *) message->data);
  bdestroy(message);
  message = bfromcstr(result);
  free(result);
}

/*
 * Decodes a bstring in-place
 */
void decodeMessage(bstring message) {
  char *result = base64_decode((char *) message->data);
  bdestroy(message);
  message = bfromcstr(result);
  free(result);
}