#include "utils.h"

struct Node *createList() {
  struct Node *node = (struct Node *)malloc(sizeof(struct Node));
  if (node == NULL) {
    return NULL;
  }
  node->next = NULL;
  node->str = NULL;
  return node;
}

int freeList(struct Node *list) {
  struct Node *curr = list;
  while (curr != NULL) {
    struct Node *prev = curr;
    curr = curr->next;
    bdestroy(prev->str);
    free(prev);
  }
  return 1;
}

int inList(struct Node *list, bstring str) {
  struct Node *curr = list;
  while (curr != NULL) {
    if (biseq(str, curr->str) == 1) return 1;
    curr = curr->next;
  }
  return 0;
}

int prependList(struct Node **list, bstring str) {
  struct Node *node = (struct Node *)malloc(sizeof(struct Node));
  if (node == NULL) {
    return 1;
  }
  node->next = *list;
  node->str = str;
  *list = node;
  return 1;
}

int appendList(struct Node **list, bstring str) {
  struct Node *curr = *list;
  while (curr->next != NULL) {
    curr = curr->next;
  }
  struct Node *node = (struct Node *)malloc(sizeof(struct Node));
  if (node == NULL) {
    return 1;
  }
  node->next = NULL;
  node->str = str;
  curr->next = node;
  return 1;
}

bstring printList(struct Node *list, const char *delim) {
  struct Node *curr = list;
  bstring result = bfromcstr("");
  int first = 1;
  while (curr != NULL) {
    if (curr->str != NULL) {
      if (!first) {
        bcatcstr(result, delim);
      } else {
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
int recipExists(bstring recip) {
  struct stat folderstat;
  bstring path = bformat("%s/%s", MAIL_PATH, recip->data);
  int statresult = stat((char *)path->data, &folderstat);
  bdestroy(path);

  if (statresult == 0) {
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
int getMessageFilename(bstring recip, bstring filename) {
  int file_count = 1;
  struct stat filestat;

  bstring _filename = bformat("../mail/%s/%05d", recip->data, file_count);

  while (stat((char *)_filename->data, &filestat) == 0) {
    bdestroy(_filename);
    file_count++;
    if (file_count > 99999) {
      return -2;
    }
    _filename = bformat("../mail/%s/%05d", recip->data, file_count);
  }

  int _i = bassign(filename, _filename);
  bdestroy(_filename);

  if (_i == BSTR_ERR) {
    return -1;
  }
  return 1;
}

/*
 * Encodes a bstring in-place
 */
void encodeMessage(bstring message) {
  char *result = base64_encode((char *)message->data);
  bassigncstr(message, result);
  free(result);
}

/*
 * Decodes a bstring in-place
 */
void decodeMessage(bstring message) {
  char *result = base64_decode((char *)message->data);
  bassigncstr(message, result);
  free(result);
}

/*
 * Serializes a data line, key : value, and stores the output in output.
 * Specify encode=1 in order to encode the key and the value.
 * ===
 * 1  invalid data line (key or value contains : or \n)
 * 0  success
 */
int serializeData(bstring key, bstring value, bstring output, int encode) {
  if (!encode) {
    for (int i = 0; i < key->slen; i++) {
      if (key->data[i] == '\n' || key->data[i] == ':') return 1;
    }
    for (int i = 0; i < value->slen; i++) {
      if (value->data[i] == '\n' || value->data[i] == ':') return 1;
    }
  }
  bstring newKey = bstrcpy(key);
  if (encode) encodeMessage(newKey);
  bstring newValue = bstrcpy(value);
  if (encode) encodeMessage(newValue);
  bstring result = bformat("%s:%s", newKey->data, newValue->data);
  bdestroy(newKey);
  bdestroy(newValue);
  bassign(output, result);
  bdestroy(result);
  return 0;
}

/*
 * Deserializes a data line, input, and stores the output in key and value
 * ===
 * 1  invalid data line
 * 0  success
 */
int deserializeData(bstring key, bstring value, bstring input, int decode) {
  struct bstrList *mamamoo = bsplit(input, ':');
  if (mamamoo->qty != 2) {
    bstrListDestroy(mamamoo);
    return 1;
  }
  bassign(key, mamamoo->entry[0]);
  bassign(value, mamamoo->entry[1]);
  if (decode) {
    decodeMessage(key);
    decodeMessage(value);
  }
  bstrListDestroy(mamamoo);
  return 0;
}

/*
 * Matches string to ARG regex expression and limit to 100 characters
 * ===
 * 1  invalid data line
 * 0  success
 */
int validArg(char *datastr) {
  if (strlen(datastr) > 100)
    return 0;
  regex_t reg;
  int value = regcomp(&reg, ARG_REGEX, REG_EXTENDED | REG_ICASE);
  if (value != 0)
    fprintf(stderr, "Regex did not compile successfully.\n");
  int r = regexec(&reg, datastr, 0, NULL, 0);
  regfree(&reg);
  return r != REG_NOMATCH;
}