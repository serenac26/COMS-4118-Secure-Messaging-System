#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <grp.h>
#include <math.h>
#include <regex.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "bstrlib.h"
#include "utf8util.h"
#include "buniutil.h"
#include "bstraux.h"
#include "bsafe.h"
#include "bstrlibext.h"

#define DEBUG 1
#define GB 1000000000
#define MB 1000000

#define p(...)           \
  if (DEBUG)             \
  {                      \
    printf(__VA_ARGS__); \
  }

struct Node
{
  bstring str;
  struct Node *next;
};

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

bstring printList(struct Node *list)
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
        bcatcstr(result, ", ");
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
 * 1      sender exists
 * 0      sender does not exist or could not be accessed
 * -1     error setting egid
 */
int senderExists(bstring sender, gid_t mamamoo)
{
  if (setegid(mamamoo) == -1)
    return -1;
  struct stat folderstat;
  bstring path = bformat("../mail/%s", sender->data);
  int statresult = stat((char *)path->data, &folderstat);
  bdestroy(path);
  if (setegid(getgid()) == -1)
    return -1;

  if (statresult == 0)
  {
    return 1;
  }
  return 0;
}

/*
 * Returns
 * ===
 * 1      mailout looks good
 * 0      mailout looks bad
 */
int verifyMailOut(gid_t mamamoo)
{
  bstring path = bfromcstr("mail-out");
  struct stat mostat;
  int statresult = stat((char *)path->data, &mostat);
  bdestroy(path);
  if (statresult != 0)
    return 0;
  if (DEBUG && mamamoo == 0)
    return 1;
  return mostat.st_gid == mamamoo;
}

/*
 * Returns
 * ===
 * 1      wrong number of args
 * 2      if too few args
 * 3      regex did not compile successfully
 * 4      createList failed to malloc
 * 3      recipient does not exist or could not be accessed
 * 4      error while concatenating recipients
 * 5      error pipeing
 * 6      error duping
 * 7      error execing
 * 8      error writing
 * 9      error setting egid
 */
int main(int argc, char *argv[])
{
  signal(SIGPIPE, SIG_IGN);
  gid_t mamamoo = getegid();
  if (setegid(getgid()) == -1)
    return 9;

  if (argc != 1)
  {
    return 1;
  }

  regex_t mailfrom, rcptto, data;
  int value;
  value = regcomp(&mailfrom, "^\\.?mail from:<([a-z0-9\\+\\-_]+)>\n$", REG_EXTENDED | REG_ICASE);
  if (value != 0)
  {
    p("Regex did not compile successfully");
    exit(3);
  }
  value = regcomp(&rcptto, "^\\.?rcpt to:<([a-z0-9\\+\\-_]+)>\n$", REG_EXTENDED | REG_ICASE);
  if (value != 0)
  {
    p("Regex did not compile successfully");
    exit(3);
  }
  value = regcomp(&data, "^\\.?data\n$", REG_EXTENDED | REG_ICASE);
  if (value != 0)
  {
    p("Regex did not compile successfully");
    exit(3);
  }

  /*
   * Welcome to state shenanigans part 2
   * ===
   * 0    No message read
   * 1    Valid MAIL FROM read
   * 2    Valid RCPT TO read - can only validate "RCPT TO" and proper recipient format
   * 3    DATA read
   * 4    naughty message read
   * 5    . read - good message
   * 6    . read - bad message
   */

  int linenum = 0;
  while (1)
  {
    int state = 0;
    int msgSize = 0;

    struct Node *rcpts = createList();
    if (rcpts == NULL)
    {
      regfree(&mailfrom);
      regfree(&rcptto);
      regfree(&data);
      return 4;
    }
    struct Node *msgdata = createList();
    if (msgdata == NULL)
    {
      freeList(rcpts);
      regfree(&mailfrom);
      regfree(&rcptto);
      regfree(&data);
      return 4;
    }

    bstring sender = bfromcstr("");

    while (1)
    {

      // Message is over a GB, we move on
      if (msgSize > GB && state != 4)
      {
        fprintf(stderr, "Message is over a gigabyte\n");
        state = 4;
      }

      bstring inp = bgets_limit((bNgetc)fgetc, stdin, '\n', MB);
      linenum++;

      if (inp == NULL)
      {
        break;
      }
      // printf("%d %d %s", state, linenum, inp->data);

      regmatch_t mailfrommatch[2], rcpttomatch[2];
      int mailfromtest = regexec(&mailfrom, (char *)inp->data, 2, mailfrommatch, 0);
      int rcpttotest = regexec(&rcptto, (char *)inp->data, 2, rcpttomatch, 0);
      int datatotest = regexec(&data, (char *)inp->data, 0, NULL, 0);
      int onlydot = (inp->slen == 2 && inp->data[0] == '.' && inp->data[1] == '\n') || (inp->slen == 1 && inp->data[0] == '.');
      int ismblong = inp->slen == MB;

      if (ismblong && state != 3 && state != 2 && state != 4)
      {
        fprintf(stderr, "Non DATA line is over a megabyte\n");
        state = 4;
      }
      else if (state == 0 && mailfromtest != REG_NOMATCH)
      {
        bstring _sender = bmidstr(inp, mailfrommatch[1].rm_so, mailfrommatch[1].rm_eo - mailfrommatch[1].rm_so);
        int senderCheck = senderExists(_sender, mamamoo);
        if (senderCheck == 0)
        {
          bdestroy(_sender);
          fprintf(stderr, "Message is invalid on linenum %d due to invalid sender\n", linenum);
          state = 4;
        }
        else if (senderCheck == -1)
        {
          bdestroy(_sender);
          bdestroy(inp);
          regfree(&mailfrom);
          regfree(&rcptto);
          regfree(&data);
          bdestroy(sender);
          freeList(rcpts);
          freeList(msgdata);
          exit(9);
        }
        else
        {
          bassign(sender, _sender);
          bdestroy(_sender);

          state = 1;
        }
      }
      else if (state == 2 && rcpttotest != REG_NOMATCH && ismblong)
      {
        fprintf(stderr, "Non DATA line is over a megabyte\n");
        state = 4;
      }
      else if ((state == 1 || state == 2) && rcpttotest != REG_NOMATCH)
      {
        bstring _rcpt = bmidstr(inp, rcpttomatch[1].rm_so, rcpttomatch[1].rm_eo - rcpttomatch[1].rm_so);
        if (!inList(rcpts, _rcpt))
        {
          prependList(&rcpts, _rcpt);
        }
        else
        {
          bdestroy(_rcpt);
        }

        state = 2;
      }
      else if (state == 2 && datatotest != REG_NOMATCH)
      {
        state = 3;
      }
      else if (state == 3 && !onlydot)
      {
        if (inp->data[0] == '.')
        {
          bdelete(inp, 0, 1);
        }
        appendList(&msgdata, inp);
        continue;
      }
      else if (state == 3 && onlydot)
      {
        state = 5;
        bdestroy(inp);
        break;
      }
      else if (state == 4 && onlydot)
      {
        state = 6;
        bdestroy(inp);
        break;
      }
      else
      {
        if (state != 4)
        {
          fprintf(stderr, "Message is invalid on linenum %d\n", linenum);
        }
        state = 4;
      }

      msgSize += inp->slen;
      bdestroy(inp);
    }

    if (state == 5)
    {
      bstring recipients = printList(rcpts);

      struct Node *curr = rcpts;
      while (curr != NULL)
      {
        bstring r = curr->str;
        if (r != NULL)
        {
          int fd[2];
          if (pipe(fd) == -1)
          {
            regfree(&mailfrom);
            regfree(&rcptto);
            regfree(&data);
            bdestroy(recipients);
            bdestroy(sender);
            freeList(rcpts);
            freeList(msgdata);
            return 5;
          }
          pid_t pid = fork();
          if (pid == 0)
          {
            int d = dup2(fd[0], STDIN_FILENO);
            if (d == -1)
            {
              regfree(&mailfrom);
              regfree(&rcptto);
              regfree(&data);
              bdestroy(recipients);
              bdestroy(sender);
              freeList(rcpts);
              freeList(msgdata);
              exit(6);
            }
            close(fd[0]);
            close(fd[1]);
            if (!verifyMailOut(mamamoo))
            {
              regfree(&mailfrom);
              regfree(&rcptto);
              regfree(&data);
              bdestroy(recipients);
              bdestroy(sender);
              freeList(rcpts);
              freeList(msgdata);
              fprintf(stderr, "Incorrect permissions for mail-out\n");
              exit(10);
            };
            char *argv[] = {"mail-out", (char *)r->data, '\0'};
            if (setegid(mamamoo) == -1)
            {
              regfree(&mailfrom);
              regfree(&rcptto);
              regfree(&data);
              bdestroy(recipients);
              bdestroy(sender);
              freeList(rcpts);
              freeList(msgdata);
              exit(9);
            };
            execv("./mail-out", argv);
            if (setegid(getgid()) == -1)
            {
              regfree(&mailfrom);
              regfree(&rcptto);
              regfree(&data);
              bdestroy(recipients);
              bdestroy(sender);
              freeList(rcpts);
              freeList(msgdata);
              exit(9);
            };
            regfree(&mailfrom);
            regfree(&rcptto);
            regfree(&data);
            bdestroy(recipients);
            bdestroy(sender);
            freeList(rcpts);
            freeList(msgdata);
            exit(7);
          }
          else
          {
            close(fd[0]);
            bstring from = bformat("From: %s\n", sender->data);
            bstring to = bformat("To: %s\n\n", recipients->data);
            int w = write(fd[1], from->data, from->slen);
            if (w == -1 && errno != EPIPE)
            {
              bdestroy(from);
              bdestroy(to);
              bdestroy(recipients);
              bdestroy(sender);
              freeList(rcpts);
              freeList(msgdata);
              regfree(&mailfrom);
              regfree(&rcptto);
              regfree(&data);
              return 8;
            }
            w = write(fd[1], to->data, to->slen);
            if (w == -1 && errno != EPIPE)
            {
              bdestroy(from);
              bdestroy(to);
              bdestroy(recipients);
              bdestroy(sender);
              freeList(rcpts);
              freeList(msgdata);
              regfree(&mailfrom);
              regfree(&rcptto);
              regfree(&data);
              return 8;
            }
            bdestroy(from);
            bdestroy(to);
            struct Node *curr = msgdata;
            while (curr != NULL)
            {
              if (curr->str != NULL)
              {
                int w = write(fd[1], curr->str->data, curr->str->slen);
                if (w == -1 && errno != EPIPE)
                {
                  bdestroy(recipients);
                  bdestroy(sender);
                  freeList(rcpts);
                  freeList(msgdata);
                  regfree(&mailfrom);
                  regfree(&rcptto);
                  regfree(&data);
                  return 8;
                }
              }
              curr = curr->next;
            }
            close(fd[1]);
            int status;
            waitpid(pid, &status, 0);
            switch (WEXITSTATUS(status))
            {
            case 1:
              fprintf(stderr, "mail-out: %s\n", "too many args");
              break;
            case 2:
              fprintf(stderr, "mail-out: %s\n", "if too few args");
              break;
            case 3:
              fprintf(stderr, "mail-out: %s\n", "recipient does not exist or could not be accessed");
              break;
            case 4:
              fprintf(stderr, "mail-out: %s\n", "input is greater than a gigabyte");
              break;
            case 5:
              fprintf(stderr, "mail-out: %s\n", "recipient does not exist or could not be accessed while constructing message filename");
              break;
            }
          }
        }
        curr = curr->next;
      }
      bdestroy(recipients);
    }

    bdestroy(sender);
    freeList(rcpts);
    freeList(msgdata);

    if (feof(stdin))
    {
      break;
    }
  }
  regfree(&mailfrom);
  regfree(&rcptto);
  regfree(&data);
  return 0;
}