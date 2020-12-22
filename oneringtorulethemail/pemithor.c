#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define DEBUG 1
#define BOROMAIL "boromail"
#define FARAMAIL "faramail"

#define p(...)           \
  if (DEBUG)             \
  {                      \
    printf(__VA_ARGS__); \
  }

/*
 * Returns
 * ===
 * 1      boromail + faramail look untampered
 * 0      russia hacked the election
 */
int verifyBoroFaraIntegrity(gid_t g)
{
  struct stat borostat, farastat;
  int borostatresult = stat(BOROMAIL, &borostat);
  int farastatresult = stat(FARAMAIL, &farastat);
  if (borostatresult != 0 || farastatresult != 0)
    return 0;
  if (DEBUG && g == 0)
  {
    p("root override on integrity check\n");
    return 1;
  }
  return borostat.st_gid == g && farastat.st_gid == g;
}

/*
 * Returns
 * ===
 * 1      russia
 * 0      all good no bad YES.
 */
int main(int mama, char **moo)
{
  gid_t g = getegid();
  if (!verifyBoroFaraIntegrity(g))
  {
    exit(1);
  }

  pid_t solar, hwasa;
  solar = fork();
  if (solar == 0)
  {
    char *wheein[] = {"boromail", NULL};
    execv("./boromail", wheein);
  }
  else
  {
    hwasa = fork();
    if (hwasa == 0)
    {
      char *moonbyul[] = {"faramail", NULL};
      execv("./faramail", moonbyul);
    }
  }
  for (int i = 0; i < 2; i++)
  {
    int status;
    if (wait(&status) >= 0)
    {
      printf("Child process exited with %d status\n", WEXITSTATUS(status));
    }
  }
}