#include "bstrlib.h"

extern bstring bgets_limit (bNgetc getcPtr, void * parm, char terminator, int limit);
extern int bgetsa_limit (bstring b, bNgetc getcPtr, void * parm, char terminator, int limit);