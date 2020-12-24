#include "utils.h"

int main(int mama, char **moo) {
  bstring test = bfromcstr("i say\nmama\nmama\nmoooooooo~");
  printf("%s\n", test->data);
  encodeMessage(test);
  printf("%s\n", test->data);
  decodeMessage(test);
  printf("%s\n", test->data);
  bdestroy(test);
}