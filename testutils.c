#include "utils.h"

int main(int mama, char **moo) {
  bstring test = bfromcstr("i say\nmama\nmama\nmoooooooo");
	for (int i = 0; i < 100; i++) {
		bconchar(test, '~');
		printf("%s\n", test->data);
		encodeMessage(test);
		printf("%s\n", test->data);
		decodeMessage(test);
		printf("%s\n", test->data);
	}
	bdestroy(test);

  bstring key = bfromcstr("members");
  bstring key2 = bfromcstr("mamamoo's\nmembers");
  bstring value = bfromcstr("moonbyul, solar, wheein, hwasa");
  bstring value2 = bfromcstr("moonbyul\nsolar\nwheein\nhwasa");
  bstring result = bfromcstr("");

	int sResult;

	sResult = serializeData(key, value, result, 0);
	printf("%d\n%s\n\n", sResult, result->data);

	sResult = deserializeData(key, value, result, 0);
	printf("%d\n%s\n%s\n\n", sResult, key->data, value->data);

	sResult = serializeData(key2, value2, result, 0);
	printf("%d\n%s\n\n", sResult, result->data);

	sResult = serializeData(key2, value2, result, 1);
	printf("%d\n%s\n\n", sResult, result->data);

	sResult = deserializeData(key2, value2, result, 1);
	printf("%d\n%s\n%s\n\n", sResult, key2->data, value2->data);

	bdestroy(key);
  bdestroy(key2);
  bdestroy(value);
  bdestroy(value2);
  bdestroy(result);
}