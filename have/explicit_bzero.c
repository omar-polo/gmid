#include <string.h>

int
main(void)
{
	char buf[] = "hello world";

	explicit_bzero(buf, sizeof(buf));
	return strcmp(buf, "");
}
