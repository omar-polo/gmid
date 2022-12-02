#include <sys/types.h>
#include <unistd.h>

int
main(void)
{
	return setresuid(-1, -1, -1) == -1;
}
