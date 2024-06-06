/*
 * public domain
 */

#include <stdio.h>
#include <stdlib.h>
#include <vis.h>

int
main(void)
{
	char buf[128];

	return strnvis(buf, sizeof(buf), "Hello, world!\n", 0);
}
