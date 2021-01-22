#include <stdio.h>

/* I need a big file made up of ascii characters.  dd if=/dev/zero is
 * thus not an option, truncate is not portable.  This is some order
 * of magnitude faster than the equivalent sh script */

int
main(int argc, char **argv)
{
	FILE *out;
	int i, j;

	if (argc != 2) {
		fprintf(stderr, "USAGE: %s <file>\n", *argv);
		return 1;
	}

	if ((out = fopen(argv[1], "w")) == NULL) {
		fprintf(stderr, "cannot open file: %s\n", argv[1]);
		return 1;
	}

	for (i = 0; i < 1024; ++i)
		for (j = 0; j < 1024; ++j)
			fprintf(out, "a\n");

	fclose(out);
	return 0;
}
