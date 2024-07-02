#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "iri.h"

int
main(void)
{
	struct iri	 iri;
	const char	*errstr = NULL;
	char		 buf[64];
	char		*line = NULL;
	size_t		 linesize = 0;
	ssize_t		 linelen;

	if ((linelen = getline(&line, &linesize, stdin)) == -1)
		return (1);

	if (line[linelen-1] == '\n')
		line[--linelen] = '\0';

	if (parse_iri(line, &iri, &errstr)) {
		if (serialize_iri(&iri, buf, sizeof(buf)))
			puts(buf);
	}

	free(line);
	if (ferror(stdin)) {
		perror("getline");
		return (1);
	}

	return (0);
}
