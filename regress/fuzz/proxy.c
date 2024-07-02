#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gmid.h"

int
main(void)
{
	struct proxy_protocol_v1 pp1;
	char			 buf[1024];
	char			*line = NULL;
	size_t			 consumed, linesize = 0;
	ssize_t			 linelen;

	memset(&pp1, 0, sizeof(pp1));
	memset(buf, 0, sizeof(buf));

	if ((linelen = getline(&line, &linesize, stdin)) == -1)
		return (1);

	if (proxy_proto_v1_parse(&pp1, line, linelen, &consumed) != -1) {
		switch (pp1.proto) {
		case PROTO_V4:
			inet_ntop(AF_INET, &pp1.srcaddr.v4, buf, sizeof(buf));
			break;
		case PROTO_V6:
			inet_ntop(AF_INET6, &pp1.srcaddr.v6, buf, sizeof(buf));
			break;
		case PROTO_UNKNOWN:
			strlcpy(buf, "UNKNOWN", sizeof(buf));
			break;
		default:
			abort();
		}
		puts(buf);
	}

	free(line);
	if (ferror(stdin)) {
		perror("getline");
		return (1);
	}

	return (0);
}
