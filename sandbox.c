#include "gmid.h"

#if defined(__FreeBSD__)

#include <sys/capsicum.h>
#include <err.h>

void
sandbox()
{
	struct vhost *h;
	int has_cgi = 0;

	for (h = hosts; h->domain != NULL; ++h)
		if (h->cgi != NULL)
			has_cgi = 1;

	if (cap_enter() == -1)
		err(1, "cap_enter");
}

#elif defined(__linux__)

void
sandbox()
{
	/* TODO: seccomp */
}

#elif defined(__OpenBSD__)

#include <err.h>
#include <unistd.h>

void
sandbox()
{
	struct vhost *h;

	for (h = hosts; h->domain != NULL; ++h) {
		if (unveil(h->dir, "rx") == -1)
			err(1, "unveil %s for domain %s", h->dir, h->domain);
	}

	if (pledge("stdio recvfd rpath inet", NULL) == -1)
		err(1, "pledge");
}

#else

void
sandbox()
{
        LOGN(NULL, "%s", "no sandbox method known for this OS");
}

#endif
