/*
 * Copyright (c) 2021, 2023 Omar Polo <op@omarpolo.com>
 * Copyright (c) 2022 Claudio Jeker <claudio@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "gmid.h"
#include "log.h"

#if defined(__OpenBSD__)

#include <unistd.h>

void
sandbox_main_process(void)
{
	if (pledge("stdio rpath wpath cpath inet dns sendfd", NULL) == -1)
		fatal("pledge");
}

void
sandbox_server_process(void)
{
	if (pledge("stdio rpath inet unix dns recvfd", NULL) == -1)
		fatal("pledge");
}

void
sandbox_crypto_process(void)
{
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");
}

void
sandbox_logger_process(void)
{
	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");
}

#elif HAVE_LANDLOCK

#include <linux/landlock.h>

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <errno.h>

/*
 * What's the deal with landlock?  While distro with linux >= 5.13
 * have the struct declarations, libc wrappers are missing.  The
 * sample landlock code provided by the authors includes these "shims"
 * in their example for the landlock API until libc provides them.
 */

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size,
    __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int
landlock_add_rule(int ruleset_fd, enum landlock_rule_type type,
    const void *attr, __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int
landlock_restrict_self(int ruleset_fd, __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

/*
 * Maybe we should ship with a full copy of the linux headers because
 * you never know...
 */

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER	(1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE	(1ULL << 14)
#endif

static int landlock_state;
static int landlock_fd;

/*
 * Initialize landlock, which is stupidly complicated.
 */
static int
landlock_init(void)
{
	struct landlock_ruleset_attr rattr = {
		/*
		 * List all capabilities currently defined by landlock.
		 * Failure in doing so will implicitly allow those actions
		 * (i.e. omitting READ_FILE will allow to read _any_ file.)
		 */
		.handled_access_fs =
		LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR |
		LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_REMOVE_DIR |
		LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_MAKE_CHAR |
		LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG |
		LANDLOCK_ACCESS_FS_MAKE_SOCK |
		LANDLOCK_ACCESS_FS_MAKE_FIFO |
		LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		LANDLOCK_ACCESS_FS_MAKE_SYM |
		LANDLOCK_ACCESS_FS_REFER |
		LANDLOCK_ACCESS_FS_TRUNCATE,
	};
	int fd, abi, saved_errno;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		return -1;

	abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi == -1)
		return -1;
	if (abi < 2)
		rattr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
	if (abi < 3)
		rattr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;

	landlock_state = 1;
	return landlock_create_ruleset(&rattr, sizeof(rattr), 0);
}

static int
landlock_lock(void)
{
	int saved_errno;

	if (landlock_restrict_self(landlock_fd, 0)) {
		saved_errno = errno;
		close(landlock_fd);
		errno = saved_errno;
		landlock_state = -1;
		return -1;
	}

	landlock_state = 2;
	close(landlock_fd);
	return 0;
}

static int
landlock_unveil(const char *path, const char *permissions)
{
	struct landlock_path_beneath_attr lpba;
	int fd, saved_errno;

	if (landlock_state == 0) {
		if ((landlock_fd = landlock_init()) == -1) {
			landlock_state = -1;
			/* this kernel doesn't have landlock built in */
			if (errno == ENOSYS || errno == EOPNOTSUPP)
				return 0;
			return -1;
		}
	}

	/* no landlock available */
	if (landlock_state == -1)
		return 0;

	if (path == NULL && permissions == NULL)
		return landlock_lock();

	if (path == NULL || permissions == NULL || landlock_state != 1) {
		errno = EINVAL;
		return -1;
	}

	if (!strcmp(permissions, "r")) {
		fd = open(path, O_PATH | O_CLOEXEC);
		if (fd == -1)
			return -1;
		lpba = (struct landlock_path_beneath_attr){
			.allowed_access =
			    LANDLOCK_ACCESS_FS_READ_FILE |
			    LANDLOCK_ACCESS_FS_READ_DIR,
			.parent_fd = fd,
		};
		if (landlock_add_rule(landlock_fd, LANDLOCK_RULE_PATH_BENEATH,
		    &lpba, 0) == -1) {
			saved_errno = errno;
			close(fd);
			errno = saved_errno;
			return -1;
		}
		close(fd);
	}

	return 0;
}

void
sandbox_main_process(void)
{
	return;
}

void
sandbox_server_process(void)
{
	if (landlock_unveil("/", "r") == -1)
		fatal("landlock_unveil(/)");

	if (landlock_unveil(NULL, NULL) == -1)
		fatal("landlock_unveil(NULL, NULL)");
}

void
sandbox_crypto_process(void)
{
	/* contrary to unveil(2), this removes all fs access. */
	if (landlock_unveil(NULL, NULL) == -1)
		fatal("landlock_unveil(NULL, NULL)");
}

void
sandbox_logger_process(void)
{
	/* contrary to unveil(2), this removes all fs access. */
	if (landlock_unveil(NULL, NULL) == -1)
		fatal("landlock_unveil(NULL, NULL)");
}

#else

void
sandbox_main_process(void)
{
	return;
}

void
sandbox_server_process(void)
{
	return;
}

void
sandbox_crypto_process(void)
{
	return;
}

void
sandbox_logger_process(void)
{
	return;
}

#endif
