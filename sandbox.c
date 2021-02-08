/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
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

#if defined(__FreeBSD__)

#include <sys/capsicum.h>

void
sandbox()
{
	if (cap_enter() == -1)
		err(1, "cap_enter");
}

#elif defined(__linux__)

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* thanks chromium' src/seccomp.c */
#if defined(__i386__)
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__x86_64__)
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__arm__)
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__aarch64__)
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__mips__)
#  if defined(__mips64)
#    if defined(__MIPSEB__)
#      define SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPS64
#    else
#      define SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPSEL64
#    endif
#  else
#    if defined(__MIPSEB__)
#      define SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPS
#    else
#      define SECCOMP_AUDIT_ARCH AUDIT_ARCH_MIPSEL
#    endif
#  endif
#else
#  error "Platform does not support seccomp filter yet"
#endif

/* uncomment to enable debugging.  ONLY FOR DEVELOPMENT */
/* #define SC_DEBUG */

#ifdef SC_DEBUG
# define SC_FAIL SECCOMP_RET_TRAP
#else
# define SC_FAIL SECCOMP_RET_KILL
#endif

/* make the filter more readable */
#define SC_ALLOW(nr)						\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##nr, 0, 1),	\
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#ifdef SC_DEBUG

#include <signal.h>
#include <unistd.h>

static void
sandbox_seccomp_violation(int signum, siginfo_t *info, void *ctx)
{
	(void)signum;
	(void)ctx;

	fprintf(stderr, "%s: unexpected system call (arch:0x%x,syscall:%d @ %p)\n",
	    __func__, info->si_arch, info->si_syscall, info->si_call_addr);
	_exit(1);
}

static void
sandbox_seccomp_catch_sigsys(void)
{
	struct sigaction act;
	sigset_t mask;

	memset(&act, 0, sizeof(act));
	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	act.sa_sigaction = &sandbox_seccomp_violation;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSYS, &act, NULL) == -1) {
		fprintf(stderr, "%s: sigaction(SIGSYS): %s\n",
		    __func__, strerror(errno));
		exit(1);
	}
	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
		fprintf(stderr, "%s: sigprocmask(SIGSYS): %s\n",
		    __func__, strerror(errno));
		exit(1);
	}
}
#endif	/* SC_DEBUG */

void
sandbox()
{
	struct sock_filter filter[] = {
		/* load the *current* architecture */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		    (offsetof(struct seccomp_data, arch))),
		/* ensure it's the same that we've been compiled on */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
		    SECCOMP_AUDIT_ARCH, 1, 0),
		/* if not, kill the program */
		BPF_STMT(BPF_RET | BPF_K, SC_FAIL),

		/* load the syscall number */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		    (offsetof(struct seccomp_data, nr))),

		/* allow logging on stdout */
		SC_ALLOW(write),
		SC_ALLOW(writev),
		SC_ALLOW(readv),

		/* these are used to serve the files.  note how we
		 * allow openat but not open. */
		SC_ALLOW(epoll_pwait),
		SC_ALLOW(epoll_ctl),
		SC_ALLOW(accept4),
		SC_ALLOW(read),
		SC_ALLOW(openat),
		SC_ALLOW(fstat),
		SC_ALLOW(close),
		SC_ALLOW(lseek),
		SC_ALLOW(brk),
		SC_ALLOW(mmap),
		SC_ALLOW(munmap),

		/* we need recvmsg to receive fd */
		SC_ALLOW(recvmsg),

		/* XXX: ??? */
		SC_ALLOW(getpid),

		/* alpine on amd64 */
		SC_ALLOW(clock_gettime),
		SC_ALLOW(madvise),

		/* void on aarch64 does a gettrandom */
		SC_ALLOW(getrandom),

		/* for directory listing */
		SC_ALLOW(getdents64),

		SC_ALLOW(exit),
		SC_ALLOW(exit_group),

		/* stuff used by syslog.  revisit once we move
		 * logging in its own process */
		SC_ALLOW(socket),
		SC_ALLOW(sendto),
		SC_ALLOW(connect),

		/* allow only F_GETFL and F_SETFL fcntl */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, 8),
		BPF_STMT(BPF_LD  | BPF_W | BPF_ABS,
		    (offsetof(struct seccomp_data, args[1]))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_GETFL, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_SETFL, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_SETFD, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SC_FAIL),

		/* re-load the syscall number */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		    (offsetof(struct seccomp_data, nr))),

		/* allow ioctl but only on fd 1, glibc doing stuff? */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		    (offsetof(struct seccomp_data, args[0]))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		/* disallow enything else */
		BPF_STMT(BPF_RET | BPF_K, SC_FAIL),
	};

	struct sock_fprog prog = {
		.len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

#ifdef SC_DEBUG
	sandbox_seccomp_catch_sigsys();
#endif

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		fprintf(stderr, "%s: prctl(PR_SET_NO_NEW_PRIVS): %s\n",
		    __func__, strerror(errno));
		exit(1);
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
		fprintf(stderr, "%s: prctl(PR_SET_SECCOMP): %s\n",
		    __func__, strerror(errno));
		exit(1);
	}
}

#elif defined(__OpenBSD__)

#include <unistd.h>

void
sandbox()
{
	struct vhost *h;

	for (h = hosts; h->domain != NULL; ++h) {
		if (unveil(h->dir, "r") == -1)
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
