/*
 * Copyright (c) 2020, 2021, 2022 Omar Polo <op@omarpolo.com>
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

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>

#include "logger.h"
#include "log.h"
#include "proc.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

static int main_configure(struct conf *);
static void main_configure_done(struct conf *);
static void main_reload(struct conf *);
static void main_sig_handler(int, short, void *);
static int main_dispatch_server(int, struct privsep_proc *, struct imsg *);
static int main_dispatch_logger(int, struct privsep_proc *, struct imsg *);
static void __dead main_shutdown(struct conf *);

static struct privsep_proc procs[] = {
	{ "server",	PROC_SERVER,	main_dispatch_server, server },
	{ "logger",	PROC_LOGGER,	main_dispatch_logger, logger },
};

static const char	*opts = "c:D:fI:hnP:T:Vv";

static const struct option longopts[] = {
	{"help",	no_argument,		NULL,	'h'},
	{"version",	no_argument,		NULL,	'V'},
	{NULL,		0,			NULL,	0},
};

struct fcgi fcgi[FCGI_MAX];

struct vhosthead hosts;

int sock4, sock6;
int privsep_process;
int pidfd = -1;

const char *config_path = "/etc/gmid.conf";
const char *pidfile;

struct conf conf;

static void
usage(void)
{
	fprintf(stderr,
	    "Version: " GMID_STRING "\n"
	    "Usage: %s [-fnv] [-c config] [-D macro=value] [-P pidfile]\n",
	    getprogname());
}

static int
write_pidfile(const char *pidfile)
{
	struct flock	lock;
	int		fd;

	if (pidfile == NULL)
		return -1;

	if ((fd = open(pidfile, O_WRONLY|O_CREAT|O_CLOEXEC, 0600)) == -1)
		fatal("can't open pidfile %s", pidfile);

	lock.l_start = 0;
	lock.l_len = 0;
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLK, &lock) == -1)
		fatalx("can't lock %s, gmid is already running?", pidfile);

	if (ftruncate(fd, 0) == -1)
		fatal("ftruncate %s", pidfile);

	dprintf(fd, "%d\n", getpid());

	return fd;
}

int
main(int argc, char **argv)
{
	struct privsep *ps;
	const char *errstr, *title = NULL;
	size_t i;
	int ch, conftest = 0;
	int proc_instance = 0;
	int proc_id = PROC_PARENT;
	int argc0 = argc;

	setlocale(LC_CTYPE, "");

	/* log to stderr until daemonized */
	log_init(1, LOG_DAEMON);
	config_init();

	while ((ch = getopt_long(argc, argv, opts, longopts, NULL)) != -1) {
		switch (ch) {
		case 'c':
			config_path = absolutify_path(optarg);
			break;
		case 'D':
			if (cmdline_symset(optarg) == -1)
				fatalx("could not parse macro definition: %s",
				    optarg);
			break;
		case 'f':
			conf.foreground = 1;
			break;
		case 'h':
			usage();
			return 0;
		case 'I':
			proc_instance = strtonum(optarg, 0, PROC_MAX_INSTANCES,
			    &errstr);
			if (errstr != NULL)
				fatalx("invalid process instance");
			break;
		case 'n':
			conftest++;
			break;
		case 'P':
			pidfile = absolutify_path(optarg);
			break;
		case 'T':
			title = optarg;
			proc_id = proc_getid(procs, nitems(procs), title);
			if (proc_id == PROC_MAX)
				fatalx("invalid process name");
			break;
		case 'V':
			puts("Version: " GMID_STRING);
			return 0;
		case 'v':
			conf.verbose++;
			break;
		default:
			usage();
			return 1;
		}
	}

	if (argc - optind != 0)
		usage();

	parse_conf(config_path);
	if (*conf.chroot != '\0' && *conf.user == '\0')
		fatalx("can't chroot without a user to switch to after.");

	if (conftest) {
		fprintf(stderr, "config OK\n");
		if (conftest > 1)
			print_conf();
		return 0;
	}

	if ((ps = calloc(1, sizeof(*ps))) == NULL)
		fatal("calloc");
	ps->ps_env = &conf;
	conf.ps = ps;
	if (*conf.user) {
		if (geteuid())
			fatalx("need root privileges");
		if ((ps->ps_pw = getpwnam(conf.user)) == NULL)
			fatalx("unknown user %s", conf.user);
	}

	ps->ps_instances[PROC_SERVER] = conf.prefork;
	ps->ps_instance = proc_instance;
	if (title != NULL)
		ps->ps_title[proc_id] = title;

	if (*conf.chroot != '\0') {
		for (i = 0; i < nitems(procs); ++i)
			procs[i].p_chroot = conf.chroot;
	}

	log_init(conf.foreground, LOG_DAEMON);
	log_setverbose(conf.verbose);
	if (title != NULL)
		log_procinit(title);

	/* only the parent returns */
	proc_init(ps, procs, nitems(procs), conf.foreground,
	    argc0, argv, proc_id);

	log_procinit("main");
	if (!conf.foreground && daemon(0, 0) == -1)
		fatal("daemon");

	pidfd = write_pidfile(pidfile);

	sandbox_main_process();

	event_init();

	signal(SIGPIPE, SIG_IGN);

	signal_set(&ps->ps_evsigint, SIGINT, main_sig_handler, ps);
	signal_set(&ps->ps_evsigterm, SIGTERM, main_sig_handler, ps);
	signal_set(&ps->ps_evsigchld, SIGCHLD, main_sig_handler, ps);
	signal_set(&ps->ps_evsighup, SIGHUP, main_sig_handler, ps);

	signal_add(&ps->ps_evsigint, NULL);
	signal_add(&ps->ps_evsigterm, NULL);
	signal_add(&ps->ps_evsigchld, NULL);
	signal_add(&ps->ps_evsighup, NULL);

	proc_connect(ps);

	if (main_configure(&conf) == -1)
		fatal("configuration failed");

	event_dispatch();
	main_shutdown(&conf);
	/* NOTREACHED */
	return 0;
}

static int
main_configure(struct conf *conf)
{
	struct privsep	*ps = conf->ps;

	conf->reload = conf->prefork;

	if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_START, NULL, 0) == -1)
		return -1;

	if (config_send(conf, fcgi, &hosts) == -1)
		return -1;

	if (proc_compose(ps, PROC_SERVER, IMSG_RECONF_END, NULL, 0) == -1)
		return -1;

	return 0;
}

static void
main_configure_done(struct conf *conf)
{
	if (conf->reload == 0) {
		log_warnx("configuration already done");
		return;
	}

	conf->reload--;
	/* send IMSG_CTL_START? */
}

static void
main_reload(struct conf *conf)
{
	if (conf->reload) {
		log_debug("%s: already in progress: %d pending",
		    __func__, conf->reload);
		return;
	}

	log_debug("%s: config file %s", __func__, config_path);
	config_free();
	parse_conf(config_path); /* XXX should handle error here */

	main_configure(conf);
}

static void
main_sig_handler(int sig, short ev, void *arg)
{
	struct privsep	*ps = arg;

	/*
	 * Normal signal handler rules don't apply here because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		if (privsep_process != PROC_PARENT)
			return;
		log_info("reload requested with SIGHUP");
		main_reload(ps->ps_env);
		break;
	case SIGCHLD:
		log_warnx("one child died, quitting");
		/* fallthrough */
	case SIGTERM:
	case SIGINT:
		main_shutdown(ps->ps_env);
		break;
	default:
		fatalx("unexpected signal %d", sig);
	}
}

static int
main_dispatch_server(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep	*ps = p->p_ps;
	struct conf	*conf = ps->ps_env;

	switch (imsg->hdr.type) {
	case IMSG_RECONF_DONE:
		main_configure_done(conf);
		break;
	default:
		return -1;
	}

	return 0;
}

static int
main_dispatch_logger(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep	*ps = p->p_ps;
	struct conf	*conf = ps->ps_env;

	switch (imsg->hdr.type) {
	case IMSG_RECONF_DONE:
		main_configure_done(conf);
		break;
	default:
		return -1;
	}

	return 0;
}

static void __dead
main_shutdown(struct conf *conf)
{
	proc_kill(conf->ps);
	config_free();
	free(conf->ps);
	/* free(conf); */

	log_info("parent terminating, pid %d", getpid());

	if (pidfd != -1)
		close(pidfd);

	exit(0);
}
