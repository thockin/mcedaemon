/*
 *  mced.c - MCE daemon.
 *
 *  Based on code from acpid.
 *  Copyright (c) 2007 Tim Hockin (thockin@hockin.org)
 *  Copyright (c) 2007 Google, Inc. (thockin@google.com)
 *  Portions Copyright (c) 2004 Tim Hockin (thockin@hockin.org)
 *  Portions Copyright (c) 2001 Sun Microsystems
 *  Portions Copyright (c) 2000 Andrew Henroid
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/poll.h>
#include <grp.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>

#include "mced.h"
#include "cmdline.h"
#if ENABLE_MCEDB
#include "mcedb.h"
#endif
#if ENABLE_DBUS
#include "dbus.h"
#endif
#include "ud_socket.h"

/* global debug level */
int mced_debug_level;

/* do we log event info? */
int mced_log_events;

/* the number of non-root clients that are connected */
int mced_non_root_clients;

/* the size of a kernel MCE record in bytes */
size_t mced_kernel_record_len;

#if ENABLE_MCEDB
/* global database handle */
struct mce_database *mced_db;
#endif

/* statics */
static const char *progname;
static cmdline_int bootnum = -1;
static cmdline_int debug_level = 0;
static cmdline_bool log_events = 0;
static cmdline_string confdir = MCED_CONFDIR;
static cmdline_string device = MCED_EVENTFILE;
static cmdline_int max_interval_ms = MCED_MAX_INTERVAL;
static cmdline_int min_interval_ms = MCED_MIN_INTERVAL;
static cmdline_int mce_rate_limit = -1;
static cmdline_string socketfile = MCED_SOCKETFILE_V2;
static cmdline_string socketfile_compat = NULL;
static cmdline_bool nosocket = 0;
static cmdline_string socketgroup = NULL;
static cmdline_mode_t socketmode = MCED_SOCKETMODE;
static cmdline_bool foreground = 0;
static cmdline_string pidfile = MCED_PIDFILE;
static cmdline_int clientmax = MCED_CLIENTMAX;
static cmdline_int overflow_suppress_time = MCED_OVERFLOW_SUPPRESS_TIME;
static cmdline_bool retry_mcelog = 0;
#if ENABLE_MCEDB
static cmdline_string dbdir = MCED_DBDIR;
#endif
#if ENABLE_DBUS
static cmdline_bool no_dbus = 0;
static cmdline_bool use_session_dbus = 0;
#endif
static int mcelog_poll_works = 0;
static int log_is_open = 0;
static int fake_dev_mcelog = 0;
static enum {
	KERNEL_MCE_UNKNOWN = 0,
	KERNEL_MCE_V1,   /* the historical 'struct mce' layout */
	KERNEL_MCE_V2,   /* 2.6.31 made 'struct mce' changes */
} kernel_mce_version;

/*
 * Helpers
 */

static void do_help(const struct cmdline_opt *, ...);
static void do_version(const struct cmdline_opt *, ...);
static struct cmdline_opt mced_opts[] = {
	#if ENABLE_MCEDB
	{
		"B", "dbdir",
		CMDLINE_OPT_STRING, &dbdir,
		"<dir>", "Set the database directory"
	},
	#endif  /* ENABLE_MCEDB */
	{
		"d", "debug",
		CMDLINE_OPT_COUNTER, &debug_level,
		"", "Increase the debugging level (implies -f)"
	},
	{
		"f", "foreground",
		CMDLINE_OPT_BOOL, &foreground,
		"", "Run in the foreground"
	},
	{
		"b", "bootnum",
		CMDLINE_OPT_INT, &bootnum,
		"<num>", "Set the current boot number"
	},
	{
		"c", "confdir",
		CMDLINE_OPT_STRING, &confdir,
		"<dir>", "Set the configuration directory"
	},
	{
		"D", "device",
		CMDLINE_OPT_STRING, &device,
		"<file>", "Use the specified mcelog device"
	},
	{
		"R", "retrydev",
		CMDLINE_OPT_BOOL, &retry_mcelog,
		"", "Retry the mcelog device if it fails to open"
	},
	{
		"p", "pidfile",
		CMDLINE_OPT_STRING, &pidfile,
		"<file>", "Use the specified PID file"
	},
	{
		"l", "logevents",
		CMDLINE_OPT_BOOL, &log_events,
		"", "Log each MCE and handlers"
	},
	{
		"n", "mininterval",
		CMDLINE_OPT_INT, &min_interval_ms,
		"<num>", "Set the MCE polling min interval (in msecs)"
	},
	{
		"x", "maxinterval",
		CMDLINE_OPT_INT, &max_interval_ms,
		"<num>", "Set the MCE polling max interval (in msecs)"
	},
	{
		"r", "ratelimit",
		CMDLINE_OPT_INT, &mce_rate_limit,
		"<num>", "Limit the number of MCEs handled per second"
	},
	{
		"o", "oflowsuppress",
		CMDLINE_OPT_INT, &overflow_suppress_time,
		"<num>", "Set the log period for overflows (in secs)"
	},
	{
		"s", "socketfile",
		CMDLINE_OPT_STRING, &socketfile,
		"<file>", "Use the specified socket file"
	},
	{
		"S", "nosocket",
		CMDLINE_OPT_BOOL, &nosocket,
		"", "Don't listen on a UNIX socket (overrides -s)"
	},
	{
		"g", "socketgroup",
		CMDLINE_OPT_STRING, &socketgroup,
		"<group>", "Set the group on the socket file"
	},
	{
		"m", "socketmode",
		CMDLINE_OPT_MODE_T, &socketmode,
		"<mode>", "Set the permissions on the socket file"
	},
	{
		"C", "clientmax",
		CMDLINE_OPT_INT, &clientmax,
		"<num>", "Limit the number of non-root socket clients"
	},
	{
		"O", "oldsocket",
		CMDLINE_OPT_STRING, &socketfile_compat,
		"", "Use the specified v1-compatible socket file"
	},
	#if ENABLE_DBUS
	{
		NULL, "no-dbus",
		CMDLINE_OPT_BOOL, &no_dbus,
		"", "Don't send MCEs over D-Bus"
	},
	{
		NULL, "dbus-session-bus",
		CMDLINE_OPT_BOOL, &use_session_dbus,
		"", "Use D-Bus session bus, instead of system bus"
	},
	#endif
	{
		"v", "version",
		CMDLINE_OPT_CALLBACK, do_version,
		"", "Print version information and exit"
	},
	{
		"h", "help",
		CMDLINE_OPT_CALLBACK, do_help,
		"", "Print this help message and exit"
	},
	CMDLINE_OPT_END_OF_LIST
};

/*
 * Print usage info.
 */
static void
usage(FILE *out)
{
	const char *help_str;
	fprintf(out, "Usage: %s [OPTIONS]\n", cmdline_progname);
	fprintf(out, "\n");
	while ((help_str = cmdline_help(mced_opts))) {
		fprintf(out, "  %s\n", help_str);
	}
	fprintf(out, "\n");
}

/*
 * Parse command line arguments.
 */
static int
handle_cmdline(int *argc, const char ***argv)
{
	/* Parse the command line. */
	if (cmdline_parse(argc, argv, mced_opts) != 0) {
		usage(stderr);
		exit(EXIT_FAILURE);
	}
	if (*argc != 1) {
		fprintf(stderr,
		        "Unknown command line argument: '%s'\n\n", (*argv)[1]);
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	/*
	 * Post-process command line flags.
	 */
	mced_debug_level = debug_level;
	mced_log_events = log_events;
	if (mced_debug_level > 0) {
		foreground = 1;
	}
	if (max_interval_ms <= 0) {
		max_interval_ms = -1;
	}
	if (min_interval_ms < 0) {
		min_interval_ms = 0;
	}
	if (clientmax < 0) {
		clientmax = 0;
	}
	if (overflow_suppress_time < 0) {
		overflow_suppress_time = 0;
	}
	if (mce_rate_limit <= 0) {
		mce_rate_limit = -1;
	}
	if (socketfile_compat && socketfile_compat[0] == '\0') {
		socketfile_compat = MCED_SOCKETFILE_V1;
	}

	return 0;
}

/*
 * Helper function for handling '-h' cmdlines.
 */
static void
do_help(const struct cmdline_opt *opt __attribute__((unused)), ...)
{
	usage(stdout);
	exit(EXIT_SUCCESS);
}

/*
 * Helper function for handling '-v' cmdlines.
 */
static void
do_version(const struct cmdline_opt *opt __attribute__((unused)), ...)
{
	printf(PACKAGE "-" PRJ_VERSION "\n");
	exit(EXIT_SUCCESS);
}

static void
close_fds(void)
{
	int fd, max;
	max = sysconf(_SC_OPEN_MAX);
	for (fd = 3; fd < max; fd++)
		close(fd);
}

static int
daemonize(void)
{
	switch(fork()) {
	case -1:
		mced_log(LOG_ERR, "ERR: fork: %s\n", strerror(errno));
		return -1;
	case 0:
		/* child */
		break;
	default:
		/* parent */
		exit(EXIT_SUCCESS);
	}

	/* disconnect */
	setsid();
	umask(0);

	/* get out of the way */
	if (chdir("/") < 0) {
		mced_log(LOG_ERR, "ERR: chdir(\"/\"): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int
open_log(void)
{
	int nullfd;
	int log_opts;
	int ret;

	/* open /dev/null */
	nullfd = open("/dev/null", O_RDWR);
	if (nullfd < 0) {
		mced_log(LOG_ERR, "ERR: can't open /dev/null: %s\n",
		         strerror(errno));
		return -1;
	}

	log_opts = LOG_CONS|LOG_NDELAY;
	if (mced_debug_level > 0) {
		log_opts |= LOG_PERROR;
	}
	openlog(PACKAGE, log_opts, LOG_DAEMON);

	/* set up stdin, stdout, stderr to /dev/null */
	ret = 0;
	if (dup2(nullfd, STDIN_FILENO) != STDIN_FILENO) {
		mced_log(LOG_ERR, "LOG_ERR: dup2: %s\n", strerror(errno));
		ret = -1;
	}
	if (!mced_debug_level && dup2(nullfd, STDOUT_FILENO) != STDOUT_FILENO) {
		mced_log(LOG_ERR, "ERR: dup2: %s\n", strerror(errno));
		ret = -1;
	}
	if (!mced_debug_level && dup2(nullfd, STDERR_FILENO) != STDERR_FILENO) {
		mced_log(LOG_ERR, "ERR: dup2: %s\n", strerror(errno));
		ret = -1;
	}

	close(nullfd);
	log_is_open = 1;

	return ret;
}

static int
create_pidfile(void)
{
	int fd;

	/* JIC */
	unlink(pidfile);

	/* open the pidfile */
	fd = open(pidfile, O_WRONLY|O_CREAT|O_EXCL, 0644);
	if (fd >= 0) {
		FILE *f;

		/* write our pid to it */
		f = fdopen(fd, "w");
		if (f != NULL) {
			fprintf(f, "%d\n", getpid());
			fclose(f);
			/* leave the fd open */
			return 0;
		}
		close(fd);
	}

	/* something went wrong */
	mced_log(LOG_ERR, "ERR: can't create pidfile %s: %s\n",
	         pidfile, strerror(errno));
	return -1;
}

static void
clean_exit_with_status(int status)
{
	mced_cleanup_rules(1);
	#if ENABLE_MCEDB
	mcedb_close(mced_db);
	#endif
	unlink(pidfile);
	mced_log(LOG_NOTICE, "exiting\n");
	exit(status);
}

static void
clean_exit(int sig)
{
	mced_log(LOG_NOTICE, "caught signal %d\n", sig);
	clean_exit_with_status(EXIT_SUCCESS);
}

static void
clean_exit_with_killer(int signum, siginfo_t *siginfo,
                       void __attribute__((unused)) *context) {
	char fname[255];
	char cmdline[1023];
	int cmdline_success = 0;
	mced_log(LOG_NOTICE, "caught signal %d\n", signum);
	snprintf(fname, sizeof(fname)-1, "/proc/%u/cmdline", siginfo->si_pid);
	FILE *cmdline_file = fopen(fname, "r");

	if (cmdline_file) {
		if (fgets(cmdline, 1023, cmdline_file)) {
			cmdline_success = 1;
		}
		fclose(cmdline_file);
	}

	if (cmdline_success) {  // file successfully read
		mced_log(
			LOG_NOTICE,
			"killed by process with pid %u and command line %.1022s\n",
			siginfo->si_pid,
			cmdline);
	} else {
		mced_log(
			LOG_NOTICE,
			"killed by process with pid %u and unknown command line\n",
			siginfo->si_pid);
	}
	clean_exit_with_status(EXIT_SUCCESS);
}

static void
reload_conf(int sig __attribute__((unused)))
{
	mced_log(LOG_NOTICE, "reloading configuration\n");
	mced_cleanup_rules(0);
	mced_read_conf(confdir);
}

static int
mced_vlog(int level, const char *fmt, va_list args)
{
	if (log_is_open) {
		vsyslog(level, fmt, args);
	} else {
		vfprintf(stderr, fmt, args);
	}
	return 0;
}

int
mced_log(int level, const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = mced_vlog(level, fmt, args);
	va_end(args);

	return r;
}

int
mced_debug(int min_dbg_lvl, const char *fmt, ...)
{
	va_list args;
	int r;

	if (mced_debug_level < min_dbg_lvl) {
		return 0;
	}

	va_start(args, fmt);
	r = mced_vlog(LOG_DEBUG, fmt, args);
	va_end(args);

	return r;
}

int
mced_perror(int level, const char *str)
{
	return mced_log(level, "%s: %s\n", str, strerror(errno));
}

static int
open_socket(const char *path, mode_t mode, const char *group)
{
	int sock_fd;

	sock_fd = ud_create_socket(path);
	if (sock_fd < 0) {
		mced_log(LOG_ERR, "ERR: can't open socket %s: %s\n",
		         path, strerror(errno));
		return -1;
	}
	fcntl(sock_fd, F_SETFD, FD_CLOEXEC);
	chmod(path, mode);
	if (group) {
		struct group *gr;
		struct stat buf;
		gr = getgrnam(group);
		if (!gr) {
			mced_log(LOG_ERR, "ERR: group %s does not exist\n",
			         group);
			close(sock_fd);
			return -1;
		}
		if (stat(path, &buf) < 0) {
			mced_log(LOG_ERR, "ERR: can't stat %s\n", path);
			close(sock_fd);
			return -1;
		}
		if (chown(path, buf.st_uid, gr->gr_gid) < 0) {
			mced_log(LOG_ERR, "ERR: chown(): %s\n",
			         strerror(errno));
			close(sock_fd);
			return -1;
		}
	}

	return sock_fd;
}

/* convert a kernel MCE struct to our MCE struct */
static void
kmce_to_mce(struct kernel_mce *kmce, struct mce *mce)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	/* common fields for all versions of 'struct kernel_mce' */
	mce->boot = bootnum;
	mce->bank = kmce->bank;
	mce->mci_status = kmce->status;
	mce->mci_address = kmce->addr;
	mce->mci_misc = kmce->misc;
	mce->mcg_status = kmce->mcgstatus;
	mce->tsc = kmce->tsc;
	mce->cs = kmce->cs;
	mce->ip = kmce->rip;

	if (kernel_mce_version == KERNEL_MCE_V1) {
		mce->time = (tv.tv_sec * 1000000ULL) + tv.tv_usec;
		mce->cpu = kmce->cpu;
		mce->socket = -1;
		mce->vendor = VENDOR_UNKNOWN;
		mce->cpuid_eax = 0;
		mce->init_apic_id = (uint32_t)-1U;
		mce->mcg_status = 0;
	} else if (kernel_mce_version == KERNEL_MCE_V2) {
		if (kmce->time != 0) {
			mce->time = kmce->time * 1000000ULL;
		} else {
			mce->time = (tv.tv_sec * 1000000ULL) + tv.tv_usec;
		}
		mce->cpu = kmce->extcpu;
		mce->socket = kmce->socketid;
		mce->vendor = kmce->cpuvendor;
		mce->cpuid_eax = kmce->cpuid;
		mce->init_apic_id = kmce->apicid;
		mce->mcg_status = kmce->mcgcap;
	} else {
		/* this should never happen */
		mced_log(LOG_EMERG,
		         "FATAL: kernel_mce_version (%d) is unknown\n",
		         kernel_mce_version);
		clean_exit_with_status(EXIT_FAILURE);
	}
}

/* this is used in a few places to throttle messages */
struct rate_limit {
	int initialized;		/* first one been done? */
	int period;			/* milliseconds */
	struct timeval last_time;	/* last time we hit this */
};
#define RATE_LIMIT(ms) { \
	.initialized = 0, \
	.period = ms, \
	.last_time = { 0, 0} \
}

/* subtract two timevals */
static int
elapsed_usecs(struct timeval *t0, struct timeval *t1)
{
	int elapsed = (t1->tv_sec - t0->tv_sec) * 1000000;
	elapsed += (t1->tv_usec - t0->tv_usec);
	return elapsed;
}

/* do we need to apply rate limiting? */
static int
apply_rate_limit(struct rate_limit *limit)
{
	struct timeval now;
	int msecs_since_last;

	if (!limit->initialized) {
		/* first time through here, just remember it */
		limit->initialized = 1;
		gettimeofday(&limit->last_time, NULL);
		return 0;
	}

	/* find how long it has been since the last event */
	gettimeofday(&now, NULL);
	msecs_since_last = elapsed_usecs(&limit->last_time, &now) / 1000;

	/* has enough time elapsed? */
	if (msecs_since_last < limit->period) {
		/* rate limit */
		return 1;
	}

	/* do not rate limit */
	limit->last_time = now;
	return 0;
}

/* process a single MCE */
static int
do_one_mce(struct kernel_mce *kmce)
{
	struct mce mce;
	static struct rate_limit hw_overflow_limit;
	static int rate_limit_initialized = 0;

	/* initialize the rate limits based on a commandline flag */
	if (!rate_limit_initialized) {
		rate_limit_initialized = 1;
		hw_overflow_limit.period = overflow_suppress_time * 1000;
	}

	/* convert the kernel's MCE struct to our own */
	kmce_to_mce(kmce, &mce);

	/* check for overflow */
	if ((mce.mci_status & MCI_STATUS_OVER)
	 && (mced_log_events || !apply_rate_limit(&hw_overflow_limit))) {
		mced_log(LOG_WARNING, "MCE overflow detected by hardware\n");
		if (!mced_log_events && overflow_suppress_time) {
			mced_log(LOG_WARNING,
			    "(previous message suppressed for %lld seconds)",
			    overflow_suppress_time);
		}
	}

	#if ENABLE_MCEDB
	if (mcedb_append(mced_db, &mce) < 0) {
		mced_log(LOG_ERR,
		    "ERR: failed to append MCE to database - not good!!\n");
	} else {
		mced_debug(1, "DBG: logged MCE #%d\n", mcedb_end(mced_db)-1);
	}
	#endif
	if (mced_log_events) {
		mced_log(LOG_INFO, "starting MCE handlers\n");
	}
	mced_handle_mce(&mce);
	if (mced_log_events) {
		mced_log(LOG_INFO, "completed MCE handlers\n");
	}
	#if ENABLE_DBUS
	if (!no_dbus) {
		dbus_send_mce(&mce);
	}
	#endif
	return 0;
}

/* get the MCE log length from the kernel */
static int
get_loglen(int mce_fd)
{
	if (!fake_dev_mcelog) {
		int loglen;
		int r = ioctl(mce_fd, MCE_GET_LOG_LEN, &loglen);
		if (r < 0) {
			mced_perror(LOG_ERR, "ERR: ioctl(MCE_GET_LOG_LEN)");
			return -1;
		}
		return loglen;
	} else {
		return 1;
	}
}

/* add some usecs to a timeval */
static void
advance_time_usecs(struct timeval *tv, int adv_usecs)
{
	uint64_t tv_us = (tv->tv_sec * 1000000) + tv->tv_usec + adv_usecs;
	tv->tv_sec = tv_us / 1000000;
	tv->tv_usec = tv_us % 1000000;
}

/* enforce MCE rate limiting */
static void
rate_limit_mces(void)
{
	static int first_event = 1;
	static struct timeval last_timestamp;
	static int bias;

	if (mce_rate_limit <= 0) {
		/* no rate limiting */
		return;
	} else if (first_event) {
		/* first time through here, just remember it */
		first_event = 0;
		gettimeofday(&last_timestamp, NULL);
	} else {
		/* we might have to rate limit */
		struct timeval now;
		int usecs_since_last;
		int usecs_per_event = 1000000 / mce_rate_limit;

		/* find how long it has been since the last event */
		gettimeofday(&now, NULL);
		usecs_since_last = elapsed_usecs(&last_timestamp, &now);

		/* set the last_timestamp to now, we might change it later */
		last_timestamp = now;

		/* are we under the minimum time between events? */
		if (usecs_per_event > usecs_since_last) {
			int usecs_to_kill;
			int missed_by;

			/*
			 * We set the last_timestamp to the *ideal* time
			 * (now + usecs_to_kill), rather than the real
			 * time after the usleep().  This is because
			 * usleep() (and all other sleeps, really) is
			 * inaccurate with very small values.  This gets
			 * us closer to the actual requested rate
			 * limiting.
			 *
			 * We also try to bias the sleep time based on
			 * past inaccuracy.  We integrate the over/under
			 * deltas somewhat slowly, so large transients
			 * should not distort the bias too quickly.
			 */
			usecs_to_kill = usecs_per_event - usecs_since_last;
			advance_time_usecs(&last_timestamp, usecs_to_kill);
			if ((usecs_to_kill + bias) > 0) {
				/* do the actual sleep */
				usleep(usecs_to_kill + bias);
			}
			/* adjust the bias */
			gettimeofday(&now, NULL);
			missed_by = elapsed_usecs(&last_timestamp, &now);
			bias -= missed_by / 8;
		}
	}
}

/* read and handle and MCEs that are pending in the kernel */
static int
do_pending_mces(int mce_fd)
{
	int loglen;
	int nmces = 0;
	int flags = 0;
	static struct rate_limit sw_overflow_limit;
	static int rate_limit_initialized = 0;

	/* initialize the rate limits based on a commandline flag */
	if (!rate_limit_initialized) {
		rate_limit_initialized = 1;
		sw_overflow_limit.period = overflow_suppress_time * 1000;
	}

	/* check for MCEs */
	loglen = get_loglen(mce_fd);
	if (loglen > 0) {
		uint8_t buf[mced_kernel_record_len*loglen];
		int n;

		/* read all of the MCE data */
		n = read(mce_fd, buf, mced_kernel_record_len*loglen);
		if (n < 0) {
			if (fake_dev_mcelog && errno == EAGAIN) {
				return 0;
			}
			mced_perror(LOG_ERR, "ERR: read()");
			return -1;
		}

		/* did we get any MCES? */
		nmces = n/mced_kernel_record_len;
		if (nmces > 0) {
			int i;

			/* read the flags */
			if (!fake_dev_mcelog
			 && ioctl(mce_fd, MCE_GETCLEAR_FLAGS, &flags) < 0) {
				mced_log(LOG_ERR, "ERR: can't get flags: %s\n",
				         strerror(errno));
				return -1;
			}

			/* check for overflow */
			if ((flags & MCE_FLAG_OVERFLOW)
			 && (mced_log_events
			  || !apply_rate_limit(&sw_overflow_limit))){
				mced_log(LOG_WARNING,
				    "MCE overflow detected by software\n");
				if (!mced_log_events
				 && overflow_suppress_time) {
					mced_log(LOG_WARNING,
					    "(previous message suppressed "
					    "for %lld seconds)",
					    overflow_suppress_time);
				}
			}

			if (mced_log_events) {
				mced_debug(1, "DBG: got %d MCE%s\n",
				           nmces, (nmces==1)?"":"s");
			}

			/* handle all the new MCEs */
			for (i = 0; i < nmces; i++) {
				struct kernel_mce kmce;
				rate_limit_mces();
				/* The assumption is that newer versions of
				 * 'struct kernel_mce' are guaranteed to be
				 * supersets of older versions. */
				memcpy(&kmce, &buf[i*mced_kernel_record_len],
				       mced_kernel_record_len);
				do_one_mce(&kmce);
			}
		}
	}

	return nmces;
}

/* see if poll() works on /dev/mcelog */
static int
check_mcelog_poll(int mce_fd)
{
	if (!CHECK_FOR_NON_POLL_KERNELS) {
	  return 1;
	}

	// On a machine with a lot of errors, this loops forever!
	while (1) {
		int r;
		struct pollfd ar[1];

		/* try poll() on mcelog and see what happens */
		ar[0].fd = mce_fd;
		ar[0].events = POLLIN;
		r = poll(ar, 1, 0);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			mced_perror(LOG_ERR, "ERR: poll()");
			return 0;
		}

		/* if poll() reports a timeout, we assume it works */
		if (r == 0) {
			return 1;
		}

		/*
		 * If poll() reports data, we have to read it to find out
		 * if there is actually data, or if it is a bogus return.
		 * If we find data, we need to retry.  We can't be sure
		 * poll() works unless we can trigger some behavior that
		 * is not present in non-poll() kernels.  That's a
		 * timeout.  If poll() reports data, but read() finds
		 * none, we can assume poll() does not work.
		 */
		if (ar[0].revents) {
			if (ar[0].revents & POLLIN) {
				if (do_pending_mces(mce_fd) > 0) {
					continue;
				}
			} else {
				mced_log(LOG_WARNING,
				    "odd, poll set flags 0x%x\n",
				    ar[0].revents);
			}
		}
		break;
	}

	return 0;
}

static int
get_kernel_version(unsigned *vmajor, unsigned *vminor, unsigned *vmicro)
{
	struct utsname u;

	int r = uname(&u);
	if (r < 0) {
		return r;
	}

	r = sscanf(u.release, "%u.%u.%u", vmajor, vminor, vmicro);
	if (r != 3) {
		errno = EBADMSG;
		return -1;
	}
	mced_debug(1, "DBG: found kernel %u.%u.%u\n",
	           *vmajor, *vminor, *vmicro);
	return 0;
}

static int
init_kernel_mce_interface(int mce_fd)
{
	if (fake_dev_mcelog) {
		mced_kernel_record_len = sizeof(struct kernel_mce);
		kernel_mce_version = KERNEL_MCE_V1;
	} else {
		int r;

		/* Adjust for kernel versions. */
		unsigned vmajor, vminor, vmicro;
		r = get_kernel_version(&vmajor, &vminor, &vmicro);
		if (r < 0) {
			static int printed_msg;
			if (!printed_msg) {
				printed_msg = 1;
				mced_perror(LOG_ERR,
				            "ERR: can't get kernel version\n");
			}
			return -1;
		}

		/* assume the historical kernel layout */
		kernel_mce_version = KERNEL_MCE_V1;

		/* there were layout changes in 2.6.31 */
		if ((vmajor > 2)
		 || (vmajor == 2 && vminor > 6)
		 || (vmajor == 2 && vminor == 6 && vmicro >= 31)) {
			kernel_mce_version = KERNEL_MCE_V2;
		}

		/* Figure out the kernel's 'struct mce' size. */
		r = ioctl(mce_fd, MCE_GET_RECORD_LEN, &mced_kernel_record_len);
		if (r < 0) {
			static int printed_msg;
			if (!printed_msg) {
				printed_msg = 1;
				mced_perror(LOG_ERR,
				            "ERR: can't get MCE record size\n");
			}
			return -1;
		}
	}

	/*
	 * Sanity check the results.
	 */

	/* This should not happen. */
	if (kernel_mce_version == KERNEL_MCE_UNKNOWN) {
		static int printed_msg;
		if (!printed_msg) {
			printed_msg = 1;
			mced_log(LOG_ERR,
			         "ERR: kernel MCE version is unknown\n");
		}
		return -1;
	}

	/*
	 * If the kernel grew 'struct mce' we will catch it here.  If they
	 * simply changed the meaning of fields (hopefully only reserved
	 * fields), then we will not catch it.  Let's hope they don't do
	 * this.
	 */
	if (mced_kernel_record_len > sizeof(struct kernel_mce)) {
		static int printed_msg;
		if (!printed_msg) {
			printed_msg = 1;
			mced_log(LOG_ERR, "ERR: kernel MCE record size (%zd) "
			         "is unsupported\n", mced_kernel_record_len);
		}
		return -1;
	}
	return 0;
}

static int
open_mcelog(const char *path)
{
	struct stat stbuf;
	int mce_fd;

	if (stat(path, &stbuf) < 0) {
		static int printed_msg;
		if (!printed_msg) {
			printed_msg = 1;
			mced_log(LOG_ERR, "ERR: can't stat %s: %s\n",
			            path, strerror(errno));
		}
		return -1;
	}
	if (ENABLE_FAKE_DEV_MCELOG && S_ISFIFO(stbuf.st_mode)) {
		static int printed_msg;
		if (!printed_msg) {
			printed_msg = 1;
			mced_log(LOG_ERR,
			         "WARNING: using a fake mcelog device\n");
		}
		fake_dev_mcelog = 1;
	}
	mce_fd = open(path, O_RDONLY|O_EXCL|O_NONBLOCK);
	if (mce_fd < 0) {
		static int printed_msg;
		if (!printed_msg) {
			printed_msg = 1;
			mced_log(LOG_ERR, "ERR: can't open %s: %s\n",
			         path, strerror(errno));
		}
		return -1;
	}
	if (init_kernel_mce_interface(mce_fd) != 0) {
		close(mce_fd);
		return -1;
	}

	/* set the device to close on exec() */
	fcntl(mce_fd, F_SETFD, FD_CLOEXEC);

	/* see if mcelog supports poll() */
	mcelog_poll_works = check_mcelog_poll(mce_fd);

	return mce_fd;
}

static int
get_mcelog_fd(void)
{
	static int fd = -1;
	if (fd < 0) {
		static int printed_msg;
		fd = open_mcelog(device);
		if (fd < 0 && !retry_mcelog) {
			exit(EXIT_FAILURE);
		}
		if (fd < 0 && !printed_msg) {
			printed_msg = 1;
			mced_log(LOG_INFO, "Will retry in %lld ms\n",
			         max_interval_ms);
		}
	}
	return fd;
}

int
main(int argc, const char *argv[])
{
	int mcelog_fd;
	int sock_fd = -1; /* init to avoid a compiler warning */
	int compat_sock_fd = -1;
	int interval_ms;

	/* learn who we really are */
	progname = strrchr(argv[0], '/');
	progname = progname ? (progname + 1) : argv[0];

	/* handle the commandline  */
	handle_cmdline(&argc, &argv);

	/* close any extra file descriptors */
	close_fds();

	/* open our socket(s) */
	if (!nosocket) {
		sock_fd = open_socket(socketfile, socketmode, socketgroup);
		if (sock_fd < 0) {
			exit(EXIT_FAILURE);
		}
		if (socketfile_compat) {
			compat_sock_fd = open_socket(socketfile_compat,
			                             socketmode, socketgroup);
			if (compat_sock_fd < 0) {
				exit(EXIT_FAILURE);
			}
		}
	}

	/* if we're running in foreground, we don't daemonize */
	if (!foreground) {
		if (daemonize() < 0) {
			exit(EXIT_FAILURE);
		}
	}

	/* open the log */
	if (open_log() < 0) {
		exit(EXIT_FAILURE);
	}
	mced_log(LOG_NOTICE, "starting up\n");

	#if ENABLE_MCEDB
	/* open the database */
	mced_db = mcedb_open(dbdir);
	if (!mced_db) {
		mced_log(LOG_ERR, "aborting");
		exit(EXIT_FAILURE);
	}
	#endif

	#if ENABLE_DBUS
	if (!no_dbus) {
		int which_bus = DBUS_BUS_SYSTEM;
		if (use_session_dbus) {
			which_bus = DBUS_BUS_SESSION;
		}
		/* enable D-Bus */
		dbus_init(which_bus);
	}
	#endif

	/* trap key signals */
	signal(SIGHUP, reload_conf);
	signal(SIGINT, clean_exit);
	signal(SIGQUIT, clean_exit);
	signal(SIGPIPE, SIG_IGN);

	// Also handle SIGTERM, but we want the siginfo_t from it.
	struct sigaction sigterm_action = {
		.sa_sigaction = clean_exit_with_killer,
		.sa_flags = SA_SIGINFO,
	};

	sigaction(SIGTERM, &sigterm_action, 0);

	/* read in our configuration */
	if (mced_read_conf(confdir) < 0) {
		mced_log(LOG_ERR, "aborting");
		exit(EXIT_FAILURE);
	}

	/* create our pidfile */
	if (create_pidfile() < 0) {
		mced_log(LOG_ERR, "aborting");
		exit(EXIT_FAILURE);
	}

	/* main loop */
	if (mce_rate_limit > 0) {
		mced_log(LOG_INFO, "rate limiting MCEs to %lld per second\n",
		         mce_rate_limit);
	}
	mced_log(LOG_INFO, "waiting for events: per-event logging is %s\n",
	         mced_log_events ? "on" : "off");
	interval_ms = max_interval_ms;
	while (1) {
		struct pollfd ar[3];
		int r;
		int nfds = 0;
		int mce_idx = -1;
		int sock_idx = -1;
		int compat_sock_idx = -1;
		int timed_out;

		/* open the device file */
		mcelog_fd = get_mcelog_fd();

		/* poll on the mcelog */
		if (mcelog_fd >= 0 && mcelog_poll_works) {
			ar[nfds].fd = mcelog_fd;
			ar[nfds].events = POLLIN;
			mce_idx = nfds;
			nfds++;
		}

		/* poll on the socket */
		if (!nosocket) {
			ar[nfds].fd = sock_fd;
			ar[nfds].events = POLLIN;
			sock_idx = nfds;
			nfds++;
			if (socketfile_compat) {
				ar[nfds].fd = compat_sock_fd;
				ar[nfds].events = POLLIN;
				compat_sock_idx = nfds;
				nfds++;
			}
		}
		if (max_interval_ms > 0) {
			mced_debug(2, "DBG: next interval = %d msecs\n",
			           interval_ms);
		}
		r = poll(ar, nfds, interval_ms);
		if (r < 0 && errno == EINTR) {
			continue;
		} else if (r < 0) {
			mced_perror(LOG_ERR, "ERR: poll()");
			continue;
		}
		/* see if poll() timed out */
		if (r == 0) {
			timed_out = 1;
			mced_debug(1, "DBG: poll timeout\n");
		} else {
			timed_out = 0;
		}

		/* house keeping */
		mced_close_dead_clients();

		/*
		 * Was it an MCE?  Be paranoid and always check.
		 */
		if (mce_idx >= 0 && ar[mce_idx].revents) {
			int n;

			/* check for MCEs */
			n = do_pending_mces(mcelog_fd);
			if (n == 0 && !timed_out && fake_dev_mcelog) {
				/* FIFO closed */
				mced_log(LOG_INFO,
				         "fake mcelog device closed\n");
				break;
			}
			/* if we are actively polling, adjust intervals */
			if (max_interval_ms > 0) {
				if (n == 0 && timed_out) {
					interval_ms *= 2;
					if (interval_ms > max_interval_ms) {
						interval_ms = max_interval_ms;
					}
				} else if (n > 0) {
					interval_ms /= 2;
					if (interval_ms < min_interval_ms) {
						interval_ms = min_interval_ms;
					}
				}
			}
		}

		/* was it a new connection? */
		if ((sock_idx >= 0 && ar[sock_idx].revents)
		 || (compat_sock_idx >= 0 && ar[compat_sock_idx].revents)) {
			int cli_fd;
			struct ucred creds;
			char buf[32];
			static int accept_errors;
			int idx;
			int fd;
			int is_legacy_client;

			/*
			 * Prefer the new socket if forced to choose.
			 * We'll get the old socket on the next loop.
			 */
			if (sock_idx >= 0 && ar[sock_idx].revents) {
				is_legacy_client = 0;
				idx = sock_idx;
				fd = sock_fd;
			} else {
				is_legacy_client = 1;
				idx = compat_sock_idx;
				fd = compat_sock_fd;
			}

			/* this shouldn't happen */
			if (!(ar[idx].revents & POLLIN)) {
				mced_log(LOG_WARNING,
				    "odd, poll set flags 0x%x\n",
				    ar[idx].revents);
				continue;
			}

			/* accept and add to our lists */
			cli_fd = ud_accept(fd, &creds);
			if (cli_fd < 0) {
				mced_perror(LOG_ERR,
				    "ERR: can't accept client");
				accept_errors++;
				if (accept_errors >= 5) {
					mced_log(LOG_ERR, "giving up\n");
					clean_exit_with_status(EXIT_FAILURE);
				}
				continue;
			}
			accept_errors = 0;
			if (creds.uid != 0
			 && mced_non_root_clients >= clientmax) {
				close(cli_fd);
				mced_log(LOG_ERR,
				         "too many non-root clients\n");
				continue;
			}
			if (creds.uid != 0) {
				mced_non_root_clients++;
			}
			fcntl(cli_fd, F_SETFD, FD_CLOEXEC);
			snprintf(buf, sizeof(buf)-1, "%d[%d:%d]",
				creds.pid, creds.uid, creds.gid);
			mced_add_client(cli_fd, buf, is_legacy_client);
		}
	}

	clean_exit_with_status(EXIT_SUCCESS);
	return 0;
}
