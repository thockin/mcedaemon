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
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <sys/poll.h>
#include <grp.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/ioctl.h>

#include "mced.h"
#if BUILD_MCE_DB
#include "mcedb.h"
#endif
#include "ud_socket.h"

/* global debug level */
int mced_debug;

/* do we log event info? */
int mced_log_events;

#if BUILD_MCE_DB
/* global database handle */
struct mce_database *mced_db;
#endif

/* statics */
static const char *progname;
static long bootnum = -1;
static const char *confdir = MCED_CONFDIR;
static const char *device = MCED_EVENTFILE;
static long max_interval_ms = MCED_MAX_INTERVAL;
static long min_interval_ms = MCED_MIN_INTERVAL;
static long rate_limit = -1;
static const char *socketfile = MCED_SOCKETFILE;
static int nosocket;
static const char *socketgroup;
static mode_t socketmode = MCED_SOCKETMODE;
static int foreground;
static const char *pidfile = MCED_PIDFILE;
#if BUILD_MCE_DB
static const char *dbdir = MCED_DBDIR;
#endif
/* This is only used if ENABLE_FAKE_DEV_MCELOG is non-zero */
static int fake_dev_mcelog = 0;

/*
 * Helpers
 */

/*
 * Parse command line arguments.
 */
static int
handle_cmdline(int *argc, char ***argv)
{
	struct option opts[] = {
#if BUILD_MCE_DB
		{"dbdir", 1, 0, 'B'},
#endif
		{"bootnum", 1, 0, 'b'},
		{"confdir", 1, 0, 'c'},
		{"debug", 0, 0, 'd'},
		{"device", 1, 0, 'D'},
		{"foreground", 0, 0, 'f'},
		{"socketgroup", 1, 0, 'g'},
		{"logevents", 0, 0, 'l'},
		{"socketmode", 1, 0, 'm'},
		{"mininterval", 1, 0, 'n'},
		{"pidfile", 1, 0, 'p'},
		{"ratelimit", 1, 0, 'r'},
		{"socketfile", 1, 0, 's'},
		{"nosocket", 1, 0, 'S'},
		{"maxinterval", 1, 0, 'x'},
		{"version", 0, 0, 'v'},
		{"help", 0, 0, 'h'},
		{NULL, 0, 0, 0},
	};
	const char *opts_help[] = {
#if BUILD_MCE_DB
		"Set the database directory.",		/* dbdir */
#endif
		"Set the current boot number.",		/* bootnum */
		"Set the configuration directory.",	/* confdir */
		"Increase debugging level (implies -f -l).",/* debug */
		"Use the specified mcelog device.",	/* device */
		"Run in the foreground.",		/* foreground */
		"Set the group on the socket file.",	/* socketgroup */
		"Log each MCE and handlers.",		/* logevents */
		"Set the permissions on the socket file.",/* socketmode */
		"Set the MCE polling min interval (msecs).",/* mininterval */
		"Use the specified PID file.",		/* pidfile */
		"Limit the number of MCEs handled per second.",/* ratelimit */
		"Use the specified socket file.",	/* socketfile */
		"Do not listen on a UNIX socket (overrides -s).",/* nosocket */
		"Set the MCE polling max interval (msecs).",/* maxinterval */
		"Print version information.",		/* version */
		"Print this message.",			/* help */
	};
	struct option *opt;
	const char **hlp;
	int max, size;

	for (;;) {
		int i;
		i = getopt_long(*argc, *argv,
#if BUILD_MCE_DB
		    "B:"
#endif
		    "b:c:dD:fg:lm:n:s:p:r:Sx:vh", opts, NULL);
		if (i == -1) {
			break;
		}
		switch (i) {
#if BUILD_MCE_DB
		case 'B':
			dbdir = optarg;
			break;
#endif
		case 'b':
			bootnum = strtol(optarg, NULL, 0);;
			break;
		case 'c':
			confdir = optarg;
			break;
		case 'd':
			foreground = 1;
			mced_debug++;
			break;
		case 'D':
			device = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'g':
			socketgroup = optarg;
			break;
		case 'x':
			max_interval_ms = strtol(optarg, NULL, 0);
			if (max_interval_ms <= 0) {
				max_interval_ms = -1;
			}
			break;
		case 'n':
			min_interval_ms = strtol(optarg, NULL, 0);
			if (min_interval_ms <= 0) {
				min_interval_ms = 0;
			}
			break;
		case 'l':
			mced_log_events = 1;
			break;
		case 'm':
			socketmode = (mode_t)strtol(optarg, NULL, 8);
			break;
		case 's':
			socketfile = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'r':
			rate_limit = strtol(optarg, NULL, 0);
			break;
		case 'S':
			nosocket = 1;
			break;
		case 'v':
			printf(PACKAGE "-" PRJ_VERSION "\n");
			exit(EXIT_SUCCESS);
		case 'h':
		default:
			fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
			max = 0;
			for (opt = opts; opt->name; opt++) {
				size = strlen(opt->name);
				if (size > max)
					max = size;
			}
			for (opt = opts, hlp = opts_help;
			     opt->name;
			     opt++, hlp++)
			{
				fprintf(stderr, "  -%c, --%s",
					opt->val, opt->name);
				size = strlen(opt->name);
				for (; size < max; size++)
					fprintf(stderr, " ");
				fprintf(stderr, "  %s\n", *hlp);
			}
			exit(EXIT_FAILURE);
			break;
		}
	}

	*argc -= optind;
	*argv += optind;

	return 0;
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
		fprintf(stderr, "%s: fork: %s\n", progname, strerror(errno));
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
		fprintf(stderr, "%s: chdir(\"/\"): %s\n", progname,
		        strerror(errno));
		return -1;
	}

	return 0;
}

static int
open_log(void)
{
	int nullfd;
	int log_opts;

	/* open /dev/null */
	nullfd = open("/dev/null", O_RDONLY);
	if (nullfd < 0) {
		fprintf(stderr, "%s: can't open %s: %s\n", progname, 
			"/dev/null", strerror(errno));
		return -1;
	}

	log_opts = LOG_CONS|LOG_NDELAY;
	if (mced_debug) {
		log_opts |= LOG_PERROR;
	}
	openlog(PACKAGE, log_opts, LOG_DAEMON);

	/* set up stdin, stdout, stderr to /dev/null */
	if (dup2(nullfd, STDIN_FILENO) != STDIN_FILENO) {
		fprintf(stderr, "%s: dup2: %s\n", progname, strerror(errno));
		return -1;
	}
	if (!mced_debug && dup2(nullfd, STDOUT_FILENO) != STDOUT_FILENO) {
		fprintf(stderr, "%s: dup2: %s\n", progname, strerror(errno));
		return -1;
	}
	if (!mced_debug && dup2(nullfd, STDERR_FILENO) != STDERR_FILENO) {
		fprintf(stderr, "%s: dup2: %s\n", progname, strerror(errno));
		return -1;
	}

	close(nullfd);

	return 0;
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
clean_exit(int sig __attribute__((unused)))
{
	mced_cleanup_rules(1);
#if BUILD_MCE_DB
	mcedb_close(mced_db);
#endif
	unlink(pidfile);
	mced_log(LOG_NOTICE, "exiting\n");
	exit(EXIT_SUCCESS);
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
	vsyslog(level, fmt, args);
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
mced_perror(int level, const char *str)
{
	return mced_log(level, "%s: %s\n", str, strerror(errno));
}

static int
open_mcelog(const char *path)
{
	struct stat stbuf;
	int mce_fd;
	int rec_len;

	if (stat(path, &stbuf) < 0) {
		fprintf(stderr, "%s: can't stat %s: %s\n", progname,
		        device, strerror(errno));
		return -1;
	}
	if (ENABLE_FAKE_DEV_MCELOG && S_ISFIFO(stbuf.st_mode)) {
		fprintf(stderr, "WARNING: using a fake mcelog device\n");
		fake_dev_mcelog = 1;
	}
	mce_fd = open(path, O_RDONLY|O_EXCL|O_NONBLOCK);
	if (mce_fd < 0) {
		fprintf(stderr, "%s: can't open %s: %s\n", progname,
		        device, strerror(errno));
		return -1;
	}
	if (!fake_dev_mcelog
	 && ioctl(mce_fd, MCE_GET_RECORD_LEN, &rec_len) < 0) {
		fprintf(stderr, "%s: can't get MCE record size: %s\n",
		        progname, strerror(errno));
		return -1;
	} else if (fake_dev_mcelog) {
		rec_len = sizeof(struct kernel_mce);
	}
	if (rec_len != sizeof(struct kernel_mce)) {
		fprintf(stderr,
		        "%s: kernel MCE record size (%d) is unsupported\n",
		        progname, rec_len);
		return -1;
	}

	return mce_fd;
}

static int
open_socket(const char *path, mode_t mode, const char *group)
{
	int sock_fd;

	sock_fd = ud_create_socket(path);
	if (sock_fd < 0) {
		fprintf(stderr, "%s: can't open socket %s: %s\n",
			progname, path, strerror(errno));
		return -1;
	}
	fcntl(sock_fd, F_SETFD, FD_CLOEXEC);
	chmod(path, mode);
	if (group) {
		struct group *gr;
		struct stat buf;
		gr = getgrnam(group);
		if (!gr) {
			fprintf(stderr, "%s: group %s does not exist\n",
				progname, group);
			close(sock_fd);
			return -1;
		}
		if (stat(path, &buf) < 0) {
			fprintf(stderr, "%s: can't stat %s\n",
				progname, path);
			close(sock_fd);
			return -1;
		}
		if (chown(path, buf.st_uid, gr->gr_gid) < 0) {
			fprintf(stderr, "%s: chown(): %s\n",
				progname, strerror(errno));
			close(sock_fd);
			return -1;
		}
	}

	return sock_fd;
}

static void
kmce_to_mce(struct kernel_mce *kmce, struct mce *mce)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	mce->boot = bootnum;
	mce->bank = kmce->bank;
	mce->status = kmce->status;
	mce->address = kmce->addr;
	mce->misc = kmce->misc;
	mce->gstatus = kmce->mcgstatus;
	mce->tsc = kmce->tsc;
	mce->time = (tv.tv_sec * 1000000) + tv.tv_usec;
	mce->cpu = kmce->cpu;
	mce->cs = kmce->cs;
	mce->ip = kmce->rip;
}

static int
do_one_mce(struct kernel_mce *kmce)
{
	struct mce mce;

	kmce_to_mce(kmce, &mce);

#if BUILD_MCE_DB
	if (mcedb_append(mced_db, &mce) < 0) {
		mced_log(LOG_ERR,
		    "ERR: failed to append MCE to database - not good!!\n");
	} else if (mced_debug) {
		mced_log(LOG_DEBUG, "DBG: logged MCE #%d\n",
		    mcedb_end(mced_db)-1);
	}
#endif
	if (mced_log_events) {
		mced_log(LOG_INFO, "starting MCE handlers\n");
	}
	mced_handle_mce(&mce);
	if (mced_log_events) {
		mced_log(LOG_INFO, "completed MCE handlers\n");
	}
	return 0;
}

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

static int
elapsed_usecs(struct timeval *t0, struct timeval *t1)
{
	int elapsed = (t1->tv_sec - t0->tv_sec) * 1000000;
	elapsed += (t1->tv_usec - t0->tv_usec);
	return elapsed;
}

static void
advance_time_usecs(struct timeval *tv, int adv_usecs)
{
	uint64_t tv_us = (tv->tv_sec * 1000000) + tv->tv_usec + adv_usecs;
	tv->tv_sec = tv_us / 1000000;
	tv->tv_usec = tv_us % 1000000;
}

static void
do_rate_limit(void)
{
	static int first_event = 1;
	static struct timeval last_timestamp;
	static int bias;

	if (rate_limit <= 0) {
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
		int usecs_per_event = 1000000 / rate_limit;

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

int
do_pending_mces(int mce_fd)
{
	int loglen;
	int nmces = 0;

	/* check for MCEs */
	loglen = get_loglen(mce_fd);
	if (loglen > 0) {
		struct kernel_mce kmce[loglen];
		int n;

		n = read(mce_fd, kmce, sizeof(kmce)*loglen);
		if (n < 0) {
			if (fake_dev_mcelog && errno == EAGAIN) {
				return 0;
			}
			mced_perror(LOG_ERR, "ERR: read()");
			return -1;
		}
		//FIXME: ioctl(MCE_GETCLEAR_FLAGS
		//FIXME: log overflows

		nmces = n/sizeof(struct kernel_mce);
		if (nmces > 0) {
			int i;

			if (mced_debug && mced_log_events) {
				mced_log(LOG_DEBUG, "DBG: got %d MCE%s\n",
				    nmces, (nmces==1)?"":"s");
			}

			/* handle all the new MCEs */
			for (i = 0; i < nmces; i++) {
				do_rate_limit();
				do_one_mce(&kmce[i]);
			}
		}
	}

	return nmces;
}

int
check_mcelog_poll(int mce_fd)
{
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

int
main(int argc, char **argv)
{
	int mce_fd;
	int sock_fd = -1; /* init to avoid a compiler warning */
	int interval_ms;
	int mce_poll_works;

	/* learn who we really are */
	progname = (const char *)strrchr(argv[0], '/');
	progname = progname ? (progname + 1) : argv[0];

	/* handle the commandline  */
	handle_cmdline(&argc, &argv);

	/* close any extra file descriptors */
	close_fds();

	/* open the device file */
	mce_fd = open_mcelog(device);
	if (mce_fd < 0) {
		exit(EXIT_FAILURE);
	}
	fcntl(mce_fd, F_SETFD, FD_CLOEXEC);

	/* open our socket */
	if (!nosocket) {
		sock_fd = open_socket(socketfile, socketmode, socketgroup);
		if (sock_fd < 0) {
			exit(EXIT_FAILURE);
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

	/* open the database */
#if BUILD_MCE_DB
	mced_db = mcedb_open(dbdir);
	if (!mced_db) {
		exit(EXIT_FAILURE);
	}
#endif

	/* trap key signals */
	signal(SIGHUP, reload_conf);
	signal(SIGINT, clean_exit);
	signal(SIGQUIT, clean_exit);
	signal(SIGTERM, clean_exit);
	signal(SIGPIPE, SIG_IGN);

	/* read in our configuration */
	if (mced_read_conf(confdir) < 0) {
		exit(EXIT_FAILURE);
	}

	/* create our pidfile */
	if (create_pidfile() < 0) {
		exit(EXIT_FAILURE);
	}

	/* see if mcelog supports poll() */
	mce_poll_works = check_mcelog_poll(mce_fd);

	/* main loop */
	mced_log(LOG_INFO, "waiting for events: event logging is %s\n",
	         mced_log_events ? "on" : "off");
	interval_ms = max_interval_ms;
	while (1) {
		struct pollfd ar[2];
		int r;
		int nfds = 0;
		int mce_idx = -1;
		int sock_idx = -1;
		int timed_out;

		/* poll on the mcelog */
		if (mce_poll_works) {
			ar[nfds].fd = mce_fd;
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
		}
		if (mced_debug > 1 && max_interval_ms > 0) {
			mced_log(LOG_DEBUG, "DBG: next interval = %d msecs\n",
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
			mced_log(LOG_DEBUG, "DBG: poll timeout\n");
		} else {
			timed_out = 0;
		}

		/*
		 * Was it an MCE?  Be paranoid and always check.
		 */
		{
			int n;

			/* check for MCEs */
			n = do_pending_mces(mce_fd);
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
		if (sock_idx >= 0 && ar[sock_idx].revents) {
			int cli_fd;
			struct ucred creds;
			char buf[32];

			/* this shouldn't happen */
			if (!ar[sock_idx].revents & POLLIN) {
				mced_log(LOG_WARNING,
				    "odd, poll set flags 0x%x\n",
				    ar[sock_idx].revents);
				continue;
			}

			/* accept and add to our lists */
			cli_fd = ud_accept(sock_fd, &creds);
			if (cli_fd < 0) {
				mced_perror(LOG_ERR,
				    "ERR: can't accept client\n");
				continue;
			}
			fcntl(cli_fd, F_SETFD, FD_CLOEXEC);
			snprintf(buf, sizeof(buf)-1, "%d[%d:%d]",
				creds.pid, creds.uid, creds.gid);
			mced_add_client(cli_fd, buf);
		}
	}

	clean_exit(EXIT_SUCCESS);
	return 0;
}
