/*
 *  mce_listen.c - client for mced's UNIX socket
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
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/poll.h>
#include <grp.h>
#include <signal.h>

#include "mced.h"
#include "cmdline.h"
#include "ud_socket.h"

static int handle_cmdline(int *argc, const char ***argv);
static char *read_line(int fd);

static const char *progname;
static cmdline_string socketfile = MCED_SOCKETFILE;
static cmdline_int max_events = -1;
static cmdline_int time_limit = -1;

static void
time_expired(int signum __attribute__((unused)))
{
	exit(EXIT_SUCCESS);
}

int
main(int argc, const char *argv[])
{
	int sock_fd;
	int ret;

	/* handle an alarm */
	signal(SIGALRM, time_expired);

	/* learn who we really are */
	progname = strrchr(argv[0], '/');
	progname = progname ? (progname + 1) : argv[0];

	/* handle the commandline  */
	handle_cmdline(&argc, &argv);

	/* open the socket */
	sock_fd = ud_connect(socketfile);
	if (sock_fd < 0) {
		fprintf(stderr, "%s: can't open socket %s: %s\n",
			progname, socketfile, strerror(errno));
		exit(EXIT_FAILURE);
	}
	fcntl(sock_fd, F_SETFD, FD_CLOEXEC);

	if (max_events == 0) {
		exit(EXIT_SUCCESS);
	}

	/* set stdout to be line buffered */
	setvbuf(stdout, NULL, _IOLBF, 0);

	/* main loop */
	ret = 0;
	while (1) {
		char *event;

		/* read and handle an event */
		event = read_line(sock_fd);
		if (event) {
			fprintf(stdout, "%s\n", event);
		} else if (errno == EPIPE) {
			fprintf(stderr, "connection closed\n");
			break;
		} else {
			static int nerrs;
			if (++nerrs >= MCED_MAX_ERRS) {
				fprintf(stderr, "too many errors - aborting\n");
				ret = 1;
				break;
			}
		}

		if (max_events > 0 && --max_events == 0) {
			break;
		}
	}

	return ret;
}

static void do_help(const struct cmdline_opt *, ...);
static void do_version(const struct cmdline_opt *, ...);
static struct cmdline_opt opts[] = {
	{
		"c", "count",
		CMDLINE_OPT_INT, &max_events,
		"<num>", "Set the maximum number of events"
	},
	{
		"s", "socketfile",
		CMDLINE_OPT_STRING, &socketfile,
		"<file>", "Use the specified socket file"
	},
	{
		"t", "time",
		CMDLINE_OPT_INT, &time_limit,
		"<secs>", "Listen for the specified time (in seconds)"
	},
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

static void
usage(FILE *out)
{
	const char *help_str;
	fprintf(out, "Usage: %s [OPTIONS]\n", cmdline_progname);
	fprintf(out, "\n");
	while ((help_str = cmdline_help(opts))) {
		fprintf(out, "  %s\n", help_str);
	}
	fprintf(out, "\n");
}

/*
 * Parse command line arguments
 */
static int
handle_cmdline(int *argc, const char ***argv)
{
	/* Parse the command line. */
	cmdline_parse(argc, argv, opts);
	if (*argc != 1) {
		fprintf(stderr,
		        "Unknown command line argument: '%s'\n\n", (*argv)[1]);
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	/*
	 * Post-process command line flags.
	 */
	if (max_events < 0) {
		max_events = 0;
	}
	if (time_limit > 0) {
		alarm(time_limit);
	}

	return 0;
}

static void
do_help(const struct cmdline_opt *opt __attribute__((unused)), ...)
{
	usage(stdout);
	exit(EXIT_SUCCESS);
}

static void
do_version(const struct cmdline_opt *opt __attribute__((unused)), ...)
{
	printf(PACKAGE "-" PRJ_VERSION "\n");
	exit(EXIT_SUCCESS);
}

#define MAX_BUFLEN	1024
static char *
read_line(int fd)
{
	static char *buf;
	int buflen = 64;
	int i = 0;
	int r;
	int searching = 1;

	while (searching) {
		buf = realloc(buf, buflen);
		if (!buf) {
			fprintf(stderr, "ERR: malloc(%d): %s\n",
				buflen, strerror(errno));
			return NULL;
		}
		memset(buf+i, 0, buflen-i);

		while (i < buflen) {
			r = read(fd, buf+i, 1);
			if (r < 0 && errno != EINTR) {
				/* we should do something with the data */
				fprintf(stderr, "ERR: read(): %s\n",
					strerror(errno));
				return NULL;
			} else if (r == 0) {
				/* signal this in an almost standard way */
				errno = EPIPE;
				return NULL;
			} else if (r == 1) {
				/* scan for a newline */
				if (buf[i] == '\n') {
					searching = 0;
					buf[i] = '\0';
					break;
				}
				i++;
			}
		}
		if (buflen >= MAX_BUFLEN) {
			break;
		}
		buflen *= 2;
	}

	return buf;
}
