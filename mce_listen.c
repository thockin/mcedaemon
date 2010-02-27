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
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/poll.h>
#include <grp.h>
#include <signal.h>

#include "mced.h"
#include "util.h"
#include "cmdline.h"
#include "ud_socket.h"

#if ENABLE_DBUS
#include <glib.h>
#include "dbus.h"
#include "dbus_asv.h"
#include "auto.dbus_client.h"
#endif

static cmdline_string socketfile = NULL;
static cmdline_int max_events = -1;
static cmdline_int time_limit = -1;
static cmdline_bool use_v1_socket = 0;

#if ENABLE_DBUS
static cmdline_bool use_dbus = 0;
static cmdline_bool use_session_dbus = 0;
#endif

static void do_help(const struct cmdline_opt *, ...);
static void do_version(const struct cmdline_opt *, ...);
static struct cmdline_opt cmdline_opts[] = {
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
		"O", "oldsocket",
		CMDLINE_OPT_BOOL, &use_v1_socket,
		"", "Make socket behavior compatible with mced v1.x"
	},
	{
		"t", "time",
		CMDLINE_OPT_INT, &time_limit,
		"<secs>", "Listen for the specified time (in seconds)"
	},
	#if ENABLE_DBUS
	{
		NULL, "dbus",
		CMDLINE_OPT_BOOL, &use_dbus,
		"", "Use D-Bus to listen for events"
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

static void
usage(FILE *out)
{
	const char *help_str;
	fprintf(out, "Usage: %s [OPTIONS]\n", cmdline_progname);
	fprintf(out, "\n");
	while ((help_str = cmdline_help(cmdline_opts))) {
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
	if (cmdline_parse(argc, argv, cmdline_opts) != 0) {
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
	if (max_events < 0) {
		max_events = -1;
	}
	if (time_limit > 0) {
		alarm(time_limit);
	}
	if (socketfile == NULL) {
		if (use_v1_socket) {
			socketfile = MCED_SOCKETFILE_V1;
		} else {
			socketfile = MCED_SOCKETFILE_V2;
		}
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

static int
socket_client(void)
{
	int sock_fd;
	int ret;

	/* open the socket */
	sock_fd = ud_connect(socketfile);
	if (sock_fd < 0) {
		fprintf(stderr, "%s: can't open socket %s: %s\n",
			cmdline_progname, socketfile, strerror(errno));
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

#if ENABLE_DBUS
/* handler for MCE events */
static void
dbus_mce_handler(DBusGProxy *proxy __attribute__((unused)),
                 const dbus_asv *asv,
                 void *data __attribute__((unused)))
{
	const char *key;
	GValue *value;
	int i = 0;

	dbus_asv_iterator it;
	dbus_asv_iter_init(&it, asv);
	while (dbus_asv_iter_next(&it, &key, &value)) {
		if (i++ != 0) {
			printf(" ");
		}
		gboolean valid;
		if (G_VALUE_HOLDS_INT(value)) {
			int32_t val = dbus_asv_get_int32(asv, key, &valid);
			if (valid) {
				printf("%s=%ld", key, (long)val);
			}
		} else if (G_VALUE_HOLDS_UINT(value)) {
			uint32_t val = dbus_asv_get_uint32(asv, key, &valid);
			if (valid) {
				printf("%s=0x%08lx", key, (unsigned long)val);
			}
		} else if (G_VALUE_HOLDS_INT64(value)) {
			int64_t val = dbus_asv_get_int64(asv, key, &valid);
			if (valid) {
				printf("%s=%lld", key, (long long)val);
			}
		} else if (G_VALUE_HOLDS_UINT64(value)) {
			uint64_t val = dbus_asv_get_uint64(asv, key, &valid);
			if (valid) {
				printf("%s=0x%016llx", key,
				       (unsigned long long)val);
			}
		}
	}
	printf("\n");

	if (max_events > 0 && --max_events == 0) {
		exit(EXIT_SUCCESS);
	}
}

/* Run a dbus mainloop */
static int
dbus_client(void)
{
	int which_bus;
	DBusGConnection *bus;
	DBusGProxy *remote_value;
	GMainLoop *main_loop;
	GError *error = NULL;

	g_type_init();

	main_loop = g_main_loop_new(NULL, FALSE);
	if (main_loop == NULL) {
		fprintf(stderr, "can't create dbus main loop");
		return -1;
	}

	if (use_session_dbus) {
		which_bus = DBUS_BUS_SESSION;
	} else {
		which_bus = DBUS_BUS_SYSTEM;
	}
	bus = dbus_g_bus_get(which_bus, &error);
	if (error != NULL) {
		fprintf(stderr, "can't connect to dbus");
		return -1;
	}

	remote_value = dbus_g_proxy_new_for_name(bus,
	                                         DBUS_SERVICE_NAME,
	                                         DBUS_SERVICE_OBJECT_PATH,
	                                         DBUS_SERVICE_INTERFACE);
	if (remote_value == NULL) {
		fprintf(stderr, "can't create the dbus proxy");
		return -1;
	}

	dbus_g_proxy_add_signal(remote_value, DBUS_SIGNAL_NAME_MCE,
	                        dbus_asv_gtype(), G_TYPE_INVALID);

	dbus_g_proxy_connect_signal(remote_value, DBUS_SIGNAL_NAME_MCE,
	                            G_CALLBACK(dbus_mce_handler), NULL, NULL);

	if (max_events == 0) {
		return EXIT_SUCCESS;
	}

	g_main_loop_run(main_loop);
	return -1;
}
#endif  /* ENABLE_DBUS */

static void
time_expired(int signum __attribute__((unused)))
{
	exit(EXIT_SUCCESS);
}

int
main(int argc, const char *argv[])
{
	/* handle an alarm */
	signal(SIGALRM, time_expired);

	/* handle the commandline  */
	handle_cmdline(&argc, &argv);

	/* listen for events */
	#if ENABLE_DBUS
	if (use_dbus) {
		return dbus_client();
	}
	#endif
	return socket_client();
}
