#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "cmdline.h"

/* globals */
const char *cmdline_progname;
int cmdline_argc;
const char * const *cmdline_argv;

static int
found_opt(const struct cmdline_opt *opt, int *argc, const char ***argv)
{
	if (opt->type == CMDLINE_OPT_BOOL) {
		/* no arg */
		*(cmdline_bool *)opt->arg = 1;
	} else if (opt->type == CMDLINE_OPT_COUNTER) {
		/* no arg */
		*(cmdline_uint *)opt->arg += 1;
	} else if (opt->type == CMDLINE_OPT_STRING) {
		/* string arg */
		(*argc)--; (*argv)++;
		if (*argc < 1) {
			return CMDLINE_ERR_REQUIRES_ARG;
		}
		*(cmdline_string *)opt->arg = (*argv)[0];
	} else if (opt->type == CMDLINE_OPT_INT) {
		/* signed number arg */
		(*argc)--; (*argv)++;
		if (*argc < 1) {
			return CMDLINE_ERR_REQUIRES_ARG;
		}
		*(cmdline_int *)opt->arg = strtoll((*argv)[0], NULL, 0);
	} else if (opt->type == CMDLINE_OPT_UINT) {
		/* unsigned number arg */
		(*argc)--; (*argv)++;
		if (*argc < 1) {
			return CMDLINE_ERR_REQUIRES_ARG;
		}
		*(cmdline_uint *)opt->arg = strtoull((*argv)[0], NULL, 0);
	} else if (opt->type == CMDLINE_OPT_MODE_T) {
		/* mode_t arg */
		(*argc)--; (*argv)++;
		if (*argc < 1) {
			return CMDLINE_ERR_REQUIRES_ARG;
		}
		*(cmdline_mode_t *)opt->arg
		    = (cmdline_mode_t)strtoll((*argv)[0], NULL, 0);
	} else if (opt->type == CMDLINE_OPT_CALLBACK) {
		/* callback function arg */
		cmdline_callback callback = (cmdline_callback)opt->arg;
		callback(opt, argc, argv);
	} else {
		return CMDLINE_ERR_UNKNOWN_TYPE;
	}
	return 0;
}

static size_t
safe_strlen(const char *str)
{
	if (str) {
		return strlen(str);
	}
	return 0;
}

static int
safe_streq(const char *lhs, const char *rhs)
{
	if (lhs && rhs) {
		return !strcmp(lhs, rhs);
	}
	return 0;
}

/* parse command line options */
int
cmdline_parse(int *argc, const char ***argv, const struct cmdline_opt *opts)
{
	const char **new_argv;
	int new_argc;
	int found_dash_dash = 0;

	/* save progname, argc, and argv */
	cmdline_progname = strrchr((*argv)[0], '/');
	if (cmdline_progname) {
		cmdline_progname++;
	} else {
		cmdline_progname = (*argv)[0];
	}
	cmdline_argc = *argc;
	cmdline_argv = *argv;
	(*argc)--; (*argv)++;

	/* allocate a new argv for leftover args, argc is a safe size */
	new_argc = 0;
	new_argv = malloc(sizeof(char *) * (*argc));
	if (new_argv == NULL) {
		return -1;
	}
	new_argv[new_argc++] = cmdline_progname;

	/* for each option on the command line */
	while (*argc) {
		int i;
		int ndashes = 0;
		int found = 0;
		const char *next_argv = &(*argv)[0][0];
		const char *arg = next_argv;

		/* special case "--" */
		if (!found_dash_dash && safe_streq(arg, "--")) {
			found_dash_dash = 1;
			(*argc)--; (*argv)++;
			continue;
		}

		/* figure out if this is a short name or long name */
		if (arg[0] == '-') {
			ndashes++;
			arg++;
			if (arg[0] == '-') {
				ndashes++;
				arg++;
			}
		}

		/* check each valid option */
		//FIXME: this does not handle --arg=val notation
		for (i = 0; !found_dash_dash && ndashes > 0
		         && opts[i].type != CMDLINE_OPT_EOL; i++) {
			const struct cmdline_opt *opt = &opts[i];
			if ((ndashes == 1 && safe_streq(arg, opt->short_name))
			 || (ndashes == 2 && safe_streq(arg, opt->long_name))) {
				/* found a known option */
				found = 1;
				found_opt(&opts[i], argc, argv);
				break;
			}
		}
		if (!found) {
			new_argv[new_argc++] = next_argv;
		}
		(*argc)--; (*argv)++;
	}

	(*argc) = new_argc;
	(*argv) = new_argv;
	return 0;
}

const char *
cmdline_help(const struct cmdline_opt *opts)
{
	static const struct cmdline_opt *saved_opts;
	static int saved_index;
	static size_t maxlen1, maxlen2, maxlen3;
	static char buf[1024];
	const struct cmdline_opt *opt;

	/* if we were passed a different opts than last time... */
	if (saved_opts != opts) {
		saved_index = 0;
		saved_opts = opts;

		/* recalculate field widths */
		maxlen1 = maxlen2 = maxlen3 = 0;
		for (opt = opts; opt->type != CMDLINE_OPT_EOL; opt++) {
			size_t size;

			size = safe_strlen(opt->short_name);
			if (size > maxlen1) {
				maxlen1 = size;
			}
			size = safe_strlen(opt->long_name);
			if (size > maxlen2) {
				maxlen2 = size;
			}
			size = safe_strlen(opt->arg_name);
			if (size > maxlen3) {
				maxlen3 = size;
			}
		}
	}

	/* if the next opt is valid, build a string */
	opt = &opts[saved_index];
	if (opt->type != CMDLINE_OPT_EOL) {
		snprintf(buf, sizeof(buf), "-%-*s --%-*s%s%-*s    %s",
		        (int)maxlen1, opt->short_name ? opt->short_name : "",
		        (int)maxlen2, opt->long_name ? opt->long_name : "",
		        (maxlen3 > 0) ? " " : "",
		        (int)maxlen3, opt->arg_name ? opt->arg_name : "",
		        opt->help);
		saved_index++;
		return buf;
	}

	return NULL;
}
