#ifndef CMDLINE_H__
#define CMDLINE_H__

#ifdef __cplusplus
extern "C" {
#endif

/* the type of commandline option */
enum cmdline_opt_type {
	CMDLINE_OPT_BOOL = 0,		/* arg = cmdline_bool */
	CMDLINE_OPT_COUNTER,		/* arg = cmdline_uint */
	CMDLINE_OPT_STRING,		/* arg = cmdline_string */
	CMDLINE_OPT_INT,		/* arg = cmdline_int */
	CMDLINE_OPT_UINT,		/* arg = cmdline_uint */
	CMDLINE_OPT_MODE_T,		/* arg = cmdline_mode_t */
	CMDLINE_OPT_CALLBACK,		/* arg = cmdline_callback */
	CMDLINE_OPT_EOL,		/* end-of-list */
};

/* a command line option */
struct cmdline_opt {
	const char *short_name;
	const char *long_name;
	enum cmdline_opt_type type;
	void *arg;
	const char *arg_name;
	const char *help;
};
#define CMDLINE_OPT_END_OF_LIST { NULL,NULL,CMDLINE_OPT_EOL,NULL,NULL,NULL }

/*
 * Use these for cmdline flag variables.  If you define a flag variable as
 * something other than these exact types, you might invoke undefined
 * behavior and all bets are off.
 */
typedef int cmdline_bool;
typedef const char *cmdline_string;
typedef signed long long cmdline_int;
typedef unsigned long long cmdline_uint;
typedef mode_t cmdline_mode_t;
typedef void (*cmdline_callback)(
    const struct cmdline_opt *opt, int *argc, const char ***argv);

/*
 * Parse command line options.
 *
 * Scan argv for options which match a cmdline_opt, and call the callback
 * if found.  When this function returns successfully, argc and argv have
 * been updated to only represent unmatched commandline options, with
 * argv[0] being the prgram name, as invoked.
 *
 * Returns 0 on success.
 * Returns CMDLINE_ERR_* on error.
 */
extern int
cmdline_parse(int *argc, const char ***argv, const struct cmdline_opt *opts);
#define CMDLINE_ERR_REQUIRES_ARG -1
#define CMDLINE_ERR_UNKNOWN_TYPE -2

/*
 * Build command line help strings.
 *
 * Build a help string for each cmdline_opt, returning one string for each
 * call to this function.  Not reentrant.
 *
 * Returns a valid pointer on success.
 * Returns NULL when done
 */
const char *
cmdline_help(const struct cmdline_opt *opts);

extern const char *cmdline_progname;
extern int cmdline_argc;
extern const char * const *cmdline_argv;

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* CMDLINE_H__ */
