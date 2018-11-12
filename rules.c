/*
 *  rules.c - MCE daemon
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
#include <sys/wait.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <regex.h>
#include <signal.h>

#include "mced.h"
#include "util.h"
#include "ud_socket.h"

/*
 * What is a rule?
 */
struct rule {
	enum {
		RULE_NONE = 0,
		RULE_CMD,
		RULE_V1_CLIENT,
		RULE_V2_CLIENT,
	} type;
	char *origin;
	union {
		char *cmd;
		int fd;
	} action;
	struct rule *next;
	struct rule *prev;
};
struct rule_list {
	struct rule *head;
	struct rule *tail;
};
static struct rule_list cmd_list;
static struct rule_list client_list;

/* rule routines */
static void enlist_rule(struct rule_list *list, struct rule *r);
static void delist_rule(struct rule_list *list, struct rule *r);
static struct rule *new_rule(void);
static void free_rule(struct rule *r);

/* other helper routines */
static void lock_rules(void);
static void unlock_rules(void);
static sigset_t *signals_handled(void);
static struct rule *parse_file(const char *file);
static struct rule *parse_client(int client, int is_legacy);
static int do_cmd_rule(struct rule *r, struct mce *mce);
static int do_v1_client_rule(struct rule *r, struct mce *mce);
static int do_v2_client_rule(struct rule *r, struct mce *mce);
static int safe_write(int fd, const char *buf, int len);
static char *parse_cmd(const char *cmd, struct mce *mce);

/*
 * read in all the configuration files
 */
int
mced_read_conf(const char *confdir)
{
	DIR *dir;
	struct dirent *dirent;
	char *file = NULL;
	int nrules = 0;

	lock_rules();

	dir = opendir(confdir);
	if (!dir) {
		mced_log(LOG_ERR, "ERR: opendir(%s): %s\n",
			confdir, strerror(errno));
		unlock_rules();
		return -1;
	}

	/* scan all the files */
	while ((dirent = readdir(dir))) {
		int len;
		struct rule *r;
		struct stat stbuf;

		if (dirent->d_name[0] == '.')
			continue; /* skip dotfiles */

		len = strlen(dirent->d_name);

		if (dirent->d_name[len - 1] == '~') {
			continue; /* skip editor backup files */
		}

		len += strlen(confdir) + 2;

		file = malloc(len);
		if (!file) {
			mced_perror(LOG_ERR, "ERR: malloc()");
			closedir(dir);
			unlock_rules();
			return -1;
		}
		snprintf(file, len, "%s/%s", confdir, dirent->d_name);

		/* allow only regular files and symlinks to files */
		if (stat(file, &stbuf) != 0) {
			mced_log(LOG_ERR, "ERR: stat(%s): %s\n", file,
			         strerror(errno));
			free(file);
			continue; /* keep trying the rest of the files */
		}
		if (!S_ISREG(stbuf.st_mode)) {
			mced_debug(1, "DBG: skipping non-file %s\n", file);
			free(file);
			continue; /* skip non-regular files */
		}

		r = parse_file(file);
		if (r) {
			enlist_rule(&cmd_list, r);
			nrules++;
		}
		free(file);
	}
	closedir(dir);
	unlock_rules();

	mced_log(LOG_INFO, "%d rule%s loaded\n", nrules, (nrules == 1)?"":"s");

	return 0;
}

/*
 * cleanup all rules
 */
int
mced_cleanup_rules(int do_detach)
{
	struct rule *p;
	struct rule *next;

	lock_rules();

	mced_debug(3, "DBG: cleaning up rules\n");

	if (do_detach) {
		/* tell our clients to buzz off */
		p = client_list.head;
		while (p) {
			next = p->next;
			delist_rule(&client_list, p);
			close(p->action.fd);
			free_rule(p);
			p = next;
		}
	}

	/* clear out our conf rules */
	p = cmd_list.head;
	while (p) {
		next = p->next;
		delist_rule(&cmd_list, p);
		free_rule(p);
		p = next;
	}

	unlock_rules();

	return 0;
}

/*
 * An unrolled state machine for parsing key = value lines.
 *
 * Allowed format: WS1 key WS2 '=' WS3 value WS4
 */
static int
line_to_key_value(char *line, char **keyp, char **valp)
{
	char *p;

	/* start at the beginning */
	p = line;
	/* skip any leading whitespace (WS1) */
	while (*p != '\0' && isspace(*p)) {
		p++;
	}
	/* if we hit EOL, error */
	if (*p == '\0') {
		return -1;
	}
	/* we found the start of the key */
	*keyp = p;
	/* skip [A-Za-z0-9_]+ */
	while (*p != '\0' && (isalnum(*p) || *p == '_')) {
		p++;
	}
	/* if we hit EOL or did not move at all, error */
	if (*p == '\0' || p == *keyp) {
		return -1;
	}
	/* if we found a space, terminate the key and move past WS2 */
	if (isspace(*p)) {
		*p++ = '\0';
		while (*p != '\0' && isspace(*p)) {
			p++;
		}
	}
	/* if we found anything but '=', error */
	if (*p != '=') {
		return -1;
	}
	/* terminate the key (if it was not terminated above) */
	*p++ = '\0';
	/* skip any whitespace (WS3) */
	while (*p != '\0' && isspace(*p)) {
		p++;
	}
	/* if we hit EOL, error */
	if (*p == '\0') {
		return -1;
	}
	/* we found the start of the value */
	*valp = p;
	/* move to the end of the line */
	while (*p != '\0') {
		p++;
	}
	/* step back one to a valid character */
	p--;
	/* rewind past any trailing whitespace (WS4) */
	while (isspace(*p)) {
		p--;
	}
	/* step forward again */
	p++;
	/* terminate the value */
	*p = '\0';

	return 0;
}

static struct rule *
parse_file(const char *file)
{
	int fd;
	int line = 0;
	struct rule *r;

	mced_debug(1, "DBG: parsing conf file %s\n", file);

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		mced_log(LOG_ERR, "ERR: open(%s): %s\n",
		    file, strerror(errno));
		return NULL;
	}

	/* make a new rule */
	r = new_rule();
	if (!r) {
		close(fd);
		return NULL;
	}
	r->type = RULE_CMD;
	r->origin = strdup(file);
	if (!r->origin) {
		mced_perror(LOG_ERR, "ERR: strdup()");
		free_rule(r);
		close(fd);
		return NULL;
	}

	/* read each line */
	char *buf;
	while ((buf = read_line(fd))) {
		char *key;
		char *val;

		line++;

		/* skip leading whitespace */
		while (*buf && isspace((int)*buf)) {
			buf++;
		}
		/* blank lines and comments get ignored */
		if (*buf == '\0' || *buf == '#') {
			continue;
		}

		/* break it into a key and a value */
		if (line_to_key_value(buf, &key, &val) < 0) {
			mced_log(LOG_WARNING, "can't parse %s at line %d\n",
				file, line);
			continue;
		}
		mced_debug(3, "DBG:    key=\"%s\" val=\"%s\"\n", key, val);

		/* handle the parsed line */
		if (!strcasecmp(key, "action")) {
			r->action.cmd = strdup(val);
			if (!r->action.cmd) {
				mced_perror(LOG_ERR, "ERR: strdup()");
				free_rule(r);
				close(fd);
				return NULL;
			}
		} else {
			mced_log(LOG_WARNING,
			    "unknown option '%s' in %s at line %d\n",
			      key, file, line);
			continue;
		}
	}
	if (!r->action.cmd) {
		mced_debug(1, "DBG: skipping incomplete file %s\n", file);
		free_rule(r);
		close(fd);
		return NULL;
	}
	close(fd);

	return r;
}

int
mced_add_client(int clifd, const char *origin, int is_legacy)
{
	struct rule *r;
	int nrules = 0;

	if (mced_log_events) {
		mced_log(LOG_NOTICE, "%sclient connected from %s\n",
		         is_legacy ? "legacy " : "", origin);
	}

	r = parse_client(clifd, is_legacy);
	if (r) {
		r->origin = strdup(origin);
		enlist_rule(&client_list, r);
		nrules++;
	}

	if (mced_log_events) {
		mced_log(LOG_INFO, "%d client rule%s loaded\n",
		         nrules, (nrules == 1)?"":"s");
	}

	return 0;
}

static struct rule *
parse_client(int client, int is_legacy)
{
	struct rule *r;

	/* make a new rule */
	r = new_rule();
	if (!r) {
		return NULL;
	}
	r->type = is_legacy ? RULE_V1_CLIENT : RULE_V2_CLIENT;
	r->action.fd = client;

	return r;
}

/*
 * a few rule methods
 */

static void
enlist_rule(struct rule_list *list, struct rule *r)
{
	r->next = r->prev = NULL;
	if (!list->head) {
		list->head = list->tail = r;
	} else {
		list->tail->next = r;
		r->prev = list->tail;
		list->tail = r;
	}
}

static void
delist_rule(struct rule_list *list, struct rule *r)
{
	if (r->next) {
		r->next->prev = r->prev;
	} else {
		list->tail = r->prev;
	}

	if (r->prev) {
		r->prev->next = r->next;
	} else {
		list->head = r->next;;
	}

	r->next = r->prev = NULL;
}

static struct rule *
new_rule(void)
{
	struct rule *r;

	r = malloc(sizeof(*r));
	if (!r) {
		mced_perror(LOG_ERR, "ERR: malloc()");
		return NULL;
	}

	r->type = RULE_NONE;
	r->origin = NULL;
	r->action.cmd = NULL;
	r->prev = r->next = NULL;

	return r;
}

/* I hope you delisted the rule before you free() it */
static void
free_rule(struct rule *r)
{
	if (r->type == RULE_CMD) {
		if (r->action.cmd) {
			free(r->action.cmd);
		}
	}

	if (r->origin) {
		free(r->origin);
	}

	free(r);
}

static int
client_is_dead(int fd)
{
	struct pollfd pfd;
	int r;

	/* check the fd to see if it is dead */
	pfd.fd = fd;
	pfd.events = POLLERR | POLLHUP;
	r = poll(&pfd, 1, 0);

	if (r < 0) {
		mced_perror(LOG_ERR, "ERR: poll()");
		return 0;
	}

	return pfd.revents;
}

void
mced_close_dead_clients(void)
{
	struct rule *p;

	lock_rules();

	/* scan our client list */
	p = client_list.head;
	while (p) {
		struct rule *next = p->next;
		if (client_is_dead(p->action.fd)) {
			struct ucred cred;
			/* closed */
			if (mced_log_events) {
				mced_log(LOG_NOTICE,
				         "client %s has disconnected\n",
				         p->origin);
			}
			delist_rule(&client_list, p);
			ud_get_peercred(p->action.fd, &cred);
			if (cred.uid != 0) {
				mced_non_root_clients--;
			}
			close(p->action.fd);
			free_rule(p);
		}
		p = next;
	}

	unlock_rules();
}

/*
 * the main hook for propogating MCEs
 */
int
mced_handle_mce(struct mce *mce)
{
	struct rule *p;
	int nrules = 0;
	struct rule_list *ar[] = { &client_list, &cmd_list, NULL };
	struct rule_list **lp;

	/* make an MCE be atomic wrt known signals */
	lock_rules();

	/* scan each rule list for any rules that care about this MCE */
	for (lp = ar; *lp; lp++) {
		struct rule_list *l = *lp;
		p = l->head;
		while (p) {
			/* the list can change underneath us */
			struct rule *pnext = p->next;

			if (mced_log_events) {
				mced_debug(1, "DBG: rule from %s\n", p->origin);
			}
			nrules++;
			if (p->type == RULE_CMD) {
				do_cmd_rule(p, mce);
			} else if (p->type == RULE_V1_CLIENT) {
				do_v1_client_rule(p, mce);
			} else if (p->type == RULE_V2_CLIENT) {
				do_v2_client_rule(p, mce);
			} else {
				mced_log(LOG_WARNING,
				    "unknown rule type: %d\n", p->type);
			}
			p = pnext;
		}
	}

	unlock_rules();

	if (mced_log_events) {
		mced_debug(1, "DBG: %d total rule%s matched\n",
		           nrules, (nrules==1)?"":"s");
	}

	return 0;
}

/* helper functions to block signals while iterating */
static sigset_t *
signals_handled(void)
{
	static sigset_t sigs;

	sigemptyset(&sigs);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGQUIT);
	sigaddset(&sigs, SIGINT);

	return &sigs;
}

static void
lock_rules(void)
{
	mced_debug(4, "DBG: blocking signals for rule lock\n");
	sigprocmask(SIG_BLOCK, signals_handled(), NULL);
}

static void
unlock_rules(void)
{
	mced_debug(4, "DBG: unblocking signals for rule lock\n");
	sigprocmask(SIG_UNBLOCK, signals_handled(), NULL);
}

/*
 * the meat of the rules
 */

static int
do_cmd_rule(struct rule *rule, struct mce *mce)
{
	pid_t pid;
	int status;
	const char *action;

	pid = fork();
	switch (pid) {
	case -1:
		mced_perror(LOG_ERR, "ERR: fork()");
		return -1;
	case 0: /* child */
		/* parse the commandline, doing any expansions needed */
		action = parse_cmd(rule->action.cmd, mce);
		if (mced_log_events) {
			mced_log(LOG_NOTICE, "executing action \"%s\"\n",
			         action);
		}

		/* reset signals */
		signal(SIGHUP, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		sigprocmask(SIG_UNBLOCK, signals_handled(), NULL);

		if (mced_log_events)
			mced_log(LOG_NOTICE, "BEGIN HANDLER MESSAGES\n");
		execl("/bin/sh", "/bin/sh", "-c", action, NULL);
		/* should not get here */
		mced_perror(LOG_ERR, "ERR: execl()");
		exit(EXIT_FAILURE);
	}

	/* parent */
	waitpid(pid, &status, 0);
	if (mced_log_events) {
		mced_log(LOG_NOTICE, "END HANDLER MESSAGES\n");
	}
	if (mced_log_events) {
		if (WIFEXITED(status)) {
			mced_log(LOG_INFO, "action exited with status %d\n",
			         WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			mced_log(LOG_INFO, "action exited on signal %d\n",
			         WTERMSIG(status));
		} else {
			mced_log(LOG_INFO, "action exited with status %d\n",
			         status);
		}
	}

	return 0;
}

static int
write_to_client(struct rule *rule, const char *buf, size_t len) {
	int client = rule->action.fd;
	int r;

	if (mced_log_events) {
		mced_log(LOG_NOTICE, "notifying client %s\n", rule->origin);
	}

	r = safe_write(client, buf, len);
	if (r < 0 && errno == EPIPE) {
		struct ucred cred;
		/* closed */
		if (mced_log_events) {
			mced_log(LOG_NOTICE, "client %s has disconnected\n",
			         rule->origin);
		}
		delist_rule(&client_list, rule);
		ud_get_peercred(rule->action.fd, &cred);
		if (cred.uid != 0) {
			mced_non_root_clients--;
		}
		close(rule->action.fd);
		free_rule(rule);
		return -1;
	}

	return 0;
}

static int
do_v1_client_rule(struct rule *rule, struct mce *mce)
{
	char buf[2048];

	snprintf(buf, sizeof(buf)-1,
	         "%u %u 0x%016llx 0x%016llx 0x%016llx 0x%016llx "
	         "0x%016llx %d\n",
	         mce->cpu, mce->bank,
	         (unsigned long long)mce->mci_status,
	         (unsigned long long)mce->mci_address,
	         (unsigned long long)mce->mci_misc,
	         (unsigned long long)mce->mcg_status,
	         (unsigned long long)mce->time, mce->boot);

	return write_to_client(rule, buf, strlen(buf));
}

static int
do_v2_client_rule(struct rule *rule, struct mce *mce)
{
	char buf[2048];

	snprintf(buf, sizeof(buf)-1,
		 "%%B=%d"			// boot
		 " %%c=%u %%S=%d"		// cpu, socket
		 " %%p=0x%08lx"			// init_apic_id
		 " %%v=%d %%A=0x%08lx"		// vendor, cpuid_eax
		 " %%b=%u"			// bank
		 " %%s=0x%016llx"		// mci_status
		 " %%a=0x%016llx"		// mci_address
		 " %%m=0x%016llx"		// mci_misc
		 " %%y=0x%016llx"		// mci_synd
		 " %%i=0x%016llx"		// mci_ipid
		 " %%g=0x%016llx"		// mcg_status
		 " %%G=0x%08lx"			// mcg_cap
		 " %%t=0x%016llx"		// time
		 " %%T=0x%016llx"		// tsc
		 " %%C=0x%04x %%I=0x%016llx"	// cs, ip
		 "\n",
		 (int)mce->boot,
		 (unsigned)mce->cpu, (int)mce->socket,
		 (unsigned long)mce->init_apic_id,
		 (int)mce->vendor, (unsigned long)mce->cpuid_eax,
		 (unsigned)mce->bank,
		 (unsigned long long)mce->mci_status,
		 (unsigned long long)mce->mci_address,
		 (unsigned long long)mce->mci_misc,
		 (unsigned long long)mce->mci_synd,
		 (unsigned long long)mce->mci_ipid,
		 (unsigned long long)mce->mcg_status,
		 (unsigned long)mce->mcg_cap,
		 (unsigned long long)mce->time,
		 (unsigned long long)mce->tsc,
		 (unsigned)mce->cs, (unsigned long long)mce->ip);

	return write_to_client(rule, buf, strlen(buf));
}

#define NTRIES 100
static int
safe_write(int fd, const char *buf, int len)
{
	int r;
	int ttl = 0;
	int ntries = NTRIES;

	do {
		r = write(fd, buf+ttl, len-ttl);
		if (r < 0) {
			if (errno != EAGAIN && errno != EINTR) {
				/* a legit error */
				return r;
			}
			ntries--;
		} else if (r > 0) {
			/* as long as we make forward progress, reset ntries */
			ntries = NTRIES;
			ttl += r;
		}
	} while (ttl < len && ntries);

	if (!ntries) {
		/* crap */
		mced_log(LOG_ERR, "uh-oh! safe_write() timed out\n");
		return r;
	}

	return ttl;
}

/*
 * Valid expansions:
 * 	%c	- CPU
 * 	%S	- CPU socket
 * 	%p	- CPU initial APIC ID
 * 	%v	- CPU vendor
 * 	%A	- CPUID(1) EAX
 * 	%b	- MC bank
 * 	%s	- MCi status
 * 	%a	- MCi address
 * 	%m	- MCi misc
 * 	%y	- MCi synd
 * 	%i	- MCi ipid
 * 	%g	- MCG status
 * 	%G	- MCG capabilities
 * 	%t	- time
 * 	%B	- bootnum
 */
static char *
parse_cmd(const char *cmd, struct mce *mce)
{
	static char buf[1024];
	size_t used;
	const char *p;

	p = cmd;
	used = 0;
	memset(buf, 0, sizeof(buf));
	while (used < (sizeof(buf)-1)) {
		if (!*p) {
			break;
		}
		if (*p == '%') {
			/* handle an expansion */
			size_t size = sizeof(buf) - used;

			p++;

			if (*p == 'c') {
				/* cpu */
				used += snprintf(buf+used, size,
				    "%u", (unsigned)mce->cpu);
			} else if (*p == 'S') {
				/* cpu socket */
				used += snprintf(buf+used, size,
				    "%d", (int)mce->vendor);
			} else if (*p == 'p') {
				/* cpu init_apic_id */
				used += snprintf(buf+used, size,
				    "0x%08lx",
				    (unsigned long)mce->init_apic_id);
			} else if (*p == 'v') {
				/* vendor */
				used += snprintf(buf+used, size,
				    "%d", (int)mce->vendor);
			} else if (*p == 'A') {
				/* CPUID(1) EAX */
				used += snprintf(buf+used, size,
				    "0x%08lx",
				    (unsigned long)mce->cpuid_eax);
			} else if (*p == 'b') {
				/* bank */
				used += snprintf(buf+used, size,
				    "%u", (unsigned)mce->bank);
			} else if (*p == 's') {
				/* mci_status */
				used += snprintf(buf+used, size,
				    "0x%016llx",
				    (unsigned long long)mce->mci_status);
			} else if (*p == 'a') {
				/* mci_address */
				used += snprintf(buf+used, size,
				    "0x%016llx",
				    (unsigned long long)mce->mci_address);
			} else if (*p == 'm') {
				/* mci_misc */
				used += snprintf(buf+used, size,
				    "0x%016llx",
				    (unsigned long long)mce->mci_misc);
			} else if (*p == 'y') {
				/* mci_synd */
				used += snprintf(buf+used, size,
				    "0x%016llx",
				    (unsigned long long)mce->mci_synd);
			} else if (*p == 'i') {
				/* mci_ipid */
				used += snprintf(buf+used, size,
				    "0x%016llx",
				    (unsigned long long)mce->mci_ipid);
			} else if (*p == 'g') {
				/* mcg_status */
				used += snprintf(buf+used, size,
				    "0x%016llx",
				    (unsigned long long)mce->mcg_status);
			} else if (*p == 'G') {
				/* mcg_cap */
				used += snprintf(buf+used, size,
				    "0x%08lx", (unsigned long)mce->mcg_cap);
			} else if (*p == 't') {
				/* time */
				used += snprintf(buf+used, size,
				    "0x%016llx", (unsigned long long)mce->time);
			} else if (*p == 'T') {
				/* tsc */
				used += snprintf(buf+used, size,
				    "0x%016llx", (unsigned long long)mce->tsc);
			} else if (*p == 'C') {
				/* cs */
				used += snprintf(buf+used, size,
				    "0x%04x", (unsigned)mce->cs);
			} else if (*p == 'I') {
				/* ip */
				used += snprintf(buf+used, size,
				    "0x%016llx", (unsigned long long)mce->ip);
			} else if (*p == 'B') {
				/* bootnum */
				used += snprintf(buf+used, size,
				    "%d", (int)mce->boot);
			} else {
				/* just assume a literal */
				buf[used++] = *p;
			}
			p++;
		} else {
			buf[used++] = *p++;
		}
	}
	if (mced_log_events) {
		mced_debug(2, "DBG: expanded \"%s\" -> \"%s\"\n", cmd, buf);
	}

	return buf;
}
