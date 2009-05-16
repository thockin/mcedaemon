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
#include "ud_socket.h"

/*
 * What is a rule?
 */
struct rule {
	enum {
		RULE_NONE = 0,
		RULE_CMD,
		RULE_CLIENT,
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
static struct rule *parse_client(int client);
static int do_cmd_rule(struct rule *r, struct mce *mce);
static int do_client_rule(struct rule *r, struct mce *mce);
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
			mced_log(LOG_DEBUG, "skipping non-file %s\n", file);
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

	if (mced_debug >= 3) {
		mced_log(LOG_DEBUG, "DBG: cleaning up rules\n");
	}

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

static struct rule *
parse_file(const char *file)
{
	FILE *fp;
	char buf[512];
	int line = 0;
	struct rule *r;

	if (mced_debug) {
		mced_log(LOG_DEBUG, "DBG: parsing conf file %s\n", file);
	}

	fp = fopen(file, "r");
	if (!fp) {
		mced_log(LOG_ERR, "ERR: fopen(%s): %s\n",
		    file, strerror(errno));
		return NULL;
	}

	/* make a new rule */
	r = new_rule();
	if (!r) {
		fclose(fp);
		return NULL;
	}
	r->type = RULE_CMD;
	r->origin = strdup(file);
	if (!r->origin) {
		mced_perror(LOG_ERR, "ERR: strdup()");
		free_rule(r);
		fclose(fp);
		return NULL;
	}

	/* read each line */
	while (!feof(fp) && !ferror(fp)) {
		char *p = buf;
		char key[64];
		char val[512];
		int n;

		line++;
		memset(key, 0, sizeof(key));
		memset(val, 0, sizeof(val));

		if (fgets(buf, sizeof(buf)-1, fp) == NULL) {
			continue;
		}

		/* skip leading whitespace */
		while (*p && isspace((int)*p)) {
			p++;
		}
		/* blank lines and comments get ignored */
		if (!*p || *p == '#') {
			continue;
		}

		/* quick parse */
		n = sscanf(p, "%63[^=\n]=%255[^\n]", key, val);
		if (n != 2) {
			mced_log(LOG_WARNING, "can't parse %s at line %d\n",
				file, line);
			continue;
		}
		if (mced_debug >= 3) {
			mced_log(LOG_DEBUG,
			    "DBG:    key=\"%s\" val=\"%s\"\n", key, val);
		}

		/* handle the parsed line */
		if (!strcasecmp(key, "action")) {
			r->action.cmd = strdup(val);
			if (!r->action.cmd) {
				mced_perror(LOG_ERR, "ERR: strdup()");
				free_rule(r);
				fclose(fp);
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
		if (mced_debug) {
			mced_log(LOG_DEBUG,
			    "DBG: skipping incomplete file %s\n", file);
		}
		free_rule(r);
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	return r;
}

int
mced_add_client(int clifd, const char *origin)
{
	struct rule *r;
	int nrules = 0;

	if (mced_debug) {
		mced_log(LOG_NOTICE, "client connected from %s\n", origin);
	}

	r = parse_client(clifd);
	if (r) {
		r->origin = strdup(origin);
		enlist_rule(&client_list, r);
		nrules++;
	}

	if (mced_debug) {
		mced_log(LOG_INFO, "%d client rule%s loaded\n",
		    nrules, (nrules == 1)?"":"s");
	}

	return 0;
}

static struct rule *
parse_client(int client)
{
	struct rule *r;

	/* make a new rule */
	r = new_rule();
	if (!r) {
		return NULL;
	}
	r->type = RULE_CLIENT;
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
			if (mced_debug) {
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

			if (mced_debug && mced_log_events) {
				mced_log(LOG_DEBUG, "DBG: rule from %s\n",
				    p->origin);
			}
			nrules++;
			if (p->type == RULE_CMD) {
				do_cmd_rule(p, mce);
			} else if (p->type == RULE_CLIENT) {
				do_client_rule(p, mce);
			} else {
				mced_log(LOG_WARNING,
				    "unknown rule type: %d\n", p->type);
			}
			p = pnext;
		}
	}

	unlock_rules();

	if (mced_debug && mced_log_events) {
		mced_log(LOG_DEBUG, "DBG: %d total rule%s matched\n",
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
	if (mced_debug >= 4) {
		mced_log(LOG_DEBUG, "DBG: blocking signals for rule lock\n");
	}
	sigprocmask(SIG_BLOCK, signals_handled(), NULL);
}

static void
unlock_rules(void)
{
	if (mced_debug >= 4) {
		mced_log(LOG_DEBUG, "DBG: unblocking signals for rule lock\n");
	}
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
do_client_rule(struct rule *rule, struct mce *mce)
{
	int r;
	int client = rule->action.fd;
	char buf[2048];

	if (mced_log_events) {
		mced_log(LOG_NOTICE, "notifying client %s\n", rule->origin);
	}

	snprintf(buf, sizeof(buf)-1,
		"%d %d 0x%016llx 0x%016llx 0x%016llx 0x%016llx 0x%016llx %d\n",
		mce->cpu, mce->bank, (unsigned long long)mce->status,
		(unsigned long long)mce->address,
		(unsigned long long)mce->misc,
		(unsigned long long)mce->gstatus, mce->time, mce->boot);
	r = safe_write(client, buf, strlen(buf));
	if (r < 0 && errno == EPIPE) {
		struct ucred cred;
		/* closed */
		mced_log(LOG_NOTICE, "client %s has disconnected\n",
		         rule->origin);
		delist_rule(&client_list, rule);
		ud_get_peercred(rule->action.fd, &cred);
		if (cred.uid != 0) {
			mced_non_root_clients--;
		}
		close(rule->action.fd);
		free_rule(rule);
		return -1;
	}
	safe_write(client, "\n", 1);

	return 0;
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
		if (mced_debug >= 2) {
			mced_log(LOG_ERR, "uh-oh! safe_write() timed out\n");
		}
		return r;
	}

	return ttl;
}

/*
 * Valid expansions:
 * 	%c	- CPU
 * 	%b	- bank
 * 	%s	- status
 * 	%a	- address
 * 	%m	- misc
 * 	%g	- gstatus
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
					"%u", mce->cpu);
			} else if (*p == 'b') {
				/* bank */
				used += snprintf(buf+used, size,
					"%u", mce->bank);
			} else if (*p == 's') {
				/* status */
				used += snprintf(buf+used, size,
					"0x%016llx",
					(unsigned long long)mce->status);
			} else if (*p == 'a') {
				/* address */
				used += snprintf(buf+used, size,
					"0x%016llx",
					(unsigned long long)mce->address);
			} else if (*p == 'm') {
				/* misc */
				used += snprintf(buf+used, size,
					"0x%016llx",
					(unsigned long long)mce->misc);
			} else if (*p == 'g') {
				/* gstatus */
				used += snprintf(buf+used, size,
					"0x%016llx",
					(unsigned long long)mce->gstatus);
			} else if (*p == 't') {
				/* time */
				used += snprintf(buf+used, size,
					"0x%016llx",
					(unsigned long long)mce->time);
			} else if (*p == 'T') {
				/* tsc */
				used += snprintf(buf+used, size,
					"0x%016llx",
					(unsigned long long)mce->tsc);
			} else if (*p == 'C') {
				/* cs */
				used += snprintf(buf+used, size,
					"0x%02x", mce->cs);
			} else if (*p == 'I') {
				/* ip */
				used += snprintf(buf+used, size,
					"0x%016llx",
					(unsigned long long)mce->ip);
			} else if (*p == 'B') {
				/* bootnum */
				used += snprintf(buf+used, size,
					"%d", mce->boot);
			} else {
				/* just assume a literal */
				buf[used++] = *p;
			}
			p++;
		} else {
			buf[used++] = *p++;
		}
	}
	if (mced_debug >= 2 && mced_log_events) {
		mced_log(LOG_DEBUG, "DBG: expanded \"%s\" -> \"%s\"\n",
		    cmd, buf);
	}

	return buf;
}
