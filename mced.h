/*
 *  mced.h - MCE daemon
 *
 *  Based on acpid.
 *  Copyright (C) 1999-2000 Andrew Henroid
 *  Copyright (C) 2001 Sun Microsystems
 *  Portions Copyright (C) 2004 Tim Hockin (thockin@hockin.org)
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

#ifndef MCED_H__
#define MCED_H__

#include <unistd.h>
#include <stdint.h>
#include <syslog.h>
#include <stdarg.h>

#define MCED_EVENTFILE		"/dev/mcelog"
#define MCED_MAX_INTERVAL	5000 /* milliseconds */
#define MCED_MIN_INTERVAL	100  /* milliseconds */
#define MCED_CONFDIR		"/etc/mced"
#define MCED_SOCKETFILE		"/var/run/mced.socket"
#define MCED_SOCKETMODE		0600
#define MCED_PIDFILE		"/var/run/mced.pid"
#define MCED_DBDIR		"/var/log/mced_db/"
#define MCED_CLIENTMAX		128
#define MCED_MAX_ERRS		5

#define PACKAGE 		"mced"

/* this structure has to match the kernel's struct mce */
struct kernel_mce {
	uint64_t status;	/* MCi_STATUS */
	uint64_t misc;		/* MCi_MISC */
	uint64_t addr;		/* MCi_MISC */
	uint64_t mcgstatus;	/* MCG_STATUS */
	uint64_t rip;		/* instruction pointer */
	uint64_t tsc;		/* time stamp counter */
	uint64_t res1;		/* reserved */
	uint64_t res2;		/* reserved */
	uint8_t  cs;		/* code segment */
	uint8_t  bank;		/* machine check bank */
	uint8_t  cpu;		/* cpu that raised the error */
	uint8_t  finished;	/* entry is valid */
	uint32_t pad;
} __attribute__ ((packed));

/* ioctl() calls for /dev/mcelog */
#define MCE_GET_RECORD_LEN   _IOR('M', 1, int)
#define MCE_GET_LOG_LEN      _IOR('M', 2, int)
#define MCE_GETCLEAR_FLAGS   _IOR('M', 3, int)

/* flags from MCE_GETCLEAR_FLAGS */
#define MCE_FLAG_OVERFLOW    (1ULL << 0)

/* this is our notion of an MCE */
struct mce {
	uint64_t status;	/* MCi_STATUS */
	uint64_t address;	/* MCi_ADDR */
	uint64_t misc;		/* MCi_MISC */
	uint64_t gstatus;	/* MCG_STATUS */
	uint64_t tsc;		/* CPU timestamp counter */
	uint64_t time;		/* MCED timestamp (usecs since epoch) */
	uint64_t ip;		/* CPU instruction pointer */
	int32_t  boot;		/* boot number (-1 for unknown) */
	uint8_t  cs;		/* CPU code segment */
	uint8_t  cpu;		/* excepting CPU */
	uint8_t  bank;		/* MC bank */
} __attribute__ ((packed));
#define MCE_STRUCT_VER	1

/* bits from the MCi_STATUS register */
#define MCI_STATUS_OVER		(1ULL<<62)	/* errors overflowed */

#ifdef __GNUC__
#  define PRINTF_ARGS(fmt, var)  __attribute__((format(printf, fmt, var)))
#else
#  define PRINTF_ARGS(fmtarg, vararg)
#endif

/*
 * mced.c
 */
extern int mced_debug_level;
extern int mced_log_events;
extern int mced_non_root_clients;
extern int mced_log(int level, const char *fmt, ...) PRINTF_ARGS(2, 3);
extern int mced_debug(int min_dbg_lvl, const char *fmt, ...) PRINTF_ARGS(2, 3);
extern int mced_perror(int level, const char *str);

/*
 * rules.c
 */
extern int mced_read_conf(const char *confdir);
extern int mced_add_client(int client, const char *origin);
extern int mced_cleanup_rules(int do_detach);
extern int mced_handle_mce(struct mce *mce);
extern void mced_close_dead_clients(void);

#endif /* MCED_H__ */
