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

#define MCED_EVENTFILE			"/dev/mcelog"
#define MCED_MAX_INTERVAL		5000 /* milliseconds */
#define MCED_MIN_INTERVAL		100  /* milliseconds */
#define MCED_CONFDIR			"/etc/mced"
#define MCED_SOCKETFILE_V1		"/var/run/mced.socket"
#define MCED_SOCKETFILE_V2		"/var/run/mced2.socket"
#define MCED_SOCKETMODE			0600
#define MCED_PIDFILE			"/var/run/mced.pid"
#define MCED_DBDIR			"/var/log/mced_db/"
#define MCED_CLIENTMAX			128
#define MCED_MAX_ERRS			5
#define MCED_OVERFLOW_SUPPRESS_TIME	10 /* seconds */

#define PACKAGE				"mced"

/* this comes from Linux's asm/processor.h on x86 */
enum cpu_vendor {
	VENDOR_UNKNOWN   = -1,
	VENDOR_INTEL     = 0,
	VENDOR_CYRIX     = 1,
	VENDOR_AMD       = 2,
	VENDOR_UMC       = 3,
	VENDOR_CENTAUR   = 5,
	VENDOR_TRANSMETA = 7,
	VENDOR_NSC       = 8,
};

/*
 * The kernel's notion of 'struct mce'.
 *
 * Because mced runs against multiple kernel versions, we need to keep
 * track of what this structure looks like for each kernel.  If mced
 * detects a structure size that it doesn't know about, it will refuse to
 * run.  The assumption here is that the Linux kernel will guarantee that
 * newer versions of 'struct mce' are strict supersets of older versions.
 */

struct kernel_mce {
	uint64_t status;	/* MCi_STATUS */
	uint64_t misc;		/* MCi_MISC */
	uint64_t addr;		/* MCi_MISC */
	uint64_t mcgstatus;	/* MCG_STATUS */
	uint64_t rip;		/* instruction pointer */
	uint64_t tsc;		/* timestamp counter */
	uint64_t time;		/* timestamp (secs since epoch) (2.6.31+) */
	uint8_t  cpuvendor;	/* cpu vendor (enum cpu_vendor) (2.6.31+) */
	uint8_t  res1;		/* reserved */
	uint16_t res2;		/* reserved */
	uint32_t cpuid;		/* CPUID 1.EAX (2.6.31+) */
	uint8_t  cs;		/* code segment */
	uint8_t  bank;		/* machine check bank */
	uint8_t  cpu;		/* excepting cpu (deprecated 2.6.31+) */
	uint8_t  finished;	/* entry is valid */
	uint32_t extcpu;	/* excepting cpu (2.6.31+) */
	uint32_t socketid;	/* cpu socket (2.6.31+) */
	uint32_t apicid;	/* cpu initial APIC ID (2.6.31+) */
	uint64_t mcgcap;	/* MCGCAP (2.6.31+) */
	uint64_t synd;		/* MCA_SYND MSR: only valid on SMCA systems */
	uint64_t ipid;		/* MCA_IPID MSR: only valid on SMCA systems */
} __attribute__ ((packed));

/* ioctl() calls for /dev/mcelog */
#define MCE_GET_RECORD_LEN   _IOR('M', 1, int)
#define MCE_GET_LOG_LEN      _IOR('M', 2, int)
#define MCE_GETCLEAR_FLAGS   _IOR('M', 3, int)

/* flags from MCE_GETCLEAR_FLAGS */
#define MCE_FLAG_OVERFLOW    (1ULL << 0)

/* this is our notion of an MCE */
struct mce {
	uint64_t mci_status;	/* MCi_STATUS */
	uint64_t mci_address;	/* MCi_ADDR */
	uint64_t mci_misc;	/* MCi_MISC */
	uint64_t mcg_status;	/* MCG_STATUS */
	uint64_t tsc;		/* CPU timestamp counter */
	uint64_t time;		/* MCED timestamp (usecs since epoch) */
	uint64_t ip;		/* CPU instruction pointer */
	int32_t  boot;		/* boot number (-1 for unknown) */
	uint32_t cpu;		/* excepting CPU */
	uint32_t cpuid_eax;	/* CPUID 1, EAX (0 for unknown) */
	uint32_t init_apic_id;	/* CPU initial APIC ID (-1UL for unknown) */
	int32_t  socket;	/* CPU socket number (-1 for unknown) */
	uint32_t mcg_cap;	/* MCG_CAP (0 for unknown) */
	uint16_t cs;		/* CPU code segment */
	uint8_t  bank;		/* MC bank */
	int8_t   vendor;	/* CPU vendor (enum cpu_vendor) */
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
extern size_t mced_kernel_record_len;
extern int mced_log(int level, const char *fmt, ...) PRINTF_ARGS(2, 3);
extern int mced_debug(int min_dbg_lvl, const char *fmt, ...) PRINTF_ARGS(2, 3);
extern int mced_perror(int level, const char *str);

/*
 * rules.c
 */
extern int mced_read_conf(const char *confdir);
extern int mced_add_client(int client, const char *origin, int is_legacy);
extern int mced_cleanup_rules(int do_detach);
extern int mced_handle_mce(struct mce *mce);
extern void mced_close_dead_clients(void);

#endif /* MCED_H__ */
