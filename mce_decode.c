/*
 *  mce_decode.c - simple MCE decoder
 *
 *  Based on code from mcelog.
 *  Copyright (c) 2007 Tim Hockin (thockin@hockin.org)
 *  Copyright (c) 2007 Google, Inc. (thockin@google.com)
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

#include <stdio.h>
#include <stdlib.h>
#include "mced.h"

#define BIT(x)	(1ULL<<(x))

static char *progname;

static void
dump_mce(struct mce *mce)
{
	printf("machine check:\n");
	printf("  cpu:     %d\n", mce->cpu);
	printf("  bank:    %d\n", mce->bank);

	printf("  gstatus: 0x%016llx\n", (unsigned long long)mce->gstatus);
	if (mce->gstatus & BIT(0))
		printf("    [0]     = restart IP is valid\n");
	if (mce->gstatus & BIT(1))
		printf("    [1]     = error IP is valid\n");
	if (mce->gstatus & BIT(2))
		printf("    [2]     = machine check in progress\n");
	printf("  status:  0x%016llx\n", (unsigned long long)mce->status);
	if (mce->status & BIT(63))
		printf("    [63]    = error is valid\n");
	if (mce->status & BIT(62))
		printf("    [62]    = errors overflowed\n");
	if (mce->status & BIT(61))
		printf("    [61]    = error is uncorrected\n");
	else
		printf("    [61]    = error is corrected\n");
	if (mce->status & BIT(60))
		printf("    [60]    = error is enabled\n");
	if (mce->status & BIT(59))
		printf("    [59]    = misc field is valid\n");
	if (mce->status & BIT(58))
		printf("    [58]    = address field is valid\n");
	if (mce->status & BIT(57))
		printf("    [57]    = processor context may be corrupt\n");
	printf("    [16:0]  = MCA error code = 0x%04x\n",
	    (unsigned)(mce->status & 0xffff));
	printf("    [31:16] = model-specific error code = 0x%04x\n",
	    (unsigned)((mce->status>>16) & 0xffff));
	printf("    [56:32] = other information = 0x%06x\n",
	    (unsigned)((mce->status>>32) & 0xffffff));

	if (mce->status & BIT(58))
		printf("  address: 0x%016llx\n",
		       (unsigned long long)mce->address);

	if (mce->status & BIT(59))
		printf("  misc:    0x%016llx\n", (unsigned long long)mce->misc);
}

static void
usage()
{
	fprintf(stderr,
	    "Usage:\n"
	    "  %s <cpu> <bank> <mcgstatus> <status> <address> <misc>\n",
	    progname);
}

int
main(int argc, char **argv)
{
	struct mce mce;

	progname = argv[0];

	if (argc != 7) {
		usage();
		return EXIT_FAILURE;
	}

	mce.cpu = strtoul(argv[1], NULL, 0);
	mce.bank = strtoul(argv[2], NULL, 0);
	mce.gstatus = strtoull(argv[3], NULL, 0);
	mce.status = strtoull(argv[4], NULL, 0);
	mce.address = strtoull(argv[5], NULL, 0);
	mce.misc = strtoull(argv[6], NULL, 0);

	dump_mce(&mce);

	return EXIT_SUCCESS;
}
