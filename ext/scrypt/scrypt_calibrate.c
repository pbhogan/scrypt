/*
 *  scrypt_calibrate.c
 *  scrypt
 *
 *  Created by Patrick Hogan on 12/15/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include "scrypt_platform.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "memlimit.h"
#include "scryptenc_cpuperf.h"
#include "sysendian.h"

#include "scrypt_calibrate.h"


static int
pickparams(size_t maxmem, double maxmemfrac, double maxtime, int * logN, uint32_t * r, uint32_t * p)
{
	size_t memlimit;
	double opps;
	double opslimit;
	double maxN, maxrp;
	int rc;

	/* Figure out how much memory to use. */
	if (memtouse(maxmem, maxmemfrac, &memlimit))
		return (1);

	/* Figure out how fast the CPU is. */
	if ((rc = scryptenc_cpuperf(&opps)) != 0)
		return (rc);
	opslimit = opps * maxtime;

	/* Allow a minimum of 2^15 salsa20/8 cores. */
	if (opslimit < 32768)
		opslimit = 32768;

	/* Fix r = 8 for now. */
	*r = 8;

	/*
	 * The memory limit requires that 128Nr <= memlimit, while the CPU
	 * limit requires that 4Nrp <= opslimit.  If opslimit < memlimit/32,
	 * opslimit imposes the stronger limit on N.
	 */
#ifdef DEBUG
	fprintf(stderr, "Requiring 128Nr <= %zu, 4Nrp <= %f\n",
			memlimit, opslimit);
#endif
	if (opslimit < memlimit/32) {
		/* Set p = 1 and choose N based on the CPU limit. */
		*p = 1;
		maxN = opslimit / (*r * 4);
		for (*logN = 1; *logN < 63; *logN += 1) {
			if ((uint64_t)(1) << *logN > maxN / 2)
				break;
		}
	} else {
		/* Set N based on the memory limit. */
		maxN = memlimit / (*r * 128);
		for (*logN = 1; *logN < 63; *logN += 1) {
			if ((uint64_t)(1) << *logN > maxN / 2)
				break;
		}

		/* Choose p based on the CPU limit. */
		maxrp = (opslimit / 4) / ((uint64_t)(1) << *logN);
		if (maxrp > 0x3fffffff)
			maxrp = 0x3fffffff;
		*p = (uint32_t)(maxrp) / *r;
	}

#ifdef DEBUG
	fprintf(stderr, "N = %zu r = %d p = %d\n",
			(size_t)(1) << *logN, (int)(*r), (int)(*p));
#endif

	/* Success! */
	return (0);
}

int
calibrate(size_t maxmem, double maxmemfrac, double maxtime, uint64_t * n, uint32_t * r, uint32_t * p)
{
	int logN = 0;
	int result = pickparams( maxmem, maxmemfrac, maxtime, & logN, r, p );
	if (result == 0)
	{
		*n = (uint64_t)(1) << logN;
	}
	return result;
}