/*
 *  scrypt_calibrate.h
 *  scrypt
 *
 *  Created by Patrick Hogan on 12/15/10.
 *
 */

#ifndef _SCRYPT_CALIBRATE_H_
#define _SCRYPT_CALIBRATE_H_

#include <stdint.h>
#include <stdio.h>

int calibrate( size_t maxmem, double maxmemfrac, double maxtime, uint64_t * n, uint32_t * r, uint32_t * p );

#endif


