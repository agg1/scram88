/* Copyright (c) 2019 Michael Ackermann, aggi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Version 2 License as published by the Free
 * Software Foundation;
 *
 * This is the original implementation of scrash88lite 8x8byte weak polymorphic scrambler matrix hash.
 * This version of the software may be subject to and remains in compliance with export regulations.
 *
 * Due to potential legal restrictions scrash88full version polymorphic scrambler matrix hash is not published
 * but scrash88full polymorphic scrambler matrix hash is a derivative work of scrash88lite nonetheless.
 *
 * International patent rights are hereby claimed by me, Michael Ackermann, born 11.11.1981 in Leipzig.
 * For as long as any derivative work must remain in compliance with GNU General Public License Version 2
 * any derviative work must remain in compliance with international export regulations too.
*/
#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <asm/byteorder.h>

#define SCRASH_DIGEST_SIZE	64
#define SCRASH_BLOCK_SIZE	64
#define SCRASH_LFSRSIZE		8
#define SCRASH_BUFNUM		8
#define SCRASH_MODUL 6
#define SCRASH_DIST1 3
#define SCRASH_DIST2 9
#define SCRASH_DIST3 18
#ifndef SCRASH_SALT
#define SCRASH_SALT  14
#define SCRASH_SALT1 ((SCRASH_SALT%SCRASH_MODUL)+SCRASH_DIST1)
#define SCRASH_SALT2 ((SCRASH_SALT%SCRASH_MODUL)+SCRASH_DIST2)
#define SCRASH_SALT3 ((SCRASH_SALT%SCRASH_MODUL)+SCRASH_DIST3)
#endif
#ifndef SCRASH_IV
#define SCRASH_IV    1
#define SCRASH_IV0   0x210fedcba9876543ULL
#define SCRASH_IV1   0x3456789abcdef012ULL
#define SCRASH_IV2   0x10fedcba98765432ULL
#define SCRASH_IV3   0x23456789abcdef01ULL
#define SCRASH_IV4   0x0fedcba987654321ULL
#define SCRASH_IV5   0x123456789abcdef0ULL
#define SCRASH_IV6   0xfedcba9876543210ULL
#define SCRASH_IV7   0x0123456789abcdefULL
#endif

struct scrash_ctx {
	u64 scrambler[8];
	u64 index;
	u64 salt;
	u64 count;
	u64 s1; u64 s2; u64 s3;
};
static void scrash88_shift(struct scrash_ctx *scr) {
	u64 *scrambler = &(scr->scrambler[scr->index]);
	*scrambler^=((*scrambler)>>scr->s1);*scrambler^=((*scrambler)<<scr->s2);*scrambler^=((*scrambler)>>scr->s3);
}
// scram88lite IV generation
void scrash88_scr(u8 *out, const u8 *data, unsigned int len) {
	struct scrash_ctx scr;
	scr.s1 = SCRASH_SALT1; scr.s2 = SCRASH_SALT2; scr.s3 = SCRASH_SALT3; scr.index=0;
	scr.scrambler[0] = SCRASH_IV0; scr.scrambler[1] = SCRASH_IV1;
	scr.scrambler[2] = SCRASH_IV2; scr.scrambler[3] = SCRASH_IV3;
	scr.scrambler[4] = SCRASH_IV4; scr.scrambler[5] = SCRASH_IV5;
	scr.scrambler[6] = SCRASH_IV6; scr.scrambler[7] = SCRASH_IV7;

	const __be64 *inp; u64 tmp;
	scr.index=0; u64 salt = 0;
	while (len >= SCRASH_LFSRSIZE) {
		scr.index %= SCRASH_BUFNUM;
		inp = (const __be64 *)data; tmp = be64_to_cpu(*inp);
		scr.scrambler[scr.index] ^= tmp; scrash88_shift(&scr);
		salt ^= scr.scrambler[scr.index];
		scr.index++; data+=SCRASH_LFSRSIZE; len-=SCRASH_LFSRSIZE;
	}
	if (len >0) {
		scr.index %= SCRASH_BUFNUM;
		u64 swap64 = 0;
		memcpy((char *)&swap64, data, len); tmp = be64_to_cpu(swap64); //
		scr.scrambler[scr.index] ^= tmp; scrash88_shift(&scr);
		salt ^= scr.scrambler[scr.index];
	}
	scr.s1 = (salt%SCRASH_MODUL)+SCRASH_DIST1;
	scr.s2 = (salt%SCRASH_MODUL)+SCRASH_DIST2;
	scr.s3 = (salt%SCRASH_MODUL)+SCRASH_DIST3;

	int s; scr.index=0; scrash88_shift(&scr);
	for (s=1;s<SCRASH_BUFNUM;s++) {
		scr.scrambler[s] ^= scr.scrambler[s-1];
		scr.index = s; scrash88_shift(&scr);
	}
	memcpy(out, ((u8 *)scr.scrambler), SCRASH_DIGEST_SIZE);
}
EXPORT_SYMBOL(scrash88_scr)
