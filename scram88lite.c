/* Copyright (c) 2019 Michael Ackermann, aggi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Version 2 License as published by the Free
 * Software Foundation;
 *
 * This is the original implementation of scram88lite 8x8byte weak polymorphic scrambler matrix.
 * It is explicitely intended only for ECB mode with block IV keys having applied scrash88 hash properly!
 * This version of the software may be subject to and remains in compliance with export regulations then.
 *
 * Due to potential legal restrictions scram88full version polymorphic scrambler matrix is not published
 * but scram88full polymorphic scrambler matrix is a derivative work of scram88lite nonetheless.
 *
 * International patent rights are hereby claimed by me, Michael Ackermann, born 11.11.1981 in Leipzig.
 * For as long as any derivative work must remain in compliance with GNU General Public License Version 2
 * any derviative work must remain in compliance with international export regulations too.
 *
 * The design goal of scram88lite and scram88full is efficiency defined as follows:
 * - Maximum processing speed of ciphering/deciphering and hashing relative to final cipher strength.
 *
 * Further design goals are:
 * - ASIC implementation brute force resistence and resistence against all known types of cryptoanalysis
 * - Utilization of 64bit datatypes with optional non-portable 128bit support available with recent CPUs and GCC
 *
 * The effective cipher strength of scram88lite is limited to far below 64bit as all other common ciphers are.
 * Instead no efforts were being made to obfuscate that fact for the purpose to allow studying this particular problem.
 *
 * Upscaling and application of valid operation mode with scram88full version is possible on-demand anytime nonetheless!
 * Choice of parameters for upscaling including mode of operation ecb-plain64 is highly critical to achieve
 * maximum cipher strength and performance. Full support for ecb-plain64 is available with scram88full version only.
 *
 * Only ecb-plain64 mode of operation together with scram88full version is considered cryptographically secure!
 * Anyone willing to challenge scram88full version's cipher strength and performance is welcome to contact me.
 * Known plaintext samples of required size will be supplied then to conduct any cryptoanalysis scram88full version is
 * supposedly resistent against! All other modes of operation and scram88lite itself are considered insecure.
 *
 * Initial benchmarks have shown a speed increase of scram88lite and scram88full implementation being 10x more efficient
 * than any other cipher in software-mode, while retaining full cipher strength depending on parameters chosen.
 * With an Intel Xeon X5670 from year 2010 this cipher with valid parameters is notably faster than AES-NI even.
 * Encryption speed was estimated as follows:
 * # cryptsetup -c scram88-ecb-plain64 -s 256 -d /dev/urandom benchmark
 * # Tests are approximate using memory only (no storage IO).
 * # Algorithm |       Key |      Encryption |      Decryption
 * scram88-ecb        256b       1813.0 MiB/s       1816.6 MiB/s
 *
 * scram88full version with any desired cipher strength will perform equally fast but in comparison to scram88lite 
 * scram88full version is resistent against all known methods of cryptanalysis except brute force against the full
 * maximum key-size of 256bit. Good luck.
 *
 * Either cipher variant scram88lite or scram88full is suitable for embedded applications,
 * and both can be combined with high speed compression to achieve optimal cryptographic properties.
 * scram88full version achieves optimal cryptographic properties without any input compression, scram88lite does not!
 *
 * TODO:
 * - portability testing across all available targets with support for either 64bit little endian or 64bit big endian
 * - re-implement linux kernel block I/O layer of device mapper since it is painfully slow
 *   a random number generator based on scram88full hit 20GB/s memory I/O limit easily for encryption, as a reference
 *   calling all method stubs of dm-crypt.c in-memory without any encryption applied yields 3.5GB/s only in comparison!
 * - userspace support for cryptoloop with scram88
 * - integration with kernel IPSec stack and ipsec userspace tools
 * - integration with SSL library
 * - scram88pipe userspace tool
 * - release of readily available LZX compression kernel module and userspace tools
 *   which combine this scram88lite cipher variant with LZ compression support for squashfs, bzImage and initrd
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <asm/byteorder.h>
#include <linux/crypto.h>
#include <linux/types.h>
#include <crypto/algapi.h>
#define SCRAM_MIN_KEY_SIZE		0
#define SCRAM_MAX_KEY_SIZE		256
#define SCRAM_BLOCK_SIZE		64
#define SCRAM_BLOCK_ALIGNMASK	7
#define SCRAM_LFSRSIZE			8
#define SCRAM_BUFNUM			8
#define SCRAM_SIZE				(SCRAM_BLOCK_SIZE/SCRAM_BUFNUM)
#define SCRAM_SCRASH_SIZE		64
#define SCRAM_MODUL	6
#define SCRAM_DIST1	3
#define SCRAM_DIST2	9
#define SCRAM_DIST3	18
#define SCRAM_SALT	14
#define SCRAM_SALT1	((SCRAM_SALT%SCRAM_MODUL)+SCRAM_DIST1)
#define SCRAM_SALT2	((SCRAM_SALT%SCRAM_MODUL)+SCRAM_DIST2)
#define SCRAM_SALT3	((SCRAM_SALT%SCRAM_MODUL)+SCRAM_DIST3)
// if anyone so desires this may be changed with a -DSCRAM_IV parameter
// alternatively anyone may re-invent yet another algorithm by changing this
// and feel like being a world-leading crypto expert, who must comply with GPL2 then!
// otherwise simply consider this a redundant watermark of my outstanding intelligence
#ifndef SCRAM_IV
#define SCRAM_IV	1
#define SCRAM_IV0	0x0123456789abcdefULL
#define SCRAM_IV1	0xfedcba9876543210ULL
#define SCRAM_IV2	0x123456789abcdef0ULL
#define SCRAM_IV3	0x0fedcba987654321ULL
#define SCRAM_IV4	0x23456789abcdef01ULL
#define SCRAM_IV5	0x10fedcba98765432ULL
#define SCRAM_IV6	0x3456789abcdef012ULL
#define SCRAM_IV7	0x210fedcba9876543ULL
#endif
static const u64 scram_iv[8] = {
	SCRAM_IV0, SCRAM_IV1, SCRAM_IV2, SCRAM_IV3, SCRAM_IV4, SCRAM_IV5, SCRAM_IV6, SCRAM_IV7
};
struct scram_ctx {
	u64 scrambler[8];
	u64 scrash[8];
};
// any other 512bit hash may be a utilized, but scrash88 is considered sufficient
extern void scrash88_scr(u8 *out, const u8 *data, unsigned int len);
// this is the super fancy high-end crypto cipher, break it
static void scram88_shift(u64 *scrambler, u64 s1, u64 s2, u64 s3) {
	*scrambler^=((*scrambler)>>s1);*scrambler^=((*scrambler)<<s2);*scrambler^=((*scrambler)>>s3);
}
static int scram88_set_key(struct crypto_tfm *tfm, const u8 *in_key, unsigned int key_len) {
	struct scram_ctx *scr = crypto_tfm_ctx(tfm);
	u64 s; u64 s1; u64 s2; u64 s3;
	scrash88_scr((u8 *)(scr->scrash), in_key, key_len);
	for (s=0;s<SCRAM_BUFNUM;s++) {
		scr->scrambler[s] = scram_iv[s]; scr->scrambler[s] ^= scr->scrash[s];
		s1 = ((scr->scrambler[s])%SCRAM_MODUL)+SCRAM_DIST1;
		s2 = ((scr->scrambler[s])%SCRAM_MODUL)+SCRAM_DIST2;
		s3 = ((scr->scrambler[s])%SCRAM_MODUL)+SCRAM_DIST3;
		scram88_shift(&(scr->scrambler[s]), s1, s2, s3);
	}
	return 0;
}
// cryptsetup -c scram88-ecb-plain64 open -s 256 -h plain --type plain $DEVICE $MD
static int ecb_scram88_crypt(struct blkcipher_desc *desc, struct scatterlist *sdst, struct scatterlist *ssrc, unsigned int nbytes) {
	struct scram_ctx *scr = crypto_blkcipher_ctx(desc->tfm);
	struct blkcipher_walk walk; int err;
	blkcipher_walk_init(&walk, sdst, ssrc, nbytes);
	err = blkcipher_walk_virt(desc, &walk);

	// weak, scram88full version required properly applying IV sequence!
	u64 sscrash[8]; memcpy((u8 *)sscrash, (u8 *)(scr->scrash), SCRAM_SCRASH_SIZE);
	if (walk.iv) sscrash[0] = *((u64 *)walk.iv); scrash88_scr((u8*)(sscrash), (u8*)(sscrash), SCRAM_SCRASH_SIZE);
	__be64 *outp; const __be64 *inp; u64 tmp; u8 *src, *dst; u64 s; u64 scrambler = 0;
	while (walk.nbytes >= SCRAM_BLOCK_SIZE) {
		src = walk.src.virt.addr; dst = walk.dst.virt.addr;
		inp = (const __be64 *)src; outp = (__be64 *)dst;
		for (s=0; s<SCRAM_SIZE;s++) {
			scrambler = scr->scrambler[s%SCRAM_BUFNUM]; scrambler ^= sscrash[s%SCRAM_BUFNUM];
			scram88_shift(&scrambler, SCRAM_SALT1, SCRAM_SALT2, SCRAM_SALT3);
			tmp = be64_to_cpu(*inp); tmp ^= scrambler; *outp = cpu_to_be64(tmp); inp++; outp++;
		}
		err = blkcipher_walk_done(desc, &walk, walk.nbytes - SCRAM_BLOCK_SIZE);
	}
	return err;
}
// insecure, remains for the purpose to study broken crypto APIs utilizing CBC to obfuscate that fact
// cryptsetup -c scram88-cbc-essiv:sha256 -s 256 open --type plain $DEVICE $MD
static void scram88_crypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src) {
	struct scram_ctx *scr = crypto_tfm_ctx(tfm);
	__be64 *outp; const __be64 *inp; u64 tmp;
	u64 s; u64 scrambler = 0;
	for (s=0; s<SCRAM_SIZE;s++) {
		inp = (const __be64 *)src; outp = (__be64 *)dst;
		scrambler ^= scr->scrambler[s%SCRAM_BUFNUM];
		scram88_shift(&scrambler, SCRAM_SALT1, SCRAM_SALT2, SCRAM_SALT3);
		tmp = be64_to_cpu(*inp); tmp ^= scrambler; *outp = cpu_to_be64(tmp);
		src+=SCRAM_LFSRSIZE; dst+=SCRAM_LFSRSIZE;
	}
}

static struct crypto_alg scram_algs[2] = {{
	.cra_name			=	"ecb(scram88)",
	.cra_priority		=   0,
	.cra_flags			=	CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		=	SCRAM_BLOCK_SIZE,
	.cra_alignmask		=	SCRAM_BLOCK_ALIGNMASK,
	.cra_ctxsize		=	sizeof(struct scram_ctx),
	.cra_type			=	&crypto_blkcipher_type,
	.cra_module			=	THIS_MODULE,
	.cra_u = {
		.blkcipher = {
			.min_keysize		=	SCRAM_MIN_KEY_SIZE,
			.max_keysize		=	SCRAM_MAX_KEY_SIZE,
			.ivsize				=	8,
			.setkey				=	scram88_set_key,
			.encrypt			=	ecb_scram88_crypt,
			.decrypt			=	ecb_scram88_crypt,
		},
	}
},{
	.cra_name           =   "scram88",
	.cra_driver_name    =   "scram88",
	.cra_priority       =   100,
	.cra_flags			=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize      =   SCRAM_BLOCK_SIZE,
	.cra_alignmask      =   SCRAM_BLOCK_ALIGNMASK,
	.cra_ctxsize        =   sizeof(struct scram_ctx),
	.cra_module         =   THIS_MODULE,
	.cra_u              =   {
	.cipher = {
			.cia_min_keysize	=	SCRAM_MIN_KEY_SIZE,
			.cia_max_keysize	=	SCRAM_MAX_KEY_SIZE,
			.cia_setkey			=	scram88_set_key,
			.cia_encrypt		=	scram88_crypt,
			.cia_decrypt		=	scram88_crypt
		}
	}
}};

static int __init scram_init(void) {
	return crypto_register_algs(scram_algs, ARRAY_SIZE(scram_algs));
}
static void __exit scram_exit(void) {
	crypto_unregister_algs(scram_algs, ARRAY_SIZE(scram_algs));
}
module_init(scram_init); module_exit(scram_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("scram88 cipher");
MODULE_AUTHOR("Michael Ackermann, aggi");
MODULE_ALIAS_CRYPTO("scram88");
