/* Copyright (c) 2019 Michael Ackermann, aggi
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Version 2 License as published by the Free
 * Software Foundation;
 *
 * This is the original implementation of scrandom88lite 8x8byte weak polymorphic scrambler matrix RNG.
 * This version of the software may be subject to and remains in compliance with export regulations.
 *
 * Due to potential legal restrictions scrandom88full version polymorphic scrambler matrix RNG is not published
 * but scrandom88full polymorphic scrambler matrix RNG is a derivative work of scrandom88lite nonetheless.
 *
 * International patent rights are hereby claimed by me, Michael Ackermann, born 11.11.1981 in Leipzig.
 * For as long as any derivative work must remain in compliance with GNU General Public License Version 2
 * any derviative work must remain in compliance with international export regulations too.
*/
#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h> 
#include <linux/fs.h> 
#include <linux/errno.h>
#include <linux/types.h> 
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/err.h>
#include <linux/device.h>
#include <linux/utsname.h>
#include <asm/timex.h>
#include <linux/random.h>
#define SCRANDOM_MAJOR 233
#define SCRANDOM_MINOR 88

#define SCRANDOM_IV 0xF8C741D01AA9BB7AULL
#define SCRANDOM_SALT 38
#define SCRANDOM_MODUL 6
#define SCRANDOM_DIST1 3
#define SCRANDOM_DIST2 9
#define SCRANDOM_DIST3 18
#define SCRANDOM_SALT1 ((SCRANDOM_SALT%SCRANDOM_MODUL)+SCRANDOM_DIST1)
#define SCRANDOM_SALT2 ((SCRANDOM_SALT%SCRANDOM_MODUL)+SCRANDOM_DIST2)
#define SCRANDOM_SALT3 ((SCRANDOM_SALT%SCRANDOM_MODUL)+SCRANDOM_DIST3)
#define SCRANDOM_HASHP 1125899906842597ull
#define SCRANDOM_LFSRSIZE 8ul
#define SCRANDOM_BUFNUM 8ul
#define SCRANDOM_BUFSIZE SCRANDOM_BUFNUM*SCRANDOM_LFSRSIZE

struct scrandom {
	unsigned long *scrambler;
	unsigned long index; unsigned long reads; unsigned long maxreads;
	unsigned long s1; unsigned long s2; unsigned long s3;
};

static unsigned long global_seed = SCRANDOM_IV;

static struct file_operations scr_fops;
static int scr_major = SCRANDOM_MAJOR;
static int scr_minor = SCRANDOM_MINOR;
static struct cdev scr_cdev;
static struct class *scr_class;
struct device *scr_dev;
MODULE_DESCRIPTION("Ultra-High-Speed pseudo-random number generator");
MODULE_AUTHOR("Michael Ackermann, aggi");
MODULE_LICENSE("GPL");
MODULE_PARM_DESC(scr_major,"major of /dev/scrandom"); MODULE_PARM_DESC(scr_minor,"minor of /dev/scrandom");

static void hash64(unsigned char *h) {
	unsigned int i; unsigned long hashp = SCRANDOM_HASHP;
	for (i=0; i<63; i++) hashp = 31*hashp + h[i];
	hashp ^= (hashp>>20)^(hashp>>12); *h = hashp^(hashp>>7)^(hashp>>4);
}
static void scrandom_shift(struct scrandom *scr) {
	scr->index %= SCRANDOM_BUFNUM; unsigned long *scrambler = &(scr->scrambler[scr->index]);
	*scrambler^=((*scrambler)>>scr->s1);*scrambler^=((*scrambler)<<scr->s2);*scrambler^=((*scrambler)>>scr->s3);
}

extern struct uts_namespace init_uts_ns;
static void scrandom_init(struct scrandom *scr) {
	unsigned long *pos64, *prev64; char *sysentropy; unsigned long clockentropy = 0;
	scr->index=0; scr->reads=0; scr->maxreads=9999;
	scr->s1 = SCRANDOM_SALT1; scr->s2 = SCRANDOM_SALT2; scr->s3 = SCRANDOM_SALT3;
	pos64 = scr->scrambler;	*pos64 = global_seed;
	struct timespec tv;
	while ( scr->index < SCRANDOM_BUFNUM ) {
		if ( scr->index > 0) { *pos64 = *prev64; hash64((unsigned char *)pos64); }
		*pos64 ^= get_random_u64();
		clockentropy = get_cycles(); if (clockentropy != 0) *pos64 ^= clockentropy;
		getnstimeofday(&tv); if (tv.tv_nsec != 0) *pos64 ^= tv.tv_nsec;
		sysentropy = (char *)&((&init_uts_ns.name)[(scr->index)%(sizeof(init_uts_ns.name))]);
		if (sysentropy && *sysentropy) *pos64 ^= (unsigned long)*sysentropy;
		hash64((unsigned char *)pos64); scrandom_shift(scr); scr->index++; prev64 = pos64; pos64++;
	}
	pos64 = scr->scrambler;	global_seed = *pos64;
	scr->s1=((*pos64)%SCRANDOM_MODUL)+SCRANDOM_DIST1;
	scr->s2=((*pos64)%SCRANDOM_MODUL)+SCRANDOM_DIST2;
	scr->s3=((*pos64)%SCRANDOM_MODUL)+SCRANDOM_DIST3;
}

static int scrandom_open(struct inode *inode, struct file *filp) {
	struct scrandom *scr = kmalloc(sizeof(struct scrandom), GFP_KERNEL|__GFP_HIGH|__GFP_ATOMIC);
	if (!scr) return -ENOMEM;
	scr->scrambler = kmalloc(SCRANDOM_BUFSIZE, GFP_KERNEL|__GFP_HIGH|__GFP_ATOMIC);
	if (!scr->scrambler) { kfree(scr); return -ENOMEM; };
	scrandom_init(scr);
	filp->private_data = scr;
	return 0;
}
static int scrandom_release(struct inode *inode, struct file *filp) {
	struct scrandom *scr = filp->private_data;
	kfree(scr->scrambler); kfree(scr);
	return 0;
}
ssize_t scrandom_read(struct file *filp, char *buf, size_t count, loff_t *f_pos) {
	struct scrandom *scr = filp->private_data;
	unsigned long done_bytes = 0; scr->index=0;
	while ( (done_bytes+SCRANDOM_BUFSIZE) <= count ) { // ~10GB/s max
		while ( scr->index < SCRANDOM_BUFNUM ) { scrandom_shift(scr); scr->index++; }
		copy_to_user(buf, (unsigned char *)(scr->scrambler), SCRANDOM_BUFSIZE);
		buf+=SCRANDOM_BUFSIZE; done_bytes+=SCRANDOM_BUFSIZE;
	}
	while ( (done_bytes+SCRANDOM_LFSRSIZE) <= count ) { // ~250GB/s max
		scrandom_shift(scr); copy_to_user(buf, (unsigned char *)&(scr->scrambler[scr->index]), SCRANDOM_LFSRSIZE);
		buf+=SCRANDOM_LFSRSIZE; done_bytes+=SCRANDOM_LFSRSIZE; scr->index++;
	}
	if ( done_bytes < count ) { // 
		scrandom_shift(scr); copy_to_user(buf, (unsigned char *)&(scr->scrambler[scr->index]), count - done_bytes);
		scr->index++;
	}
	return count;
}

static struct file_operations scr_fops = {
	read:       scrandom_read,
	open:       scrandom_open,
	release:    scrandom_release,
};
static void scrandom_cleanup_module(void) {
	unregister_chrdev_region(MKDEV(scr_major, scr_minor), 1);
	cdev_del(&scr_cdev);
	device_destroy(scr_class, MKDEV(scr_major, scr_minor));
	class_destroy(scr_class);
}
int scrandom_init_module(void) {
	int result;

	scr_class = class_create(THIS_MODULE, "scrng");
	if (IS_ERR(scr_class)) { result = PTR_ERR(scr_class); goto error0; }
	cdev_init(&scr_cdev, &scr_fops);
	scr_cdev.owner = THIS_MODULE;
	result = cdev_add(&scr_cdev, MKDEV(scr_major, scr_minor), 1);
	if (result) goto error1;
	result = register_chrdev_region(MKDEV(scr_major, scr_minor), 1, "/dev/scrandom");
	if (result < 0) goto error2;
	scr_dev = device_create(scr_class, NULL, MKDEV(scr_major, scr_minor), NULL, "scrandom");
	if (IS_ERR(scr_dev)) goto error3;

	printk(KERN_INFO "scrandom: OK\n"); return 0;

error3: unregister_chrdev_region(MKDEV(scr_major, scr_minor), 1);
error2: cdev_del(&scr_cdev);
error1: class_destroy(scr_class);
error0: printk(KERN_ALERT "scrandom: failed to register class scrng\n");
		return result;	
}
module_param(scr_major, int, 0); module_param(scr_minor, int, 0);
module_init(scrandom_init_module); module_exit(scrandom_cleanup_module);
