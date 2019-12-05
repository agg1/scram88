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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/nodemask.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/uuid.h>
#include <linux/utsname.h>
#include <asm/time.h>
#include <asm/timex.h>

int __init rand_initialize(void) { return 0; }
// method stubs required by kernel
void add_device_randomness(const void *buf, unsigned int size){}
EXPORT_SYMBOL(add_device_randomness);
void add_input_randomness(unsigned int type, unsigned int code,	 unsigned int value) {}
EXPORT_SYMBOL_GPL(add_input_randomness);
void add_interrupt_randomness(int irq, int irq_flags){}
EXPORT_SYMBOL_GPL(add_interrupt_randomness);
#ifdef CONFIG_BLOCK
void add_disk_randomness(struct gendisk *disk){}
EXPORT_SYMBOL_GPL(add_disk_randomness);
#endif
int wait_for_random_bytes(void) { return 0; }
EXPORT_SYMBOL(wait_for_random_bytes);
bool rng_is_initialized(void) { return 2; }
EXPORT_SYMBOL(rng_is_initialized);
int add_random_ready_callback(struct random_ready_callback *rdy) { return 0; }
EXPORT_SYMBOL(add_random_ready_callback);
void del_random_ready_callback(struct random_ready_callback *rdy) {}
EXPORT_SYMBOL(del_random_ready_callback);
#ifdef CONFIG_BLOCK
void rand_initialize_disk(struct gendisk *disk) {}
#endif
void add_hwgenerator_randomness(const char *buffer, size_t count, size_t entropy) {}
EXPORT_SYMBOL_GPL(add_hwgenerator_randomness);

#define RANDOM_IV 0xF8C741D01AA9BB7AULL
#define RANDOM_SALT 38
#define RANDOM_MODUL 6
#define RANDOM_DIST1 3
#define RANDOM_DIST2 9
#define RANDOM_DIST3 18
#define RANDOM_SALT1 ((RANDOM_SALT%RANDOM_MODUL)+RANDOM_DIST1)
#define RANDOM_SALT2 ((RANDOM_SALT%RANDOM_MODUL)+RANDOM_DIST2)
#define RANDOM_SALT3 ((RANDOM_SALT%RANDOM_MODUL)+RANDOM_DIST3)
#define RANDOM_HASHP 1125899906842597ull
// ~2^(64+424)->~488bit
#define RANDOM_LFSRSIZE 8ul
#define RANDOM_BUFNUM 425ul
#define RANDOM_BUFSIZE RANDOM_BUFNUM*RANDOM_LFSRSIZE

struct scrandom {
	u64 *scrambler;
	u64 index; u64 reads; u64 maxreads;
	u64 s1; u64 s2; u64 s3;
};

static u64 global_scrambler[RANDOM_BUFNUM];
static struct scrandom global_scr;
static unsigned int global_init = 0;
static u64 global_seed = RANDOM_IV;

static void hash64(u8 *h) {
	unsigned int i; u64 hashp = RANDOM_HASHP;
	for (i=0; i<63; i++) hashp = 31*hashp + h[i];
	hashp ^= (hashp>>20)^(hashp>>12); *h = hashp^(hashp>>7)^(hashp>>4);
}
static void scrand_shift(struct scrandom *scr) {
	scr->index %= RANDOM_BUFNUM; u64 *scrambler = &(scr->scrambler[scr->index]);
	*scrambler^=((*scrambler)>>scr->s1);*scrambler^=((*scrambler)<<scr->s2);*scrambler^=((*scrambler)>>scr->s3);
}
static DEFINE_SPINLOCK(scr_spinlock);
//static DEFINE_MUTEX(scr_mutex); // spinlock and semaphore cannot be used if process can sleep (copy_to_user)
//spin_lock_irqsave(&scr_spinlock,spl_flag); spin_unlock_irqrestore(&scr_spinlock,spl_flag);
extern struct uts_namespace init_uts_ns;
static int random_boot_seed;
static __init int get_random_boot_seed(char *str) {
    get_option(&str, &random_boot_seed); return 1;
}
__setup("random_seed=", get_random_boot_seed);
static void get_global_random_bytes(u64 *buf) {
	spin_lock(&scr_spinlock);
	if (global_init == 0) {
		global_scr.scrambler = global_scrambler;
		global_scr.reads=0; global_scr.index=0; global_scr.maxreads=999;
		global_scr.s1 = RANDOM_SALT1; global_scr.s2 = RANDOM_SALT2; global_scr.s3 = RANDOM_SALT3;
		if (random_boot_seed != 0) global_seed ^= random_boot_seed;
		global_init = 1;
	}
	if (global_scr.reads%global_scr.maxreads == 0) {
		u64 *pos64, *prev64; char *sysentropy; u64 clockentropy; global_scr.index = 0;
		pos64 = global_scr.scrambler; *pos64 = global_seed;
		while ( global_scr.index < RANDOM_BUFNUM ) {
			if (global_scr.index > 0) { *pos64 = *prev64; hash64((u8 *)pos64); }
			clockentropy = get_cycles(); *pos64 ^= clockentropy;
			sysentropy = (char *)&((&init_uts_ns.name)[(global_scr.index)%(sizeof(init_uts_ns.name))]);
			if (sysentropy && *sysentropy) *pos64 ^= (u64)*sysentropy;
			hash64((u8 *)pos64); scrand_shift(&global_scr); global_scr.index++; prev64=pos64; pos64++;
		}
		pos64 = global_scr.scrambler; global_scr.reads = *pos64 % global_scr.maxreads; global_scr.index = 0;
		global_scr.s1=((*pos64)%RANDOM_MODUL)+RANDOM_DIST1; pos64++;
		global_scr.s2=((*pos64)%RANDOM_MODUL)+RANDOM_DIST2; pos64++;
		global_scr.s3=((*pos64)%RANDOM_MODUL)+RANDOM_DIST3;
		global_seed = *pos64;
	}
	scrand_shift(&global_scr); *buf = global_scr.scrambler[global_scr.index];
	global_scr.index++; global_scr.reads++;
	spin_unlock(&scr_spinlock);
}

void get_random_bytes(void *buf, int nbytes) {
	int left = nbytes; char *p = buf;
	while (left) {
		u64 v; int chunk = min_t(int, left, sizeof(u64));
		get_global_random_bytes(&v); memcpy(p, &v, chunk); p += chunk; left -= chunk;
	}
}
EXPORT_SYMBOL(get_random_bytes);
/* This function normally uses the architecture-specific hardware random */
int __must_check get_random_bytes_arch(void *buf, int nbytes) {
	int left = nbytes; char *p = buf;
	while (left) {
		u64 v; int chunk = min_t(int, left, sizeof(u64));
		get_global_random_bytes(&v); memcpy(p, &v, chunk); p += chunk; left -= chunk;
	}
	return nbytes - left;
}
EXPORT_SYMBOL(get_random_bytes_arch);

SYSCALL_DEFINE3(getrandom, char __user *, buf, size_t, nbytes, unsigned int, flags) {
	int left = nbytes; char *p = buf;
	while (left) {
		u64 v; int chunk = min_t(int, left, sizeof(u64));
		get_global_random_bytes(&v); copy_to_user(p, &v, chunk); p += chunk; left -= chunk;
	}
	return nbytes - left;
}

u64 get_random_u64(void) { u64 ret; get_global_random_bytes(&ret); return (u64)ret; }
EXPORT_SYMBOL(get_random_u64);
u32 get_random_u32(void) { u32 ret; get_random_bytes((u8 *)&ret, 4); return ret; }
EXPORT_SYMBOL(get_random_u32);

/*
 * randomize_page - Generate a random, page aligned address
 * @start:	The smallest acceptable address the caller will take.
 * @range:	The size of the area, starting at @start
 * If @start + @range would overflow, @range is capped.
 *
 * NOTE: Historical use of randomize_range, which this replaces, presumed that
 * @start was already page aligned.  We now align it regardless.
 *
 * Return: A page aligned address within [start, start + range).  On error,
 * @start is returned.
 */
unsigned long randomize_page(unsigned long start, unsigned long range) {
	if (!PAGE_ALIGNED(start)) { range -= PAGE_ALIGN(start) - start; start = PAGE_ALIGN(start); }
	if (start > ULONG_MAX - range) range = ULONG_MAX - start;
	range >>= PAGE_SHIFT;
	if (range == 0) return start;
	return start + (get_random_long() % range << PAGE_SHIFT);
}

// methods for read() from /dev/random and /dev/urandom
static void scrambler_init(struct scrandom *scr) {
	u64 *pos64, *prev64; char *sysentropy; u64 clockentropy = 0;
	scr->index=0; scr->reads=0; scr->maxreads=9999;
	scr->s1 = RANDOM_SALT1; scr->s2 = RANDOM_SALT2; scr->s3 = RANDOM_SALT3;
	pos64 = scr->scrambler;	*pos64 = global_seed;
	struct timespec tv;
	while ( scr->index < RANDOM_BUFNUM ) {
		if ( scr->index > 0) { *pos64 = *prev64; hash64((u8 *)pos64); }
		clockentropy = get_cycles(); if (clockentropy != 0) *pos64 ^= clockentropy;
		sysentropy = (char *)&((&init_uts_ns.name)[(scr->index)%(sizeof(init_uts_ns.name))]);
		getnstimeofday(&tv); if (tv.tv_nsec != 0) *pos64 ^= tv.tv_nsec;
		if (sysentropy && *sysentropy) *pos64 ^= (u64)*sysentropy;
		hash64((u8 *)pos64); scrand_shift(scr); scr->index++; prev64=pos64; pos64++;
	}
	pos64 = scr->scrambler; global_seed = *pos64;
	scr->s1=((*pos64)%RANDOM_MODUL)+RANDOM_DIST1;
	scr->s2=((*pos64)%RANDOM_MODUL)+RANDOM_DIST2;
	scr->s3=((*pos64)%RANDOM_MODUL)+RANDOM_DIST3;
}
static void scramble(struct scrandom *scr, char __user *buf, size_t count) {
	u64 done_bytes = 0; scr->index=0;
	while ( (done_bytes+RANDOM_BUFSIZE) <= count ) {
		while ( scr->index < RANDOM_BUFNUM ) { scrand_shift(scr); scr->index++; }
		copy_to_user(buf, (u8 *)(scr->scrambler), RANDOM_BUFSIZE);
		buf+=RANDOM_BUFSIZE; done_bytes+=RANDOM_BUFSIZE;
	}
	while ( (done_bytes+RANDOM_LFSRSIZE) <= count ) {
		scrand_shift(scr); copy_to_user(buf, (u8 *)&(scr->scrambler[scr->index]), RANDOM_LFSRSIZE);
		buf+=RANDOM_LFSRSIZE; done_bytes+=RANDOM_LFSRSIZE; scr->index++;
	}
	if ( done_bytes < count ) {
		scrand_shift(scr); copy_to_user(buf, (u8 *)&(scr->scrambler[scr->index]), count - done_bytes);
		scr->index++;
	}
}
static __poll_t random_poll(struct file *file, poll_table * wait) {
	__poll_t mask; mask = 0; mask |= EPOLLIN | EPOLLRDNORM;	return mask;
}
static int random_open(struct inode *inode, struct file *filp) {
	struct scrandom *scr = kmalloc(sizeof(struct scrandom), GFP_KERNEL|__GFP_HIGH|__GFP_ATOMIC);
	if (!scr) return -ENOMEM;
	scr->scrambler = kmalloc(RANDOM_BUFSIZE, GFP_KERNEL|__GFP_HIGH|__GFP_ATOMIC);
	if (!scr->scrambler) { kfree(scr); return -ENOMEM; };
	scrambler_init(scr);
	filp->private_data = scr;
	return 0;
}
static ssize_t random_read(struct file *filp, char __user *buf, size_t nbytes, loff_t *ppos) {
	struct scrandom *scr = filp->private_data;
	scramble(scr, buf, nbytes); return nbytes;
}
static int random_release(struct inode *inode, struct file *filp) {
	struct scrandom *scr = filp->private_data;
	kfree(scr->scrambler); kfree(scr);
	return 0;
}
static ssize_t random_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{ return count; }
static long random_ioctl(struct file *f, unsigned int cmd, unsigned long arg) { return 0; }

static struct fasync_struct *fasync;
static int random_fasync(int fd, struct file *filp, int on) { return fasync_helper(fd, filp, on, &fasync); }
const struct file_operations random_fops = {
	.open = random_open,
	.release = random_release,
	.read  = random_read,
	.write = random_write,
	.poll  = random_poll,
	.unlocked_ioctl = random_ioctl,
	.fasync = random_fasync,
	.llseek = noop_llseek,
};
const struct file_operations urandom_fops = {
	.open = random_open,
	.release = random_release,
	.read  = random_read,
	.write = random_write,
	.unlocked_ioctl = random_ioctl,
	.fasync = random_fasync,
	.llseek = noop_llseek,
};

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
static char sysctl_bootid[16];
static DEFINE_SPINLOCK(bootid_spinlock);
static int proc_do_uuid(struct ctl_table *table, int write,	void __user *buffer, size_t *lenp, loff_t *ppos) {
	struct ctl_table fake_table; unsigned char buf[64], tmp_uuid[16], *uuid;
	uuid = table->data;
	if (!uuid) { uuid = tmp_uuid; generate_random_uuid(uuid); }
	else { spin_lock(&bootid_spinlock); uuid = sysctl_bootid; spin_unlock(&bootid_spinlock); }
	sprintf(buf, "%pU", uuid); fake_table.data = buf; fake_table.maxlen = sizeof(buf);
	return proc_dostring(&fake_table, write, buffer, lenp, ppos);
}
static int sysctl_poolsize = 524288; static int total_entropy = 524288;
extern struct ctl_table random_table[];
struct ctl_table random_table[] = {
	{
		.procname	= "poolsize",
		.data		= &sysctl_poolsize,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "entropy_avail",
		.data		= &total_entropy,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "boot_id",
		.data		= &sysctl_bootid,
		.maxlen		= 16,
		.mode		= 0444,
		.proc_handler	= proc_do_uuid,
	},
	{
		.procname	= "uuid",
		.maxlen		= 16,
		.mode		= 0444,
		.proc_handler	= proc_do_uuid,
	},
	{ }
};
#endif
