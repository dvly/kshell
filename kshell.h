#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/delay.h>		/* msleep */

#include <linux/workqueue.h>
#include <asm/uaccess.h>		/* copy_*_user */
#include <linux/spinlock.h>
#include <linux/ioctl.h>

#define KSHELL_IOC_MAGIC 'N'

#define KSHELL_IOC_LIST		_IOWR(KSHELL_IOC_MAGIC, 1, char *)
#define KSHELL_IOC_FG		_IOWR(KSHELL_IOC_MAGIC, 2, char *)
#define KSHELL_IOC_KILL		_IOWR(KSHELL_IOC_MAGIC, 3, char *)
#define KSHELL_IOC_WAIT		_IOWR(KSHELL_IOC_MAGIC, 4, char *)
#define KSHELL_IOC_MEMINFO	_IOWR(KSHELL_IOC_MAGIC, 5, char *)
#define KSHELL_IOC_MODINFO	_IOWR(KSHELL_IOC_MAGIC, 6, char *)
#define KSHELL_IOC_TEST		_IOWR(KSHELL_IOC_MAGIC, 7, char *)

struct kshell_struct;
static void remove_work(struct kshell_struct *);
static void add_work(struct kshell_struct *);
