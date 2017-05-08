#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/delay.h>		/* msleep */
#include <linux/sched.h>		/* TASK_INTERUPTIBLE*/
#include <linux/capability.h>		/* capable*/

#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/mm.h>			/* si_meminfo */
#include <linux/swap.h>			/* si_swapinfo */
#include <linux/slab.h>			/* KMEM_CACHE, ...*/
#include <asm/uaccess.h>		/* copy_*_user */
#include <asm/page.h>			/* PAGE_SIZE */
#include <linux/kref.h>			/* kref*/
#include <linux/shrinker.h>
#include <linux/spinlock.h>


#define MAX_CMD_ID 100
#define KB(num) ((x) << (PAGE_SHIFT - 10))
