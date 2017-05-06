#include "kshell.h"
#include "common.h"

MODULE_DESCRIPTION("Module \"kernel shell\" pour noyau linux");
MODULE_AUTHOR("Sofiane IDRI - Davy LY, UPMC");
MODULE_LICENSE("GPL");
MODULE_VERSION("1");

static int major;

/* ioctl stuffs */
static int ioctl_flag;
static int ioctl_err;

static int cmd_id[MAX_CMD_ID] = {0};
static struct mutex id_mutex;

static struct kmem_cache *kshell_struct_cachep;

enum kshell_cmd {list, fg, kill, wait, meminfo, modinfo};

struct kshell_struct {
	struct work_struct work;
	struct list_head list;
	struct kref refcount;

	enum kshell_cmd cmd;
	void *private_data;
	void *user_datap;

	int private_data_len;
	int cmd_id;

	int ioctl_flag;
	int fg_flag;

	/* [tmp] Let `fg` to reset this cmd_id */
	int fg_ed_cmd_id;

	/* Set this when wou put a synchro cmd tp the wq */
	bool synchro;

	/* Set this when `fg` found its job */
	bool fg_ed;

	/* return value from {list|fg|kill|...}_handler */
	int err;
};

/* List and lock for all CMDs */
static LIST_HEAD(kshell_cmd_list);
static DEFINE_SPINLOCK(kc_lock);

static DECLARE_WAIT_QUEUE_HEAD(waiter);

static struct workqueue_struct *kshell_wq;

static void list_remove_work(struct kref *ref)
{
	int stop = 0, to_copy;
	void __user *to_i, *to_p;
	const void *from_i, *from_p;

	struct kshell_struct *p = container_of(ref, struct kshell_struct,
								refcount);

	struct common *up = (struct common *)p->user_datap;

	if (p->private_data_len < USER_BUFFER_SIZE) {
		spin_lock(&kc_lock);
		list_del(&p->list);
		spin_unlock(&kc_lock);
	}

	/*
	 * Data Transfer - from kernel to user space.
	 *
	 * This is the kshell pipe implementation, it's main porpose is to
	 * facilate data transfer from kernel to user space when data length
	 * 
	 * The idea here is to 
	 *
	 * Don't transfer/continue if p->err was set previously.
	 */

	to_i = &up->pipe_id;
	from_i = &p->cmd_id;

	to_p = up->buffer;
	from_p = p->private_data;

	if(!p->err) {
		to_copy = min(USER_BUFFER_SIZE -1 , p->private_data_len);

		p->err += copy_to_user(to_p, from_p, to_copy);
		p->err += copy_to_user(to_i, from_i, sizeof(int));

		p->private_data_len -= to_copy;
		p->private_data += to_copy;

		if (!p->err && p->private_data_len > 0) {

			if (p->fg_ed_cmd_id != 0)
				cmd_id[p->fg_ed_cmd_id - 1] = 0;

			p->fg_flag = true;
			p->fg_ed = false;
			return;
		}

		p->err += copy_to_user(to_i, (const void *)&stop, sizeof(int));
	}

	/* We need to reset cmd_id(s) */
	mutex_lock(&id_mutex);

	cmd_id[p->cmd_id - 1] = 0;
	if (p->fg_ed_cmd_id != 0)
		cmd_id[p->fg_ed_cmd_id - 1] = 0;

	mutex_unlock(&id_mutex);

	/* Error transfer - from kernel to user space */
	ioctl_err = p->err;
	kmem_cache_free(kshell_struct_cachep, p);
}

static void list_add_work(struct kshell_struct *w)
{
	spin_lock(&kc_lock);
	list_add_tail(&w->list, &kshell_cmd_list);
	spin_unlock(&kc_lock);
}

static void reset_handler(void)
{
	struct kshell_struct *p, *next;

	flush_workqueue(kshell_wq);

	spin_lock(&kc_lock);
	list_for_each_entry_safe(p, next, &kshell_cmd_list, list) {
		list_del(&p->list);

		cmd_id[p->cmd_id - 1] = 0;

		if(p->private_data_len)
			kfree(p->private_data);

		kmem_cache_free(kshell_struct_cachep, p);
	}
	spin_unlock(&kc_lock);
}

static void fg_handler(struct work_struct *w)
{
	int cmd_id, err;
	bool found = false;
	struct common *cp;
	struct kshell_struct *p, *ip;

	p = container_of(w, struct kshell_struct, work);
	cp = (struct common *)p->user_datap;

	err = __get_user(cmd_id, (int __user *)&cp->cmd_id);
	if (err) {
		p->err = -EFAULT;
		goto out;
	}

	spin_lock(&kc_lock);
	list_for_each_entry(ip, &kshell_cmd_list, list) {
		if (ip->cmd_id == cmd_id && !ip->fg_ed) {

			/*
			 * Recall, we have already a reference to this job.
			 * check it out at kshell_ioctl.
			 */

			found = true;
			ip->fg_ed = true;
			break;
		}
	}
	spin_unlock(&kc_lock);

	/* Job don't exist - still `fg` */
	if (!found) {

		p->err = -1;
		goto out;
	}

	/* Protect ourselves from -ERESTARTSYS*/
	while (wait_event_interruptible(waiter, ip->fg_flag != 0))
		;

	p->fg_ed_cmd_id = cmd_id;
	p->private_data = ip->private_data;
	p->private_data_len = ip->private_data_len;

	/* We are responsible to remove this job from the cmd_list */
	spin_lock(&kc_lock);
	list_del(&ip->list);
	spin_unlock(&kc_lock);

	kmem_cache_free(kshell_struct_cachep, ip);

out:
	p->ioctl_flag = 1;
	kref_put(&p->refcount, list_remove_work);
	wake_up_interruptible(&waiter);
}

static void list_handler(struct work_struct *w)
{
	int i, len, count, buffer_size;
	char *buffer, *buffer_realloc, v[32];
	struct kshell_struct *p, *ip;

	i = 1;
	len = 0;
	count = 0;
	buffer_size = BUFF_SIZE;
	p = container_of(w, struct kshell_struct, work);

	buffer = kmalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		p->err = -ENOMEM;
		goto out;
	}

	spin_lock(&kc_lock);
	list_for_each_entry(ip, &kshell_cmd_list, list) {

		switch (ip->cmd) {
		case list:
			len = scnprintf(v, sizeof(v), "list\t%d\n", ip->cmd_id);
			break;

		case kill:
			len = scnprintf(v, sizeof(v), "kill\t%d\n", ip->cmd_id);
			break;

		case wait:
			len = scnprintf(v, sizeof(v), "wait\t%d\n", ip->cmd_id);
			break;

		case meminfo:
			len = scnprintf(v, sizeof(v), "minfo\t%d\n", ip->cmd_id);
			break;

		case modinfo:
			len = scnprintf(v, sizeof(v), "dinfo\t%d\n", ip->cmd_id);
			break;

		default:
			continue;
		}

		/* use `while` as we can't trust the `if` statement, Got it? */
		while (count + len >= buffer_size) {
			i *= 2;
			buffer_size = BUFF_SIZE * i;
			buffer_realloc = buffer;

			buffer = kmalloc(buffer_size, GFP_KERNEL);
			if (!buffer_realloc) {
				kfree(buffer_realloc);
				p->err = -ENOMEM;
				goto out;
			}

			memcpy((void *)buffer, (void *)buffer_realloc, buffer_size / 2);
			kfree(buffer_realloc);
		}

		strncat(buffer, v, len);
		count += len;
	}
	spin_unlock(&kc_lock);

	p->private_data = buffer;
	p->private_data_len = count;
out:
	/* wake up the sleeped thread */
	kref_put(&p->refcount, list_remove_work);
	ioctl_flag = 1;
	wake_up_interruptible(&waiter);

        if (p->synchro) {
                p->fg_flag = 1;
                wake_up_interruptible(&waiter);
        }

        else {
                p->ioctl_flag = 1;
                wake_up_interruptible(&waiter);
	}
}

/*
static int copy_to_struct(void __user *u, unsigned long num)
{

	char v[32];
	int len;
*/
	/*
	 * display in kilobytes.
	 */
/*
	len = num_to_str(v, sizeof(v), num << (PAGE_SHIFT - 10));

	return copy_to_user(u, (const void *)v, len);
	return 0;
}
*/

static void meminfo_handler(struct work_struct *w)
{
/*
	int err;
	struct sysinfo si;
	struct kshell_struct *p;
	struct meminfo_common *mi;

	p = container_of(w, struct kshell_struct, work);
	mi = (struct meminfo_common *)p->user_datap;

	si_meminfo(&si);
	si_swapinfo(&si);
	err = copy_to_struct((void __user*)mi->MemTotal, si.totalram);

	err += copy_to_struct((void __user*)mi->MemFree, si.freeram);
	err += copy_to_struct((void __user*)mi->Buffers, si.bufferram);
	err += copy_to_struct((void __user*)mi->HighTotal, si.totalhigh);
	err += copy_to_struct((void __user*)mi->HighFree, si.freehigh);
	err += copy_to_struct((void __user*)mi->LowTotal, si.totalram - si.totalhigh);
	err += copy_to_struct((void __user*)mi->LowFree, si.freeram - si.freehigh);
	err += copy_to_struct((void __user*)mi->SwapTotal, si.totalswap);
	err += copy_to_struct((void __user*)mi->SwapFree, si.freeswap);

	if (err)
		p->err = -1;


	kref_put(&p->refcount, list_remove_work);

	if (p->synchro) {
		fg_flag = 1;
		wake_up_interruptible(&waiter);
	} else {
		ioctl_flag = 1;
		wake_up_interruptible(&waiter);
	}
*/
}

static void modinfo_handler(struct work_struct *w)
{
	int i, len, count, err=0;
	char *buffer, v[32];
	struct module *m;
	struct kshell_struct *p;
	struct common *cp;

	count = 0;
	p = container_of(w, struct kshell_struct, work);
	cp = (struct common *)p->user_datap;

	buffer = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (!buffer) {
		p->err = -ENOMEM;
		goto out;
	}

	err += __get_user(len, (int __user *)&cp->len);

	err += copy_from_user((void *)v, (void __user *)cp->name, len);
	if (err)
		pr_info("[  kshell_MODINFO ]  ERROR.\n");

	/*
	 * From module.h#L305
	 * Search for module by name, must hold module_mutex.
	 */

	mutex_lock(&module_mutex);
	m = find_module(v);
	mutex_unlock(&module_mutex);

	if (!m) {
		p->err = -1;
		goto out;
	}

	/*
	 * Because module functions can be called even in the GOING state until
	 * m->exit() finishes.
	 *
	 * klp_alive field is not always defined.
	 */
	#ifdef CONFIG_LIVEPATCH
		if (!m->klp_alive) {
			p->err = -1;
			goto return_0;
		}
	#endif

	len = scnprintf(v, sizeof(v), "name:\t%s\n", m->name);
	strncat(buffer, v, len);
	count += len;

	len = scnprintf(v, sizeof(v), "version:\t%s\n", m->version);
	strncat(buffer, v, len);
	count += len;

	len = scnprintf(v, sizeof(v), "adresse:\t%p\n", &m);
	strncat(buffer, v, len);
	count += len;

	for(i = 0; i < m->num_kp; i++) {
		len = scnprintf(v, sizeof(v), "param:\t%s\n", m->kp[i].name);
		strncat(buffer, v, len);
		count += len;
	}

	p->private_data = buffer;
	p->private_data_len = count;

out:
	kref_put(&p->refcount, list_remove_work);

	if (p->synchro) {
		p->fg_flag = 1;
		wake_up_interruptible(&waiter);
	} else {
		p->ioctl_flag = 1;
		wake_up_interruptible(&waiter);
	}
}

/*TODO : Handle MAX_CMD_ID limit*/
static int find_cmd_id(void)
{
	int i;

	mutex_lock(&id_mutex);
	for (i = 0; i < MAX_CMD_ID; i++)
		if (cmd_id[i] == 0)
			break;

	cmd_id[i] = 1;
	mutex_unlock(&id_mutex);

	return i+1;
}

static long kshell_ioctl(struct file *iof, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	struct kshell_struct *s;

	/*
	 * extracts the type and number bitfields, and don't decode wrong CMDs:
	 * return -ENOTTY (Inappriopariate ioctl) before switching.
	 */

	if (_IOC_TYPE(cmd) != KSHELL_IOC_MAGIC)
		return -ENOTTY;
	if (_IOC_NR(cmd) > SYNC_IOC_MODINFO)
		return -ENOTTY;

	/*
	 * From ioctl-number.txt
	 *
	 * The direction is a bitmask, and VERITY_WRITE catches R/W transferts,
	 * `Type` is user-oriented, while access_ok is kernel oriented, so the
	 *  concept of `read` and `write` is reversed.
	 *
	 *
	 * From <asm/uaccess.h>L#197|L#205
	 *
	 * access_ok will be checked by copy_*_user, but we want be sure that
	 * it will success before switching.
	 */

	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	if (_IOC_DIR(cmd) & _IOC_WRITE)
		err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (err)
		return -EFAULT;


	s = kmem_cache_alloc(kshell_struct_cachep, GFP_KERNEL);
	if (unlikely(!s))
		return -ENOMEM;

	memset(s, '\0', sizeof(struct kshell_struct));
	s->cmd_id = find_cmd_id();
	s->user_datap = (void *)arg;
	kref_init(&s->refcount);

	switch (cmd) {
	case ASYNC_IOC_LIST:
		s->synchro = true;

	case SYNC_IOC_LIST:
		s->cmd = list;
		INIT_WORK(&s->work, list_handler);
		break;

	case SYNC_IOC_FG:
		s->cmd = fg;
		/*
		 * Set `fg_ed` to protect this cmd to be fg_ed by another `fg`
		 * from another terminal.
		 */
		s->fg_ed = true;
		INIT_WORK(&s->work, fg_handler);
		break;

	case ASYNC_IOC_KILL:
		s->synchro = true;

	case SYNC_IOC_KILL:
		s->cmd = kill;
		INIT_WORK(&s->work, list_handler);
		break;

	case ASYNC_IOC_WAIT:
		s->synchro = true;

	case SYNC_IOC_WAIT:
		s->cmd = wait;
		INIT_WORK(&s->work, list_handler);
		break;

	case ASYNC_IOC_MEMINFO:
		s->synchro = true;

	case SYNC_IOC_MEMINFO:
		s->cmd = meminfo;
		INIT_WORK(&s->work, meminfo_handler);
		break;

	case ASYNC_IOC_MODINFO:
		s->synchro = true;

	case SYNC_IOC_MODINFO:
		s->cmd = modinfo;
		INIT_WORK(&s->work, modinfo_handler);
		break;

	case KSHELL_IOC_RESET:
		reset_handler();
		return 0;

	default: /* redudant, as cmd was checked before !*/
		pr_info("[  kshell_ioctl_default ]  ERROR.\n");
		kmem_cache_free(kshell_struct_cachep, s);
		return -ENOTTY;
	}

	/*  Get a reference for the `fg` which reclaim this job - see fg_handler */
	if(s->synchro)
		kref_get(&s->refcount);

	/* Get a reference for the thread worker */
	kref_get(&s->refcount);

	list_add_work(s);
	schedule_work(&s->work);

	if (!s->synchro)
		/* Protect ourselves from -ERESTARTSYS */
		while (wait_event_interruptible(waiter, s->ioctl_flag != 0))
			;

	kref_put(&s->refcount, list_remove_work);
	return ioctl_err;
}

const struct file_operations kshell_fops = {
	.unlocked_ioctl = kshell_ioctl
};

static int __init hello_init(void)
{
	/* NOTE: `SLAB_PANIC` causes the slab layer to panic if the allocation
	 * fails. This flag is useful when the allocation must not fail.
	 * ^see slab.h^ 
	 *
	 * As result, the return value is not checked for NULL. 
	 */
	kshell_struct_cachep = KMEM_CACHE(kshell_struct, SLAB_PANIC);

	major = register_chrdev(0, "kshell", &kshell_fops);
	if (major < 0) {
		pr_info("[  kshell  ]  Module loading failed.\n");
		pr_info("[  kshell  ]  register_chrdev() reurned %d.\n", major);
		goto out_kmem_destroy;
	}

	kshell_wq = create_workqueue("kshell");
	if (!kshell_wq)
		goto out_unregister;

	mutex_init(&id_mutex);
	pr_info("[  kshell  ]  Module loaded successfully\n");
	goto out;

out_unregister:
	unregister_chrdev(major, "kshell");
out_kmem_destroy:
	kmem_cache_destroy(kshell_struct_cachep);
out:
	return 0;
}
module_init(hello_init);

static void __exit hello_exit(void)
{
	reset_handler();
	destroy_workqueue(kshell_wq);

	kmem_cache_destroy(kshell_struct_cachep);

	unregister_chrdev(major, "kshell");
	pr_info("[  kshell  ]  Module unloaded successfully\n");
}
module_exit(hello_exit);
