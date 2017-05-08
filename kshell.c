#include "kshell.h"
#include "common.h"

MODULE_DESCRIPTION("Module \"kernel shell\" pour noyau linux");
MODULE_AUTHOR("Sofiane IDRI - Davy LY, UPMC");
MODULE_LICENSE("GPL");
MODULE_VERSION("1");

#define KB(num) num << (PAGE_SHIFT - 10)

static int major;

/* ioctl stuffs */
static int ioctl_err;

/* cmd_id management */
static int cmd_id[MAX_CMD_ID] = {0};
static int max_id_reached; /* increment this when MAX_CMD_ID reached */
static struct mutex id_mutex;

static struct kmem_cache *cmd_struct_cachep;

enum kshell_cmd {list, fg, kill, wait, meminfo, modinfo};

/* cmd_struct contient toutes les informations liées à une commande. */
struct cmd_struct {
	struct work_struct work;
	struct list_head list;
	struct kref refcount;

	enum kshell_cmd cmd;
	void *private_data;
	void *user_datap;

	int private_data_len;
	int cmd_id;

	int ioctl_cond;
	int fg_cond;

	/* when `fg` reclaim an asynchro cmd, set this to it's cmd_id */
	int fg_ed_cmd_id;

	/* Set this when wou put a asynchro cmd tp the wq */
	bool asynchro;

	/* Set this when `fg` found its job */
	bool fg_ed;

	/* return value from {list|fg|kill|...}_handler */
	int err;
};

/* List and lock for all CMDs */
/* kshell_cmd_list est la liste de toutes les commandes en cours d'exécution*/
static LIST_HEAD(kshell_cmd_list);
static DEFINE_SPINLOCK(kc_lock);

/* 
 * k_pool est une liste contenant les cmd_struct des commandes 
 * qui ont finies d'être exécutées.
 * Cette liste évite de désallouer et réallouer des cmd_struct 
 * en permanance. Si une commande est appelée par l'utilisateur, 
 * et qu'il y a des cmd_struct disponibles dans le pool alors il 
 * nous suffit d'en reprendre un, la reinitialiser, puis la remettre 
 * dans la liste des commandes actives : kshell_cmd_list.
 *
 * Par ailleurs lorsque le shrinker passe c'est les éléments qui sont présents dans
 * le k_pool qui sont déalloués.
 */
static LIST_HEAD(k_pool);
static struct mutex kp_mutex;

static DECLARE_WAIT_QUEUE_HEAD(waiter);

static struct workqueue_struct *kshell_wq;

/*
 * find_cmd_id - cherche et retourne un id unique pour les commandes 
 */
static int find_cmd_id(void)
{
	int i, ret;

	mutex_lock(&id_mutex);
	for (i = 0; i < MAX_CMD_ID; i++)
		if (cmd_id[i] == 0)
			break;

	/*
	 * code become easier when we don't
	 * use the last case
	 */
	if (i < MAX_CMD_ID - 1) {
		cmd_id[i] = 1;
		mutex_unlock(&id_mutex);
		return i + 1;
	}

	max_id_reached += 1;
	ret = max_id_reached;
	mutex_unlock(&id_mutex);

	return (i + ret);
}

/*
 * reset_cmd_id - reset up two pre-assigned cmd_id(s),
 * @a may be the caller cmd_id.
 * @b may be the fg_ed_cmd_id, (see fg_handler).
 *
 */
static void reset_cmd_id(int a, int b)
{
	mutex_lock(&id_mutex);
	if (a < MAX_CMD_ID)
		cmd_id[a - 1] = 0;
	
	if (b != 0)
		if (b < MAX_CMD_ID)
			cmd_id[b - 1] = 0;
	mutex_unlock(&id_mutex);

}

/*
 * pool_alloc_entry - Retire un élément cmd_struct de la pool  
 *
 * @return : retourne le cmd_struct retiré 
 *
 */
static struct cmd_struct *pool_alloc_entry(void)
{
	struct cmd_struct *entry = NULL;

	mutex_lock(&kp_mutex);
	if (!list_empty(&k_pool)) {
		entry = container_of(k_pool.next, struct cmd_struct, list);
		list_del(&entry->list);
	}
	mutex_unlock(&kp_mutex);

	return entry;
}

/*
 * pool_add_entry - Ajoute une cmd_struct dans le pool
 */
static void pool_add_entry(struct cmd_struct *p)
{
	reset_cmd_id(p->cmd_id, p->fg_ed_cmd_id);

	mutex_lock(&kp_mutex);
	list_add(&p->list, &k_pool);
	mutex_unlock(&kp_mutex);
}

/* 
 * kref_ed_entry - Utilisée uniquement par fg, et concerne donc
 * des commandes en background. Cette fonction permet de retirer 
 * un élément cmd_list de la liste des commandes actives : cmd_list.
 *
 * on utilise cette fonction plutôt que list_remove_work car
 * list_remove_work transmet en même temps des données, ce qui est
 * dans notre cas déjà fait par fg_handler.
 *
 * L'élément retiré de cmd_list est ajouté à la pool.
 */
static void kref_ed_entry(struct kref *ref)
{
	struct cmd_struct *p;

	p = container_of(ref, struct cmd_struct, refcount);

	spin_lock(&kc_lock);
	list_del(&p->list);
	spin_unlock(&kc_lock);

	pool_add_entry(p);
}

/*
 * pool_count - fonction utilisée par le shrinker pour
 * compter le nombre de cmd_struct libérables (ce sont
 * les cmd_struct présentes dans le pool)
 */
static unsigned long pool_count(struct shrinker *s, struct shrink_control *sc)
{
	int count = 0;
	struct cmd_struct *p;

	mutex_lock(&kp_mutex);
	list_for_each_entry(p, &k_pool, list) {
		count += 1;
	}
	mutex_unlock(&kp_mutex);

	return count;
}

/*
 * pool_scan - fonction utilisée par le shrinker pour 
 * désallouer des cmd_struct, on parcourt le pool et
 * on essaie de libérer les cmd_struct qui y sont présentes
 */
static unsigned long pool_scan(struct shrinker *s, struct shrink_control *sc)
{
	int count = 0;
	struct cmd_struct *p, *next;

	mutex_lock(&kp_mutex);
	list_for_each_entry_safe(p, next, &k_pool, list) {
		count += 1;
		list_del(&p->list);
		kmem_cache_free(cmd_struct_cachep, p);
	}
	mutex_unlock(&kp_mutex);

	return count;
}

/*
 * list_remove_work - Retire un élément cmd_struct de la liste des
 * commandes actives, la fonction est appelée quand le champ refcount 
 * d'une cmd_struct a été mis à 0 par kref_put
 */
static void list_remove_work(struct kref *ref)
{
	int to_copy, eot = 0;
	void __user *to_i, *to_p;
	const void *from_i, *from_p;

	struct common *up;
	struct cmd_struct *p;

	p = container_of(ref, struct cmd_struct, refcount);
	up = (struct common *)p->user_datap;

	/*
	 * Kshell pipe - Data Transfer from kernel to user space.
	 * 
	 * The idea is quick simple; if can't transfer at once, transfer as
	 * mush as possible, mark this job as a FINISHED asynchronous one and
	 * return. User space responsability is then to reclaim the remaining
	 * data using `fg <pipe_id>`,
	 *
	 *
	 * WARNING: DON'T TRANSFER IF p->err WAS SET PREVIOUSLY.
	 * if allocated, p->private_data is freed as soon as p->err is set and
	 * may be done in the workqueue.
	 */

	to_i = &up->pipe_id;
	from_i = &p->cmd_id;

	to_p = up->buffer;
	from_p = p->private_data;

	if(!p->err && p->private_data_len) {
		to_copy = min(USER_BUFFER_SIZE - 1 , p->private_data_len);

		/* data_transfer */
		p->err += copy_to_user(to_p, from_p, to_copy);

		/* some parameterising.. */
		p->private_data_len -= to_copy;
		p->private_data += to_copy;

		if (!p->err && p->private_data_len > 0) {

			/* pipe_id = cmd_id, a new one in each iteration */
			p->err += copy_to_user(to_i, from_i, sizeof(int));

			/* cmd_id management, - see fg_handler */
			if (p->fg_ed_cmd_id != 0)
				cmd_id[p->fg_ed_cmd_id - 1] = 0;

			/* Because it's refcount was zeroed, as we are here. */
			kref_get(ref);

			/* FINISHED asynchronous cmd */
			p->fg_cond = true;

			/* this `cmd` can be reclaimed by `fg` */
			p->fg_ed = false;
			return;
		}

		/* EOT - End Of Transfer */
		p->err += copy_to_user(to_i, (const void *)&eot, sizeof(int));
		kfree(p->private_data);
	}

	spin_lock(&kc_lock);
	list_del(&p->list);
	spin_unlock(&kc_lock);

	/* Error transfer - from wq to user space */
	ioctl_err = p->err;

	/* From kshell_cmd_list to kshell_pool */
	pool_add_entry(p);
}

/*
 * list_add_work - Ajoute une cmd_struct dans la liste
 * des commandes actives
 */
static void list_add_work(struct cmd_struct *w)
{
	spin_lock(&kc_lock);
	list_add_tail(&w->list, &kshell_cmd_list);
	spin_unlock(&kc_lock);
}

/*
 * Chaque handler correspond à une commande que l'utilisateur
 * peut utiliser 
 */

static void reset_handler(void)
{
	struct cmd_struct *p, *next;

	flush_workqueue(kshell_wq);

	spin_lock(&kc_lock);
	list_for_each_entry_safe(p, next, &kshell_cmd_list, list) {
		list_del(&p->list);

		reset_cmd_id(p->cmd_id, p->fg_ed_cmd_id);
		if(!p->err && p->private_data_len)
			kfree(p->private_data);
		kmem_cache_free(cmd_struct_cachep, p);
	}
	spin_unlock(&kc_lock);

	mutex_lock(&kp_mutex);
	list_for_each_entry_safe(p, next, &k_pool, list) {
		list_del(&p->list);
		kmem_cache_free(cmd_struct_cachep, p);
	}
	mutex_unlock(&kp_mutex);
}

static void fg_handler(struct work_struct *w)
{
	int cmd_id, err;
	bool found = false;
	struct common *cp;
	struct cmd_struct *p, *ip;

	p = container_of(w, struct cmd_struct, work);
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

	/* Job not found */
	if (!found) {
		p->err = -1;
		goto out;
	}

	/* Protect ourselves from -ERESTARTSYS*/
	while (wait_event_interruptible(waiter, ip->fg_cond != 0))
		;

	/* after this, `fg` will looks as ip->cmd */
	p->err = ip->err; /* happened errors in (ip->cmd)_handler */
	p->fg_ed_cmd_id = cmd_id; /* == ip->cmd_id */
	p->private_data = ip->private_data;
	p->private_data_len = ip->private_data_len;

	kref_put(&ip->refcount, kref_ed_entry);

out:
	p->ioctl_cond = 1;
	kref_put(&p->refcount, list_remove_work);
	wake_up_interruptible(&waiter);
}

static void list_handler(struct work_struct *w)
{
	int i, len, count, buffer_size;
	char *buffer, *buffer_realloc, v[32];
	struct cmd_struct *p, *ip;

	i = 1;
	len = 0;
	count = 0;
	buffer_size = BUFF_SIZE;
	p = container_of(w, struct cmd_struct, work);

	buffer = kmalloc(buffer_size, GFP_KERNEL);
	if (!buffer) {
		p->err = -ENOMEM;
		goto out;
	}

	spin_lock(&kc_lock);
	list_for_each_entry(ip, &kshell_cmd_list, list) {

		switch (ip->cmd) {
		case kill:
			len = scnprintf(v, sizeof(v), "kill\t%d\n", ip->cmd_id);
			break;

		case wait:
			len = scnprintf(v, sizeof(v), "wait\t%d\n", ip->cmd_id);
			break;

		case meminfo:
			len = scnprintf(v, sizeof(v), "meminfo\t%d\n", ip->cmd_id);
			break;

		case modinfo:
			len = scnprintf(v, sizeof(v), "modinfo\t%d\n", ip->cmd_id);
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
			if (!buffer) {
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
	p->ioctl_cond = 1;
	kref_put(&p->refcount, list_remove_work);
	wake_up_interruptible(&waiter);
}


static void meminfo_handler(struct work_struct *w)
{
	int len, count = 0;
	struct sysinfo si;
	struct cmd_struct *p;
	char v[32];
	char *buffer;

	p = container_of(w, struct cmd_struct, work);

	buffer = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (!buffer) {
		p->err = -ENOMEM;
		goto out;
	}
	
	memset(buffer, '\0', BUFF_SIZE * sizeof(char));
	si_meminfo(&si);
	si_swapinfo(&si);
	
	len = scnprintf(v, sizeof(v), "MemTotal:\t%lu kB\n", KB(si.totalram));
	strncat(buffer, v, len);
	count += len;

	len = scnprintf(v, sizeof(v), "MemFree:\t%lu kB\n", KB(si.freeram));
	strncat(buffer, v, len);
	count += len;

	len = scnprintf(v, sizeof(v), "BufferRam:\t%lu kB\n", KB(si.bufferram));
	strncat(buffer, v, len);
	count += len;

	len = scnprintf(v, sizeof(v), "HighTotal:\t%lu kB\n", KB(si.totalhigh));
	strncat(buffer, v, len);
	count += len;
	
	len = scnprintf(v, sizeof(v), "HighFree:\t%lu kB\n", KB(si.freehigh));
	strncat(buffer, v, len);
	count += len;

	len = scnprintf(v, sizeof(v), "LowTotal:\t%lu kB\n", KB((si.totalram - si.totalhigh)) );
	strncat(buffer, v, len);
	count += len;

	len = scnprintf(v, sizeof(v), "LowFree:\t%lu kB\n", KB((si.freeram - si.freehigh)) );
	strncat(buffer, v, len);
	count += len;

	len = scnprintf(v, sizeof(v), "SwapTotal:\t%lu kB\n", KB(si.totalswap));
	strncat(buffer, v, len);
	count += len;

	len = scnprintf(v, sizeof(v), "SwapFree:\t%lu kB\n", KB(si.freeswap));
	strncat(buffer, v, len);
	count += len;
	
	p->private_data = buffer;
	p->private_data_len = count;

out:
	kref_put(&p->refcount, list_remove_work);

	if (p->asynchro) {
		p->fg_cond = 1;
		wake_up_interruptible(&waiter);
	} else {
		p->ioctl_cond = 1;
		wake_up_interruptible(&waiter);
	}
}

static void kill_handler(struct work_struct *w){
	int proc_pid;
	int sig;
	int err;
	struct pid *pid;
	struct common *cp;
	struct cmd_struct *p;

	p = container_of(w, struct cmd_struct, work);
	cp = (struct common *)p->user_datap;
	
	err = __get_user(proc_pid, (int __user *)&cp->cmd_id);
	err += __get_user(sig, (int __user *)&cp->sig);
	if (err) {
		pr_info("[  kshell_KILL ] error at copy_from_user.\n");
		p->err = -EFAULT;
		goto out;
	}
	
	pid = find_get_pid(proc_pid);
	if (!pid) {
		pr_info("[KILL] PID NOT FOUND \n");
		p->err = -EFAULT;
		goto out;
	}

	err = kill_pid(pid, sig, 1);
	put_pid(pid);
	
	p->err = err;

out:
	kref_put(&p->refcount, list_remove_work);

	if (p->asynchro) {
		p->fg_cond = 1;
		wake_up_interruptible(&waiter);
	} else {
		p->ioctl_cond = 1;
		wake_up_interruptible(&waiter);
	}

}

static void modinfo_handler(struct work_struct *w)
{
	int i, len, count, err;
	char *buffer, v[32];
	struct module *m;
	struct cmd_struct *p;
	struct common *cp;

	count = 0;
	p = container_of(w, struct cmd_struct, work);
	cp = (struct common *)p->user_datap;
	
	buffer = kmalloc(BUFF_SIZE, GFP_KERNEL);
	if (!buffer) {
		p->err = -ENOMEM;
		goto out;
	}

	memset(v, '\0', sizeof(v));
	memset(buffer, '\0', BUFF_SIZE * sizeof(char));

	err = __get_user(len, (int __user *)&cp->len);
	err += copy_from_user((void *)v, (void __user *)cp->name, len);
	if (err) {
		pr_info("[  kshell_MODINFO ] error at copy_from_user.\n");
		kfree(buffer);
		p->err = -EFAULT;
		goto out;
	}

	/*
	 * From module.h#L305
	 * Search for module by name, must hold module_mutex.
	 */

	mutex_lock(&module_mutex);
	m = find_module(v);
	mutex_unlock(&module_mutex);

	if (!m) {
		kfree(buffer);
		p->err = -2;
		goto out;
	}

	/*
	 * Because module functions can be called even in the GOING state until
	 * m->exit() finishes.
	 *
	 */
	#ifdef CONFIG_LIVEPATCH
		if (!m->klp_alive) {
			p->err = -1;
			kfree(buffer);
			goto out;
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

	if (p->asynchro) {
		p->fg_cond = 1;
		wake_up_interruptible(&waiter);
	} else {
		p->ioctl_cond = 1;
		wake_up_interruptible(&waiter);
	}
}

/* 
 * kshell_ioctl - La fonction exécutée lorsque l'utilisateur
 * fait un appel système ioctl
 */
static long kshell_ioctl(struct file *iof, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	struct cmd_struct *s;

	/*
	 * extracts the type and number bitfields, and don't decode wrong CMDs:
	 * return -ENOTTY (Inappriopariate ioctl) before switching.
	 */

	if (_IOC_TYPE(cmd) != KSHELL_IOC_MAGIC)
		return -ENOTTY;
	if (_IOC_NR(cmd) > KSHELL_IOC_MAXNR)
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


	ioctl_err = 0;
	s = pool_alloc_entry();
	if (s == NULL) {
		s = kmem_cache_alloc(cmd_struct_cachep, GFP_KERNEL);
		if (unlikely(!s))
			return -ENOMEM;
	}

	memset(s, '\0', sizeof(struct cmd_struct));
	kref_init(&s->refcount); 
	
	s->cmd_id = find_cmd_id();
	s->user_datap = (void *)arg;

	switch (cmd) {
	case SYNC_IOC_LIST:
		s->cmd = list;
		INIT_WORK(&s->work, list_handler);
		break;

	case SYNC_IOC_FG:
		s->cmd = fg;
		/*
		 * Set `fg_ed` to protect this cmd to be fg_ed by another `fg`
		 * from another terminal as our driver isn't a single openness.
		 */
		s->fg_ed = true;
		INIT_WORK(&s->work, fg_handler);
		break;

	case ASYNC_IOC_KILL:
		s->asynchro = true;

	case SYNC_IOC_KILL:
		s->cmd = kill;
		INIT_WORK(&s->work, kill_handler);
		break;

	case ASYNC_IOC_WAIT:
		s->asynchro = true;

	case SYNC_IOC_WAIT:
		s->cmd = wait;
		INIT_WORK(&s->work, list_handler);
		break;

	case ASYNC_IOC_MEMINFO:
		s->asynchro = true;

	case SYNC_IOC_MEMINFO:
		s->cmd = meminfo;
		INIT_WORK(&s->work, meminfo_handler);
		break;

	case ASYNC_IOC_MODINFO:
		s->asynchro = true;

	case SYNC_IOC_MODINFO:
		s->cmd = modinfo;
		INIT_WORK(&s->work, modinfo_handler);
		break;

	case KSHELL_IOC_RESET:
		pool_add_entry(s);
		reset_handler();
		return 0;

	default: /* redudant, as cmd was checked before !*/
		pool_add_entry(s);
		return -ENOTTY;
	}

	/*  Get a reference for the `fg` which reclaim this job - see fg_handler */
	if(s->asynchro)
		kref_get(&s->refcount);

	/* Get a reference for the thread worker */
	kref_get(&s->refcount);

	list_add_work(s);
	schedule_work(&s->work);

	if (!s->asynchro)
		/* Protect ourselves from -ERESTARTSYS */
		while (wait_event_interruptible(waiter, s->ioctl_cond != 0))
			;

	kref_put(&s->refcount, list_remove_work);
	return ioctl_err;
}

const struct file_operations kshell_fops = {
	.unlocked_ioctl = kshell_ioctl
};

static struct shrinker kshell_shrinker = {
	.count_objects = pool_count,
	.scan_objects = pool_scan,
	.seeks = DEFAULT_SEEKS,
};

static int __init hello_init(void)
{
	int err;

	/* NOTE: `SLAB_PANIC` causes the slab layer to panic if the allocation
	 * fails. This flag is useful when the allocation must not fail.
	 * ^see slab.h^ 
	 *
	 * As result, the return value is not checked for NULL.
	 */
	cmd_struct_cachep = KMEM_CACHE(cmd_struct, SLAB_PANIC);

	major = register_chrdev(0, "kshell", &kshell_fops);
	if (major < 0) {
		pr_info("[  kshell  ]  Module loading failed.\n");
		pr_info("[  kshell  ]  register_chrdev() reurned %d.\n", major);
		goto out_kmem_destroy;
	}

	kshell_wq = create_workqueue("kshell");
	if (!kshell_wq)
		goto out_unregister;

	err = register_shrinker(&kshell_shrinker);
	if (err)
		goto out_wq_destroy;

	mutex_init(&id_mutex);
	mutex_init(&kp_mutex);

	pr_info("[  kshell  ]  Module loaded successfully\n");
	return 0;

out_wq_destroy:
	destroy_workqueue(kshell_wq);

out_unregister:
	unregister_chrdev(major, "kshell");

out_kmem_destroy:
	kmem_cache_destroy(cmd_struct_cachep);

	return -1;
}
module_init(hello_init);

static void __exit hello_exit(void)
{
	reset_handler();
	
	destroy_workqueue(kshell_wq);
	unregister_shrinker(&kshell_shrinker);
	kmem_cache_destroy(cmd_struct_cachep);

	unregister_chrdev(major, "kshell");
	pr_info("[  kshell  ]  Module unloaded successfully\n");
}
module_exit(hello_exit);
