#include "kshell.h"

MODULE_DESCRIPTION("Module \"kernel shell\" pour noyau linux");
MODULE_AUTHOR("Sofiane IDRI - Davy LY, UPMC");
MODULE_LICENSE("GPL");

static int major;
enum kshell_cmd {list, fg, kill, wait, meminfo, modinfo};

struct kshell_struct {
	struct work_struct work;
	struct list_head list;
	enum kshell_cmd cmd;
};

/* List and lock for all CMDs */
static LIST_HEAD(kshell_cmd_list);
static DEFINE_SPINLOCK(kc_lock);

static void remove_work(struct kshell_struct *w)
{
	spin_lock(&kc_lock);
	list_del(&w->list);
	kfree(w);
	spin_unlock(&kc_lock);
}

static void add_work(struct kshell_struct *w)
{
	spin_lock(&kc_lock);
	list_add_tail(&w->list, &kshell_cmd_list);
	spin_unlock(&kc_lock);
}

static void list_handler(void)
{
	struct kshell_struct *f;

	spin_lock(&kc_lock);
	list_for_each_entry(f, &kshell_cmd_list, list) {
		switch (f->cmd) {
		case list:
			pr_info("ls cmd\n");
			break;

		case fg:
			pr_info("fg cmd\n");
			break;

		case kill:
			pr_info("kill cmd\n");
			break;

		case wait:
			pr_info("wait cmd\n");
			break;

		case meminfo:
			pr_info("meminfo cmd\n");
			break;

		case modinfo:
			pr_info("modinfo cmd\n");
			break;

		default:
			pr_info("error.\n");
			break;
		}
	}
	spin_unlock(&kc_lock);
}

static long kshell_ioctl(struct file *iof, unsigned int cmd, unsigned long arg)
{
	int rcu;

	if (_IOC_TYPE(cmd) != KSHELL_IOC_MAGIC)
		return -ENOTTY;

	switch (cmd) {
	case KSHELL_IOC_TEST:
		rcu = copy_to_user((void *)arg, "TEST ok", 7);
		if (rcu)
			pr_info("[  kshell_ioctl  ]  copy_to_user Error.\n");

		pr_info("[  kshell  ] %d\n", rcu);
		break;

	case KSHELL_IOC_LIST:
		pr_info("[  kshell_ioctl ]  list.\n");
		break;

	case KSHELL_IOC_FG:
		pr_info("[  kshell_ioctl ]  FG.\n");
		break;

	case KSHELL_IOC_KILL:
		pr_info("[  kshell_ioctl ]  KILL.\n");
		break;

	case KSHELL_IOC_WAIT:
		pr_info("[  kshell_ioctl ]  WAIT.\n");
		break;

	case KSHELL_IOC_MEMINFO:
		pr_info("[  kshell_ioctl ]  MEMINFO.\n");
		break;

	case KSHELL_IOC_MODINFO:
		pr_info("[  kshell_ioctl ]  MODINFO.\n");
		break;

	default:
		pr_info("[  kshell_ioctl ]  ERROR.\n");
		return -ENOTTY;
	}

	return 0;
}

const struct file_operations kshell_fops = {
	.unlocked_ioctl = kshell_ioctl
};

static void test(void)
{
	struct kshell_struct *s;

	s  = kmalloc(sizeof(s), GFP_KERNEL);
	s->cmd = wait;

	add_work(s);
	list_handler();
	remove_work(s);
}

static int __init hello_init(void)
{
	major = register_chrdev(0, "kshell", &kshell_fops);
	if (major < 0) {
		pr_info("[  kshell  ]  Module loading failed.\n");
		pr_info("[  kshell  ]  register_chrdev() reurned %d.\n", major);
		goto out;
	}

	pr_info("[  kshell  ]  Module loaded successfully\n");

	/* Test and remove the "not used warning */
	test();

out:
	return 0;
}
module_init(hello_init);

static void __exit hello_exit(void)
{
	unregister_chrdev(major, "kshell");
	pr_info("[  kshell  ]  Module unloaded successfully\n");
}
module_exit(hello_exit);
