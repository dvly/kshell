#include <linux/ioctl.h>

#define PARAM_BUFF_SIZE	5
#define KSHELL_IOC_MAGIC 'N'

#define SYNC_IOC_LIST		_IOWR(KSHELL_IOC_MAGIC, 0, char *)
#define SYNC_IOC_FG			_IOWR(KSHELL_IOC_MAGIC, 1, char *)
#define	SYNC_IOC_KILL		_IOWR(KSHELL_IOC_MAGIC, 2, char *)
#define SYNC_IOC_WAIT		_IOWR(KSHELL_IOC_MAGIC, 3, char *)
#define SYNC_IOC_MEMINFO	_IOWR(KSHELL_IOC_MAGIC, 4, char *)
#define SYNC_IOC_MODINFO	_IOWR(KSHELL_IOC_MAGIC, 5, char *)

#define ASYNC_IOC_LIST		_IOWR(KSHELL_IOC_MAGIC, 6, char *)
#define ASYNC_IOC_KILL		_IOWR(KSHELL_IOC_MAGIC, 7, char *)
#define ASYNC_IOC_WAIT		_IOWR(KSHELL_IOC_MAGIC, 8, char *)
#define ASYNC_IOC_MEMINFO	_IOWR(KSHELL_IOC_MAGIC, 9, char *)
#define ASYNC_IOC_MODINFO	_IOWR(KSHELL_IOC_MAGIC, 10, char *)

#define KSHELL_IOC_RESET	_IOWR(KSHELL_IOC_MAGIC, 11, char *)
#define KSHELL_IOC_MAXNR	_IOWR(KSHELL_IOC_MAGIC, 12, char *)

#define USER_BUFFER_SIZE 5

#define BUFF_SIZE 1024

struct common {
	char name[32];
	char buffer[USER_BUFFER_SIZE];
	int cmd_id;
	int len;
	int pipe_id;
};
