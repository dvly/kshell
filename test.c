#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "common.h"
/*
VOid test_meminfo(int fd)
{
	int ri;
	struct meminfo_common *buf;
	buf = (struct meminfo_common *)malloc(sizeof(struct meminfo_common *));
	ri = ioctl(fd, KSHELL_IOC_MEMINFO, (void *)buf);
	if(ri)
		printf("[ MEMINFO ] Error %d\n", ri);

	else{
		printf("%s\n", buf->MemTotal);
	}
}
*/


void test_modinfo(int fd, char *mname)
{
	int ri = 1;
	struct common buf;

	memset(&buf, '\0', sizeof(struct common));
	buf.len = strlen(mname);
	strncpy(buf.name, mname, buf.len);

	ri = ioctl(fd, KSHELL_IOC_MODINFO, (void *)&buf);
	printf("return value is %d\n", ri);
	printf("%s\n", buf->buffer);
}

void test_list_synchro(int fd, char *mname)
{
        int ri;
	struct common *buf;
        buf = (struct common *)malloc(sizeof(struct common *));
	memset(buf, '\0', sizeof(struct common));
        ri = ioctl(fd, SSHELL_IOC_LIST, (void *)buf);
}

void test_list(int fd)
{
        int ri;
        struct common *buff;
        buff = (struct common *)malloc(sizeof(struct common *));
        memset(buff, '\0', sizeof(struct common));

        ri = ioctl(fd, KSHELL_IOC_LIST, (void *)buff);

	printf("[  LIST  ] %d\n", ri);
	printf("%s", buff->buffer);
}

void test_fg(int fd, int id)
{
	int ri;
	char *buf = (char *)malloc(64);
	
	ri = ioctl(fd, KSHELL_IOC_SETFG, (void *)&id);
	ri = ioctl(fd, KSHELL_IOC_FG, (void *)buf);

        printf("[ FG  ]\n");
        printf("[ FG  ] %d\n", ri);
        printf("[ FG  ] %s\n", buf);
}

int main(int argc, char **argv)
{
	int fd;

	fd = open("/dev/kshell", O_RDWR);
	if (fd == -1)
		exit(1);

	//test_modinfo(fd, "kshell");
	test_list(fd);
	//test_meminfo(fd);
	close(fd);

	return 0;
}


