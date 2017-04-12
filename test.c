#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "kshell.h"

int main(int argc, char **argv)
{

	int ri;
	int fd;
	char *buf;

	buf = (char *)malloc(128);

	fd = open("/dev/kshell", O_RDWR);
	if (fd == -1)
		exit(1);

	ri = ioctl(fd, KSHELL_IOC_TEST, (void *)buf);

	printf("[  test  ] %d\n", ri);
	printf("[  test  ] %s\n", buf);

	return 0;
}

