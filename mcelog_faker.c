/* a test tool to act as a fake mcelog */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "mced.h"

/*
 * Call as:
 *  mcelog_faker path
 *  	send 1 MCE for every character it reads on stdin
 *  	e.g. yes "" | mcelog_faker ./test_dev
 *  mcelog_faker path number
 *  	send <number> MCEs and exit
 *  	e.g. mcelog_faker ./test_dev 1000
 */
int
main(int argc, char *argv[])
{
	int fd;
	struct stat stbuf;
	unsigned long nmces = 0;
	int do_unlink = 0;

	if (argc != 2 && argc != 3) {
		printf("usage: %s <path> <nmces=0>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (argc == 3) {
		nmces = strtoul(argv[2], NULL, 0);
	}

	/* create the FIFO if needed */
	if (stat(argv[1], &stbuf) < 0 && errno == ENOENT) {
		if (mkfifo(argv[1], 0600) < 0) {
			perror("mkfifo()");
			exit(EXIT_FAILURE);
		}
		do_unlink = 1;
	}

	fd = open(argv[1], O_WRONLY);
	if (fd < 0) {
		perror("open()");
		if (do_unlink) {
			unlink(argv[1]);
		}
		exit(EXIT_FAILURE);
	}

	printf("fake MCE device: %s\n", argv[1]);

	if (nmces == 0) {
		printf("press enter to generate an MCE\n");
		setvbuf(stdin, NULL, _IONBF, 0);
		while (1) {
			int n;
			char buf[10];
			struct kernel_mce mce;
			n = read(STDIN_FILENO, &buf, sizeof(buf));
			if (n == 0) {
				break;
			}
			if (n < 0) {
				perror("read()");
				close(fd);
				if (do_unlink) {
					unlink(argv[1]);
				}
				exit(EXIT_FAILURE);
			}
			memset(&mce, 0, sizeof(mce));
			while (n--) {
				if (write(fd, &mce, sizeof(mce)) < 0) {
					perror("write()");
					close(fd);
					if (do_unlink) {
						unlink(argv[1]);
					}
					exit(EXIT_FAILURE);
				}
			}
		}
	} else {
		struct kernel_mce *mces;
		printf("sending %lu MCEs\n", nmces);
		mces = malloc(nmces * sizeof(*mces));
		if (mces == NULL) {
			perror("malloc()");
			close(fd);
			if (do_unlink) {
				unlink(argv[1]);
			}
			exit(EXIT_FAILURE);
		}
		memset(mces, 0, nmces * sizeof(*mces));
		if (write(fd, mces, nmces * sizeof(*mces)) < 0) {
			perror("write()");
			close(fd);
			if (do_unlink) {
				unlink(argv[1]);
			}
			exit(EXIT_FAILURE);
		}
		sleep(5);
	}

	close(fd);
	if (do_unlink) {
		unlink(argv[1]);
	}
	exit(EXIT_SUCCESS);
}
