#pragma once

#include "const.h"
#include <cerrno>
#include <sys/ioctl.h>
#include <sys/event.h>
#include <stdint.h>
#include <sys/socket.h>
#include <thread>
#include <stdio.h>
#include <sys/param.h>

#define W(fmt, ...) do { \
	fprintf(stderr, "[WARN] " fmt, ##__VA_ARGS__); \
} while(0)

#define E(fmt, ...) do { \
	fprintf(stderr, "[ERROR] " fmt, ##__VA_ARGS__); \
	exit(1); \
} while(0)

#define V(fmt, ...) do { \
	if (options.verbose) { \
	fprintf(stdout, "[INFO] " fmt, ##__VA_ARGS__); \
	} \
} while(0)

static inline int
readbuf(int fd, void *buf, int len)
{
	int status;

	do {
		if ((status = recv(fd, buf, len, 0)) < 0) {
			return -1;
		} else if (status == 0) { // connection disconnected.
			return -1;
		}
		buf = (char*)buf + status;
		len -= status;
	} while (len > 0);

	return 0;
}

static inline int
writebuf(int fd, void * buf, int len)
{
	int status;

	do {
		if ((status = send(fd, buf, len, 0)) < 0) {
			return -1;
		} else if (status == 0) {
			return -1;
		}
		buf = (char*) buf + status;
		len -= status;
	} while (len > 0);

	return 0;
}

static inline int 
readmsg(int fd, char *buf, int len)
{
	if ((uint)len < sizeof(struct ppd_msg)) {
		return EOVERFLOW;
	}

	int status = readbuf(fd, buf, sizeof(struct ppd_msg));

	if (status != 0) {
		return status;
	}

	if (((struct ppd_msg *)buf)->size + sizeof(ppd_msg) > (uint)len) {
		return EOVERFLOW;
	}

	if (((struct ppd_msg *)buf)->size > 0) {
		status = readbuf(fd, buf + sizeof(ppd_msg), ((struct ppd_msg *)buf)->size);
	}
	
	return status;
}

static inline int
writemsg(int fd, char *buf, int len, const char *msg, int mlen)
{
	int real_len = sizeof(struct ppd_msg) + mlen;
	if (len < real_len) {
		return EOVERFLOW;
	}

	struct ppd_msg * m = (struct ppd_msg *)buf;
	memmove(m->payload, msg, mlen);

	m->size = mlen;

	return writebuf(fd, buf, real_len);
}

static inline int 
get_numcpus()
{
	return std::thread::hardware_concurrency();
}

static inline uint64_t
get_time_us() 
{
  	struct timespec ts;
  	clock_gettime(CLOCK_REALTIME, &ts);
  	//  clock_gettime(CLOCK_REALTIME, &ts);
  	return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

#define UNUSED(x) (x)
