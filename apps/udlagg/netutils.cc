#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "app.h"
#include "utils.h"
#include "netutils.h"

#define LISTEN_BACK_LOG 100

int init_primary(int, uint32_t, uint16_t, uint32_t, uint16_t);
int init_replica(int, uint32_t, uint16_t, uint32_t, uint16_t, uint32_t, uint16_t);
int read_socket_internal(int fd, char *buf, size_t count, int arb);

int 
create_socket(int *ifd)
{
	int error = 0, opt = 1, fd;

	/* Init socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		APPERR("Failed to create socket.\n");
		exit(0);
	}

	error = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (error != 0) {
		SYSERR(error, "Failed to set SO_REUSEADDR.\n");
		exit(0);
	}

	error = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	if (error != 0) {
		SYSERR(error, "Failed to set SO_REUSEPORT.\n");
		exit(0);
	}

	error = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt, sizeof(opt));
	if (error != 0) {
		SYSERR(error, "Failed to set SO_REUSEPORT_LB.\n");
		exit(0);
	}

	error = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
	if (error != 0) {
		SYSERR(error, "Failed to set SO_NOSIGPIPE.\n");
		exit(0);
	}

	*ifd = fd;

	return (error);
}


int 
init_socket(int *ifd, uint32_t addr, uint16_t port, 
    int somig_mode, uint32_t mso_addr, uint16_t mso_port, 
    uint32_t rso_addr, uint16_t rso_port)
{
	*ifd = 0;
	return (0);
}

int 
accept_socket(int fd)
{
	int tmpfd;
	socklen_t len;
	struct sockaddr_in address;

	tmpfd = accept(fd, (struct sockaddr *)&address, &len);
	if (tmpfd < 0) {
		return (-1);
	}

	return (tmpfd);
}

int 
bind_socket(int fd, uint32_t addr, uint16_t port)
{
	struct sockaddr_in address;

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = addr;
	address.sin_port = port;

	return (bind(fd, (struct sockaddr *)&address, sizeof(address)));
}

void
listen_socket(int fd)
{
	listen(fd, LISTEN_BACK_LOG);
}

int 
connect_socket(int fd, uint32_t ip, uint16_t port)
{
	struct sockaddr_in sa;

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ip;
	sa.sin_port = port;

	return (connect(fd, (struct sockaddr *)&sa, sizeof(struct sockaddr)));
}

int 
init_primary(int fd, uint32_t app_addr, uint16_t app_port, uint32_t addr, uint16_t port)
{
#ifdef SOMIGRATION
	int opt = 1, err = 0;
	struct sockaddr_in address;
	
	opt = SOMIG_PRIMARY;
	err = setsockopt(fd, SOL_SOCKET, SO_MIG_ROLE, &opt, sizeof(opt));
	if (err) {
		SYSERR(err, "Failed to init primary role.\n");
		exit(0);
	}

#ifdef SMCP
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = app_addr;
	address.sin_port = app_port;

	if (setsockopt(fd, SOL_SOCKET, SO_MIG_PREBIND, 
		(struct sockaddr*)&address, sizeof(address))) {
		perror("setsockopt - somigpostbind");
		return (-1);
	}
#endif

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = addr;
	address.sin_port = port;
	err = setsockopt(fd, SOL_SOCKET, SO_MIG_BIND, 
	    (struct sockaddr *)&address, sizeof(address));
	if (err) {
		SYSERR(err, "Failed to bind SOMIG.\n");
		exit(0);
	}

	opt = 1;
	err = setsockopt(fd, SOL_SOCKET, SO_MIG_LISTEN, &opt, sizeof(opt));
	if (err) {
		SYSERR(err, "Failed to listen.\n");
		exit(0);
	}
	
#else
	APPERR("Current kernel does not have SOMIG support.\n");
	exit(0);
#endif
	return 0;
}

int
init_replica(int fd, uint32_t app_addr, uint16_t app_port, 
    uint32_t paddr, uint16_t pport, uint32_t raddr, uint16_t rport)
{
#ifdef SOMIGRATION
	int opt = 1, error = 0;
	struct sockaddr_in address;

	opt = SOMIG_REPLICA;
	error = setsockopt(fd, SOL_SOCKET, SO_MIG_ROLE, &opt, sizeof(opt));
	if (error) {
		SYSERR(error, "Failed to init replica role.\n");
		exit(0);
	}

#ifdef SMCP
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = app_addr; 
	address.sin_port = app_port;

	if (setsockopt(fd, SOL_SOCKET, SO_MIG_PREBIND, 
		(struct sockaddr*)&address, sizeof(address))) {
		perror("setsockopt - somigpostbind");
		return (-1);
	}
#endif

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = raddr;
#ifndef SMCP
	address.sin_port = rport;
#endif
	error = setsockopt(fd, SOL_SOCKET, SO_MIG_BIND, 
	    (struct sockaddr *)&address, sizeof(address));
	if (error) {
		SYSERR(error, "Failed to bind SOMIG.\n");
		exit(0);
	}
	
	opt = 1;
	error = setsockopt(fd, SOL_SOCKET, SO_MIG_LISTEN,
	    (struct sockaddr *)&opt, sizeof(opt));
	if (error) {
		SYSERR(error, "Failed to change into listening state.\n");
		exit(0);
	}

	address.sin_addr.s_addr = paddr;
#ifndef SMCP
	address.sin_port = pport;
#endif
	error = setsockopt(fd, SOL_SOCKET, SO_MIG_CONNECT,
	    (struct sockaddr *)&address, sizeof(address));
	if (error) {
		SYSERR(error, "Failed to connect to primary.\n");
		exit(0);
	}
#else
	APPERR("Current kernel does not have SOMIG support.\n");
	exit(0);
#endif
	return (0);
}

int
readonce_socket(int fd, char *buf, size_t count)
{
	return read_socket_internal(fd, buf, count, 1);
}

int 
read_socket(int fd, char *buf, size_t count)
{
	return read_socket_internal(fd, buf, count, 0);
}

int 
read_socket_internal(int fd, char *buf, size_t count, int arb)
{
	ssize_t n, left = count;
	while (left > 0) {
		n = read(fd, buf, left);
		if (n < 0) {
			return (-1);
		}
		if (n == 0) {
			return (count - left);
		}
		left -= n;
		buf += n;
		if (arb)
			break;
	}
	return (count - left);
}

int
write_socket(int fd, const char *buf, size_t count)
{
	ssize_t n, left = count;
	while (left > 0) {
		n = write(fd, buf, left);
		if (n < 0) {
			DBG("Write returned errno %d", errno);
			return (-1);
		}
		if (n == 0) {
			DBG("Wrote 0 byte to client.");
			return (-1);
		}
		left -= n;
		buf += n;
	}
	return (count - left);
}

int
get_sockinfo(int fd, int *type, uint32_t *addr, uint16_t *port)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);

	if (getsockname(fd, (struct sockaddr *)&sin, &len) == -1) {
		return (1);
	} else {
		*type = (int)sin.sin_family;
		*addr = sin.sin_addr.s_addr;
		*port = sin.sin_port;
		return (0);
	}
}

int
get_socket_avail_bytes(int fd)
{
	int c, err = 0;

	err = ioctl(fd, FIONREAD, &c);
	if (err != 0) {
	    return (-1);
	}

	return (c);
}

struct tcp_stat
get_tcp_info(int fd)
{
	struct tcp_stat rt;
	struct tcp_info tinfo;
	socklen_t ti_len = sizeof(struct tcp_info);

	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, (void *)&tinfo, &ti_len)) {
		SYSERR(errno, "Cannot get tcp info from fd %d.", fd);
		return (rt);
	}

	rt.tcp_state = tinfo.tcpi_state;
	rt.rtt = tinfo.tcpi_rtt;
	rt.rtt_var = tinfo.tcpi_rttvar;
	rt.ss_thres = tinfo.tcpi_snd_ssthresh;
	rt.snd_cwnd = tinfo.tcpi_snd_cwnd;
	rt.rcv_space = tinfo.tcpi_rcv_space;
	rt.snd_rexmitpkt = tinfo.tcpi_snd_rexmitpack;
	rt.rcv_ooopkt = tinfo.tcpi_rcv_ooopack;

#ifdef SOMIGRATION
	rt.smg_bufsize = tinfo.tcpi_smg_bufsize;
	rt.smg_bufsize_cso = tinfo.tcpi_smg_bufsize_cso;
	rt.smg_clicpu = tinfo.tcpi_cli_cpu_id;
	rt.smg_smgcpu = tinfo.tcpi_smg_cpu_id;
#endif

	return (rt);
}
