#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"
#include "netutil.h"

int read_socket_internal(int fd, char *buf, size_t count, int arb);

int 
init_socket(int *ifd)
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

	error = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
	if (error != 0) {
		SYSERR(error, "Failed to set SO_NOSIGPIPE.\n");
		exit(0);
	}

	*ifd = fd;

	return (error);
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
		if (type)
			*type = (int)sin.sin_family;
		if (addr)
			*addr = ntohl(sin.sin_addr.s_addr);
		if (port)
			*port = ntohs(sin.sin_port);
		return (0);
	}
}

int
get_peerinfo(int fd, int *type, uint32_t *addr, uint16_t *port)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);

	if (getpeername(fd, (struct sockaddr *)&sin, &len) == -1) {
		return (1);
	} else {
		if (type)
		    *type = (int)sin.sin_family;
		if (addr)
		    *addr = ntohl(sin.sin_addr.s_addr);
		if (port)
		    *port = ntohs(sin.sin_port);
		return (0);
	}

}

uint32_t
get_ip_from_hostname(const char* hostname) 
{
	struct in_addr **addr;
	struct hostent *he;
	struct sockaddr_in sa;
	int val;

	val = inet_pton(AF_INET, hostname, &(sa.sin_addr));
	if (val != 0) {
		return sa.sin_addr.s_addr;
	}

	if ((he = gethostbyname(hostname)) == NULL) {
		SYSERR(errno, "Hostname %s cannot be resolved.\n", hostname);
		return 0;
	}
	addr = (struct in_addr**)he->h_addr_list;
	for (int i=0;addr[i]!=NULL;i++) {
		return (addr[i]->s_addr);
	}
}

int
get_tcp_stat(int fd, struct tcp_stat *ts)
{
	int error = 0;
	socklen_t ti_len = sizeof(struct tcp_info);
	struct tcp_info ti;
#if (defined(linux) || defined(__FreeBSD__) || defined(__NetBSD__)) && defined(TCP_INFO)
	error = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_len);
	if (error != 0)
		return (error);

#if defined(linux) && defined(TCP_MD5SIG)
	ts->snd_rexmitpkt = ti.tcpi_total_retrans;
#elif defined(__FreeBSD__)
	ts->snd_wscale = ti.tcpi_snd_wscale;
	ts->rcv_wscale = ti.tcpi_rcv_wscale;
	ts->rtt = ti.tcpi_rtt;
	ts->snd_cwnd = ti.tcpi_snd_cwnd;
	ts->rcv_space = ti.tcpi_rcv_space;
	ts->snd_rexmitpkt = ti.tcpi_snd_rexmitpack;
	ts->rcv_ooopkt = ti.tcpi_rcv_ooopack;
#elif defined(__NetBSD__) && defined(TCP_INFO)
	ts->snd_rexmitpkt = ti.tcpi_snd_rexmitpack;
#else
	memset(ts, 0, sizeof(struct tcp_stat));
#endif

#else
	memset(ts, 0, sizeof(struct tcp_stat));
#endif

	return (error);
}
