#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>

#include "utils.h"
#include "netutil.h"
#include "socks.h"


#define SOCKS_NMETHODS		1
#define SOCKS_CMD_CONNECT	1

#define SOCKS_ATYP_IP4		1
#define SOCKS_ATYP_DOMAINNAME	3
#define SOCKS_ATYP_IP6		4

const uint8_t socks_methods[] = {
		0	/* No authentication required */
};

static int compose_socks_methods_selection(char * out);
static int compose_socks_request(int atyp, char * addr, int addr_len, char * port, char *out);
static int parse_socks_response(char * resp, int len, struct socks *s);

int 
init_socks(int fd, uint32_t addr, uint16_t port, struct socks *s)
{
	char buf[260];
	int len, len_buf, error;

	s->method = 0xff; 

	error = connect_socket(fd, addr, port);
	if (error) {
		DBG("Failed to connect proxy with errno %d", errno);
		return (errno);
	}
	
	len_buf = compose_socks_methods_selection(buf);
	len = write_socket(fd, buf, len_buf);

	len = read_socket(fd, buf, 2);
	for (int i=0;i<SOCKS_NMETHODS;i++) {
		if (socks_methods[i] == buf[1]) {
			s->method = buf[1];
			break;
		}
	}

	s->state = SOCKS_STATE_CONNECTING;

	return (0);
}

int
connect_socks_ip(int fd, uint32_t addr, uint16_t port, struct socks *s)
{
	int len, w_len, error;
	char addr_buf[5];
	char port_buf[2];
	char buf[1024];

	if (s->state != SOCKS_STATE_CONNECTING) {
		return (-1);
	}

	port_buf[0] = (port) & 0xff;
	port_buf[1] = (port >> 8) & 0xff;

	/* TODO: IPv6 support */
	addr_buf[0] = (addr) & 0xff;
	addr_buf[1] = (addr >> 8) & 0xff;
	addr_buf[2] = (addr >> 16) & 0xff;
	addr_buf[3] = (addr >> 24) & 0xff;
	addr_buf[4] = '\0';

	len = compose_socks_request(SOCKS_ATYP_IP4, addr_buf, 4, port_buf, buf);
	if (len <= 0) {
		DBG("Failed to compose socks request.");
		return (-1);
	}

	w_len = write_socket(fd, buf, len);

	len = readonce_socket(fd, buf, 1024);
	if (len <= 0) {
		close(fd);
		return (-2);
	}

	error = parse_socks_response(buf, len, s);
	if (error != 0) {
		close(fd);
		return (-2);
	}

	return (0);
}

static int 
compose_socks_methods_selection(char * out)
{
	int len = 2;

	out[0] = SOCKS_VERSION;
	out[1] = SOCKS_NMETHODS;
	for (int i=0;i<SOCKS_NMETHODS;i++) {
		out[2+i] = socks_methods[i];
		len++;
	}
	
	return len;
}

static int 
compose_socks_request(int atyp, char * addr, int addr_len, char * port, char *out)
{
	int len = 0, buf_len = 0;

	out[0] = SOCKS_VERSION;
	out[1] = SOCKS_CMD_CONNECT;
	out[2] = 0;
	out[3] = atyp;

	len = addr_len;
	memcpy(out + 4, addr, len);
	
	len += 4;
	out[len++] = port[0];
	out[len++] = port[1];

	return (len);
}


static int 
parse_socks_response(char * resp, int len, struct socks *s)
{
	int ver, rep;

	ver = resp[0];
	if (ver != SOCKS_VERSION) {
		return (1);
	}

	rep = resp[1];
	if (rep != 0) {
		return (1);
	}

	s->state = SOCKS_STATE_CONNECTED;
	return (0);
}
