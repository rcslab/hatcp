#ifndef SOCKS_H_
#define SOCKS_H_

#define SOCKS_VERSION		5
#define SOCKS_DEFAULT_PORT	htons(1080)

#define SOCKS_STATE_DISCONNECTED	0
#define SOCKS_STATE_AUTH		1
#define SOCKS_STATE_CONNECTING		2
#define SOCKS_STATE_CONNECTED		3

struct socks {
	int state;
	int ver;
	int method;
};

int init_socks(int fd, uint32_t addr, uint16_t port, struct socks *s);
int connect_socks_ip(int fd, uint32_t addr, uint16_t port, struct socks *s);



#endif 
