#ifndef NETUTILS_H_
#define NETUTILS_H_

struct tcp_stat {
	u_int8_t snd_wscale:4,	/* RFC1323 send shift value. */
		 rcv_wscale:4;	/* RFC1323 recv shift value. */
	uint32_t rtt;
	uint32_t snd_cwnd;
	uint32_t rcv_space;
	uint32_t snd_rexmitpkt;
	uint32_t rcv_ooopkt;

	uint32_t smg_bufsize;
	uint32_t smg_bufsize_cso;
	uint32_t smg_cpuid;
};

int init_socket(int *);
int bind_socket(int, uint32_t, uint16_t);
int connect_socket(int, uint32_t, uint16_t);
int read_socket(int fd, char *buf, size_t count);
int readonce_socket(int fd, char *buf, size_t count);
int write_socket(int fd, const char *buf, size_t count);
int get_sockinfo(int fd, int *type, uint32_t *addr, uint16_t *port);
int get_peerinfo(int fd, int *type, uint32_t *addr, uint16_t *port);
uint32_t get_ip_from_hostname(const char* hostname);
int get_tcp_stat(int fd, struct tcp_stat *ts);
#endif
