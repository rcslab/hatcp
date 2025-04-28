#ifndef NETUTILS_H_
#define NETUTILS_H_

struct tcp_stat {
	uint8_t tcp_state;
	uint32_t rtt;
	uint32_t rtt_var;
	uint32_t ss_thres;
	uint32_t snd_cwnd;
	uint32_t rcv_space;
	uint32_t snd_rexmitpkt;
	uint32_t rcv_ooopkt;

	uint32_t smg_bufsize;
	uint32_t smg_bufsize_cso;
	uint32_t smg_clicpu;
	uint32_t smg_smgcpu;
};

#define SERVER_SMG_PRIMARY  3
#define SERVER_SMG_REPLICA  1

int init_socket(int *);
int init_socket_ppd(int *, uint32_t, uint16_t, int, uint32_t, uint16_t, 
    uint32_t, uint16_t);
int accept_socket(int);
void listen_socket(int);
int bind_socket(int, uint32_t, uint16_t);
int connect_socket(int, uint32_t, uint16_t);
int read_socket(int fd, char *buf, size_t count);
int readonce_socket(int fd, char *buf, size_t count);
int write_socket(int fd, const char *buf, size_t count);
int get_sockinfo(int fd, int *type, uint32_t *addr, uint16_t *port);

int init_primary(int, uint32_t, uint16_t, uint32_t, uint16_t);
int init_replica(int, uint32_t, uint16_t, uint32_t, uint16_t, uint32_t, uint16_t);

struct tcp_stat get_tcp_info(int fd);

#endif
