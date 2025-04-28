#ifndef SOCKS_H_
#define SOCKS_H_

#include "plugin/plugin.h"

#define SOCKS_STATE_DISCONNECTED	0
#define SOCKS_STATE_AUTH		1
#define SOCKS_STATE_CONNECTING		2
#define SOCKS_STATE_CONNECTED		3

#define SOCKS_CMD_CONNECT		0x01
#define SOCKS_CMD_BIND			0x02
#define SOCKS_CMD_UDP			0x03

#define SOCKS_VERSION_COUNT		(5) +1
#define SOCKS_VERSION_4 0x4
#define SOCKS_VERSION_5 0x5
#define SOCKS_VERSION_MAX SOCKS_VERSION_5
static const int SOCKS_SUPPORTED_VERSION[SOCKS_VERSION_COUNT] = {
	0,
	0,
	0,
	0,
	1,
	1
};

#define SOCKS_METHOD_NOAUTH		0x00
#define SOCKS_METHOD_GSSAPI		0x01
#define SOCKS_METHOD_USRPWD		0x02
#define SOCKS_METHOD_IANA_RNG_LO	0x03
#define SOCKS_METHOD_IANA_RNG_HI	0x7f
#define SOCKS_METHOD_NONE		0xff

#define SOCKS_ATYP_IPV4			0x1
#define SOCKS_ATYP_IPV6			0x4
#define SOCKS_ATYP_DOMAINNAME		0x3

#define SOCKS_IO_CLIFD			0
#define SOCKS_IO_DSTFD			1
#define SOCKS_IO_LISTENFD		2

#define SOCKS_CLI_BUF_SIZE		1024 * 1024
#define SOCKS_DST_BUF_SIZE		1024 * 1024

struct socks_ev_io {
	ev_io evio;
	int socks_type;
	union {
		struct socks_entry *socks;
		struct socks_worker *worker;
	};
};

struct stat_ev_io {
	ev_timer tmout_w;
	struct socks_app *app;
};


struct socks_entry {
	struct socks_ev_io cli_io;
	struct socks_ev_io dst_io;
	int		fd;		/* To dest */
	int		cli_fd;		/* To client */
	char	       *cli_buf;
	char	       *dst_buf;
	int		cli_buf_size;
	int		dst_buf_size;
	uint64_t	recent_ts;
	int		debug_size;
	int		debug_size_now;
	int		state;
	uint8_t		ver;
	uint8_t		method;
	uint8_t		atyp;
	uint8_t		bind_atyp;
	char		remote_addr[256];
	uint16_t	remote_port;
	char		bind_addr[256];
	uint16_t	bind_port;
	int		lat_stat[10];
	int		lat_stat_count;
	int		lat_stat_max;
	struct socks_worker *worker;

	TAILQ_ENTRY(socks_entry) list;
};

struct socks_methods {
	uint8_t		ver;
	union {
		uint8_t nmethods;
		uint8_t method;
	};
	uint8_t		methods[256];
};

/* Ip & ports are using HBO */
struct socks_req {
	uint8_t		ver;
	uint8_t		cmd;
	uint8_t		rsv;
	uint8_t		atyp;
	char		addr[256];
	uint16_t	port;
};

struct socks_resp {
	uint8_t		ver;
	uint8_t		rep;
	uint8_t		rsv;
	uint8_t		atyp;
	char		addr[256];
	uint16_t	port;
};

int socks_server_method_handler(struct socks_entry *socks);
int socks_server_request_handler(struct socks_entry *socks);

int socks_check_version(uint8_t ver, struct socks_worker *worker);
int socks_select_method(struct socks_methods *pkt, struct socks_worker *worker);

void socks_read_cb(EV_P_ ev_io *w, int revents);
void socks_stat_cb(EV_P_ struct ev_timer* w, int revents);
void socks_clean(struct socks_entry *socks);

#endif	
