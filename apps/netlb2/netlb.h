#ifndef NETLB_H_
#define NETLB_H_

#include "plugin/plugin.h"

#define NETLB_STATE_DEST_DISCONNECTED	0
#define NETLB_STATE_DEST_CONNECTED	1

#define NETLOAD_IO_CLIFD			0
#define NETLOAD_IO_DSTFD			1
#define NETLOAD_IO_LISTENFD		2

#define NETLOAD_CLI_BUF_SIZE		1024 * 1024
#define NETLOAD_DST_BUF_SIZE		1024 * 1024

struct netlb_ev_io {
	ev_io evio;
	int netload_type;
	union {
		struct netload_entry *netload;
		struct netlb_worker *worker;
	};
};

struct netload_entry {
	struct netlb_ev_io cli_io;
	struct netlb_ev_io dst_io;
	int		fd;		/* To dest */
	int		cli_fd;		/* To client */
	char	       *cli_buf;
	char	       *dst_buf;
	int		cli_buf_size;
	int		dst_buf_size;
	uint32_t	remote_addr;
	uint16_t	remote_port;
	struct netlb_worker *worker;

	TAILQ_ENTRY(netload_entry) list;
};

void netload_read_cb(EV_P_ ev_io *w, int revents);
void netload_clean(struct netload_entry *netload);


#endif
