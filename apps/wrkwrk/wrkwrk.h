#ifndef WRKWRK_H_
#define WRKWRK_H_

#define WRKWRK_MODE_HTTP_PATH	0
#define WRKWRK_MODE_TRACE_FILE	1

#define WRKWRK_STATUS_READY	0
#define WRKWRK_STATUS_RUNNING	1
#define WRKWRK_STATUS_STOPING	2

#define WRKWRK_MAX_CONNECTION	1024

#define HTTP_RAW_REQ_BUFFER_SIZE    32768
#define HTTP_REQ_BUFFER_SIZE    65536
//#define HTTP_RESP_BUFFER_SIZE	65536
#define HTTP_RESP_BUFFER_SIZE	1048691

#define WRKWRK_RECV_OK		0
#define WRKWRK_RECV_BADPACKET	10
#define WRKWRK_RECV_BADCONN	11

#define WRKWRK_REQ_TIMEOUT	10000 //ms

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

#include <ev.h>

#include "socks.h"
#include "http.h"
#include "stat.h"

struct wrkwrk {
	uint32_t proxy_addr;
	uint16_t proxy_port;
	uint32_t bind_addr;
	uint16_t bind_port;
	int proxy;
	int mode;
	int connection;
	int trace_lines;
	char * trace_file;
	char * http_path;
	int duration;
	int threads;
	int verbose;
	int warmup;
	double req_timeout;
	int stat;
	int fg_stat;
	int debug_size;
};

struct thread_arg {
	int id;
	struct wrkwrk *app;
	struct wrkwrk_stat *w_stat;
};

struct stat_arg {
	int thread;
	struct wrkwrk *app;
	struct wrkwrk_stat *w_stat;
};

struct wrkwrk_wio {
	struct ws_ev_io wio;
	struct connection *conn;
	int conn_cnt;
};

struct connection {
	ev_io evio;
	int fd;
	int proxy_mode;
	struct socks proxy;
	int trace_line;
	int keep_alive;
	int discnt;
	int error_count;
	uint64_t send_time, recv_time;
	struct wrkwrk *app;
	struct wrkwrk_stat *w_stat;
	struct ev_loop *loop;

	uint32_t remote_listen_addr;
	uint16_t remote_listen_port;
	uint16_t remote_conn_port;
	uint16_t local_conn_port;

	int head_request;
	int resp_len;
	int received_len;
	int debug_size;

	int fg_throughput;
	/* Used for smaller packet to prevent frequent malloc */
	char resp[HTTP_RESP_BUFFER_SIZE];
	char *resp_buffer;

	char *req;
	int req_len;
	uint32_t addr;	//addr for this req
	uint16_t port;	//port for this req
};

extern _Atomic int wrkwrk_status;
extern _Atomic int wrkwrk_conn_cnt;


#endif
