#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <time.h>

#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"
#include "trace.h"
#include "stat.h"
#include "netutil.h"
#include "wrkwrk.h"

#define HTTP_ERROR_THRESHOLD	10

#define WRKWRK_PROXY_MODE_NONE		0
#define WRKWRK_PROXY_MODE_SOCKS		1
#define WRKWRK_PROXY_MODE_WANACC	2
#define WRKWRK_PROXY_MODE_NETLB		3

extern int APP_VERBOSE;
_Atomic int wrkwrk_status;
_Atomic int wrkwrk_conn_cnt;

static int raw_http_path_req_len;
static char raw_http_path_req[HTTP_RAW_REQ_BUFFER_SIZE];

static pthread_mutex_t thread_lock;

static int	wrkwrk_connection_init(struct connection *conn, uint32_t addr, 
    uint16_t port);
static int	wrkwrk_connection_send(struct connection *conn, char *req, int req_len);
static int	wrkwrk_connection_recv(struct connection *conn, int *recv_len);
static void	wrkwrk_clean_conn(struct connection *conn, int close_conn, int keep_req); 
static int	wrkwrk_make_request(struct connection *conn, char **req0, 
    int *req_len0, uint32_t *addr, uint16_t *port);
static void	wrkwrk_connection_callback(EV_P_ ev_io *w, int revents);


void
usage()
{
	printf("wrkwrk usage\n");
	printf("[-d time: duration]\n");
	printf("[-T threads: thread count][-c connection: connection count]\n");
	printf("[-B binding: address][-b binding: port]\n");
	printf("[-m: proxy mode][-s addr: proxy addr][-p port: proxy port]\n");
	printf("[-f path: http path]\n");
	printf("[-t path: trace file path]\n");
	printf("[-w time: warmup]\n");
	printf("[-l stat-less mode]\n");
	printf("[-r timeout(ms): request-timeout override]\n");
	printf("[-D debug_size: checks the returned size matches]\n");
}

static int 
wrkwrk_connection_init(struct connection *conn, uint32_t addr, uint16_t port) 
{
	int error = 0;

	DBG("Conn %p: Calling connect init.", conn);

	switch (conn->proxy_mode) {
	case WRKWRK_PROXY_MODE_SOCKS:
		/* 
		 * Handle socks connection issues 
		 */
		error = init_socket(&(conn->fd));
		if (error) {
			SYSERR(error, "Failed to initialize socket.");
			exit(0);
		}

		if (conn->app->bind_addr != 0 || conn->app->bind_port != 0) {
			if (bind_socket(conn->fd, conn->app->bind_addr, 
					    conn->app->bind_port) != 0) {
				SYSERR(error, "Failed to bind socket.");
				exit(0);
			}
		}

		pthread_mutex_lock(&thread_lock);
		error = init_socks(conn->fd, conn->app->proxy_addr, 
		    conn->app->proxy_port, &conn->proxy);
		atomic_fetch_add(&wrkwrk_conn_cnt, -1);
		usleep(200000);
		pthread_mutex_unlock(&thread_lock);
		if (error != 0) {
			APPERR("Cannot connect to proxy server.");
			exit(0);
		}

		error = connect_socks_ip(conn->fd, addr, port, &conn->proxy);
		if (error != 0) {
			close(conn->fd);
			conn->proxy.state = SOCKS_STATE_DISCONNECTED;
			conn->error_count++;
			return (1);
		}
		
		conn->remote_listen_addr = addr;
		conn->remote_listen_port = port;

		error = get_peerinfo(conn->fd, NULL, NULL, &conn->remote_conn_port);
		error = get_sockinfo(conn->fd, NULL, NULL, &conn->local_conn_port);
		break;
	case WRKWRK_PROXY_MODE_WANACC:
		/* 
		 * WANACC should be long connection, therefore we
		 * only connect once. 
		 */
		assert(conn->fd == -1);
		error = init_socket(&(conn->fd));
		if (error) {
			SYSERR(error, "Failed to initialize socket.");
			exit(0);
		}

		if (conn->app->bind_addr != 0 || conn->app->bind_port != 0) {
			if (bind_socket(conn->fd, conn->app->bind_addr, 
					    conn->app->bind_port) != 0) {
				SYSERR(error, "Failed to bind socket.");
				exit(0);
			}
		}

		pthread_mutex_lock(&thread_lock);
		error = connect_socket(conn->fd, 
		    conn->app->proxy_addr, conn->app->proxy_port);
		atomic_fetch_add(&wrkwrk_conn_cnt, -1);
		usleep(200000);
		pthread_mutex_unlock(&thread_lock);
		if (error) {
			DBG("Failed to connect with errno %d", errno);
			APPERR("Cannot connect to proxy server.");
			exit(0);
		}

		conn->remote_listen_addr = conn->app->proxy_addr;
		conn->remote_listen_port = conn->app->proxy_port;

		error = get_peerinfo(conn->fd, NULL, NULL,
		    &conn->remote_conn_port);
		error = get_sockinfo(conn->fd, NULL, NULL,
		    &conn->local_conn_port);
		break;
	case WRKWRK_PROXY_MODE_NETLB:
	case WRKWRK_PROXY_MODE_NONE:
		/* 
		 * Handle http connection issues
		 * Prepare socket if necessary 
		 */
		error = init_socket(&conn->fd);
		if (error) {
			SYSERR(error, "Failed to initialize socket.");
			exit(0);
		}

		if (conn->app->bind_addr != 0 || conn->app->bind_port != 0) {
			if (bind_socket(conn->fd, conn->app->bind_addr, 
					    conn->app->bind_port) != 0) {
				SYSERR(error, "Failed to bind socket.");
				exit(0);
			}
		}

		pthread_mutex_lock(&thread_lock);
		error = connect_socket(conn->fd, addr, port);
		atomic_fetch_add(&wrkwrk_conn_cnt, -1);
		if (conn->proxy_mode == WRKWRK_PROXY_MODE_NETLB)
			usleep(200000);
		pthread_mutex_unlock(&thread_lock);
		if (error) {
			DBG("Failed to connect with errno %d", errno);
			conn->w_stat->connect_error++;
			conn->error_count++;
			return (1);
		}

		error = get_peerinfo(conn->fd, NULL, NULL, 
			    &conn->remote_conn_port);
		error = get_sockinfo(conn->fd, NULL, NULL,
		    &conn->local_conn_port);

		conn->discnt = 0;
		conn->remote_listen_addr = addr;
		conn->remote_listen_port = port;
		break;
	}

	/* Add fd events */
	ev_io_init(&conn->evio, wrkwrk_connection_callback, conn->fd, EV_READ);
	ev_io_start(conn->loop, &conn->evio);

	return (0);
}

static int 
wrkwrk_connection_send(struct connection *conn, char *req, int req_len)
{
	int error = 0, len = 0;

	conn->send_time = get_time_us();
	conn->recv_time = 0;

	len = write_socket(conn->fd, req, req_len);
	if (len <= 0) {
		return (errno);
	}

	DBG("fd %d Send %d bytes at st%lu rt%lu\n", conn->fd, len, conn->send_time,
	    conn->recv_time);
	return (error);
}

static int
wrkwrk_connection_recv(struct connection *conn, int *recv_len)
{
	int error = WRKWRK_RECV_OK, left = 0, len = 0;
	int http_code;
	struct http_response_field h_field[HTTP_FIELDS_COUNT];

	/* 
	 * Read response
	 *
	 * Note that libev is level triggering therefore we could read from
	 * socket partially multiple times, and the event will be triggered as
	 * long as the socket is readable.
	 */
	if (conn->resp_buffer == NULL) {
		left = HTTP_RESP_BUFFER_SIZE - conn->received_len;
		if (conn->resp_len != 0) {
			if (left > (conn->resp_len - conn->received_len))
				left = conn->resp_len - conn->received_len;
		} else {
			left = HTTP_HEADER_MAX_LEN - conn->received_len;
			if (left <= 0) {
				return (WRKWRK_RECV_BADPACKET);
			}
		} 
		len = readonce_socket(conn->fd, conn->resp + conn->received_len, left);
	} else {
		len = readonce_socket(conn->fd, 
		    conn->resp_buffer + conn->received_len,
		    conn->resp_len - conn->received_len);
	}

	/* Record timestamp (recv) */
	if (conn->recv_time == 0) {
		conn->recv_time = get_time_us();
		if (conn->recv_time == conn->send_time) {
			static int ccc = 0;
			if (ccc++ > 1000) {
			    printf("st %lu rt%lu\n", conn->send_time, conn->recv_time);

			    assert(conn->recv_time != conn->send_time);
			}
		}
	}

	DBG("fd %d Read %d bytes(%d/%d bytes recv'd) st%lu rt%lu.", conn->fd, len,
	    conn->received_len + len, conn->resp_len, conn->send_time, conn->recv_time);

	if (len <= 0) {
		*recv_len = 0;
		return (WRKWRK_RECV_BADCONN);
	}

	conn->received_len += len;
	*recv_len = len;

	/* 
	 * Return if we either get a full response or partial response with full
	 * HTTP length section.
	 */
	if (conn->received_len <= conn->resp_len) {
		return (WRKWRK_RECV_OK);
	}

	/* TODO: run the code below if we didn't get full HTTP header */
	assert(conn->resp_len == 0);

	/* See if we can get necessary HTTP header sections */
	/* Prepare our interested response fields */
	for (int i=0;i<HTTP_FIELDS_COUNT;i++) {
		make_http_response_field(&h_field[i], HTTP_FIELDS[i]);
	}

	/* Parse response */
	http_code = parse_http_response(conn->resp, conn->received_len, h_field, HTTP_FIELDS_COUNT);
	if (http_code == HTTP_INVALID) {
		/* Assume we haven't gotten all header sections */ 
		return (WRKWRK_RECV_OK);
	}

	/* Check Content-Length field to see if we need to read more */
	if (h_field[HTTP_FIELD_CONTENT_LENGTH].status == WRKWRK_HTTP_RESP_FOUND) {
		int content_pos, content_len;

		content_len = atoi(h_field[HTTP_FIELD_CONTENT_LENGTH].value);
		/* Find http payload offset (after two CrLfs) */
		content_pos = find_http_content_offset(conn->resp, len);
		
		/* 
		 * If content_pos is 0, then means we haven't gotten a full HTTP
		 * hdr.
		 */
		if (content_pos == 0) {
			return (WRKWRK_RECV_OK);
		}

		conn->resp_len = content_len + content_pos;
		
		/* 
		 * If this response is larger than our static buffer size,
		 * we then alloc a memory region on heap.
		 */
		if ((!conn->head_request) && conn->resp_len > HTTP_RESP_BUFFER_SIZE) {
			conn->resp_buffer = (char *)malloc(conn->resp_len);
			memcpy(conn->resp_buffer, conn->resp, conn->received_len);
		}

		if (conn->head_request) {
			conn->resp_len = conn->received_len;
			conn->head_request = 0;
		}

	} else {
		/* this part might get fragmented, wait for more */
		return (WRKWRK_RECV_OK);
	}

	/* Check if we need to keep this connection alive */
	if (h_field[HTTP_FIELD_CONNECTION].status == WRKWRK_HTTP_RESP_FOUND) {
		if (strncmp_ci((char *)h_field[HTTP_FIELD_CONNECTION].value, 
		    HTTP_FIELD_CONNECTION_KEEPALIVE, 10) != 0) {
			conn->discnt = 1;
			conn->keep_alive = 0;
		} else {
			conn->discnt = 0;
			conn->keep_alive = 1;
		}
	} else {
		conn->discnt = 0;
		conn->keep_alive = 1;
	}

	return (error);
}

static void
wrkwrk_clean_conn(struct connection *conn, int close_conn, int keep_req) 
{
	DBG("Cleaning conn struct with fd termination %d", close_conn);
	if (close_conn) {
		ev_io_stop(conn->loop, &conn->evio);
		close(conn->fd);
	}

	if (conn->proxy_mode == WRKWRK_PROXY_MODE_SOCKS && close_conn) {
		conn->proxy.state = SOCKS_STATE_DISCONNECTED;
		conn->keep_alive = 0;
		conn->discnt = 0;
	}
	
	conn->send_time = 0;
	conn->recv_time = 0;

	conn->head_request = 0;
	conn->resp_len = 0;
	conn->received_len = 0;

	if (!keep_req) {
		if (conn->req)
			free(conn->req);
		conn->req = NULL;
		conn->req_len = 0;
	}

	if (conn->resp_buffer)
		free(conn->resp_buffer);
	conn->resp_buffer = NULL;
}

static int
wrkwrk_make_request(struct connection *conn, char **req0, int *req_len0,
    uint32_t *addr, uint16_t *port)
{
	int error = 0, req_len = 0, raw_req_len = 0;
	char *req = NULL;
	char raw_req[HTTP_RAW_REQ_BUFFER_SIZE];
	char *raw_req_ptr;
	
	switch (conn->app->mode) {
	case WRKWRK_MODE_TRACE_FILE:
		if (*req0)  
			free(*req0);
		*req0 = NULL;
		*req_len0 = 0;

		raw_req_len = get_trace_line(conn->trace_line, raw_req, HTTP_RAW_REQ_BUFFER_SIZE);
		if (raw_req_len == 0) {
			APPERR("Cannot parse trace line %d", conn->trace_line);
			exit(0);
		}
		DBG("Trace line %d", conn->trace_line);
		conn->trace_line++;
		if (conn->trace_line >= conn->app->trace_lines) {
			pthread_spin_lock(&(conn->w_stat->lock));
			conn->w_stat->trace_done+=1;
			pthread_spin_unlock(&(conn->w_stat->lock));
			// stop current connection.
			ev_io_stop(conn->loop, &conn->evio);
			return (0);
		}
		raw_req_ptr = raw_req;
		break;
	case WRKWRK_MODE_HTTP_PATH:
		if (*req_len0 != 0) {
			return (0);
		} 
		raw_req_ptr = raw_http_path_req;
		raw_req_len = raw_http_path_req_len;
		break;
	}

	/* Generate http request */
	req = (char *)calloc(HTTP_REQ_BUFFER_SIZE, sizeof(char));
	req_len = compose_http_get_request(conn->app->mode, raw_req_ptr, raw_req_len, 
		    req, addr, port); 
	if (req_len <= 0) {
		if (conn->app->mode == WRKWRK_MODE_HTTP_PATH) {
			APPERR("Failed to parse http path: %s\n", 
			    conn->app->http_path);
			exit(0);
		}

		DBG("Failed to parse line %d. Continuing..", conn->trace_line);
		exit(0);
		conn->w_stat->parse_error++;
		conn->error_count++;
	}

	if (req_len > 3) {
		if (strncmp_ci(req, "HEAD", 4) == 0) {
			conn->head_request = 1;
		} else
			conn->head_request = 0;
	}

	*req0 = req;
	*req_len0 = req_len;

	return (error);
}

static void 
wrkwrk_connection_callback(EV_P_ ev_io *w, int revents)
{
	int error = 0, len = 0, add_ev = 0, send_req = 0;
	int recvd_full = 0, first_resp = 0;
#ifdef LATENCY_DIAG
	int delta, bkt;
#endif
	struct connection *conn;
	
	conn = (struct connection *)w;

	/* Check global status */ 
	if (atomic_load(&wrkwrk_status) == WRKWRK_STATUS_STOPING) {
		/* Cancel all events and quit */
		ev_break(conn->loop, EVBREAK_ALL);
		DBG("Stopping all events.");
		return;
	}

	/* Recv response */
	error = wrkwrk_connection_recv(conn, &len);
	switch (error) {
	case WRKWRK_RECV_OK:
		if (len == conn->received_len && len != 0)
			first_resp = 1;
		if (conn->received_len == conn->resp_len) {
			recvd_full = 1;
			send_req = 1;
		}
		
		if (conn->app->stat != 0) {
			pthread_spin_lock(&(conn->w_stat->lock));

			/* Update stats */
			conn->w_stat->total_transfered += len;
			conn->w_stat->throughput += len;
			if (first_resp) {
				conn->w_stat->latency += (conn->recv_time - conn->send_time);
				conn->w_stat->latency_count++;
#ifdef LATENCY_DIAG
				delta = (conn->recv_time - conn->send_time);
				bkt = delta / BUCKET_UNIT;
				bkt = (bkt > 10? 10: bkt);
				conn->w_stat->lat_dist[bkt]++;
				
				if (delta > conn->w_stat->lat_max) {
					conn->w_stat->lat_max = delta;
				}
#endif
			}
			conn->fg_throughput += len;

			pthread_spin_unlock(&(conn->w_stat->lock));
		} 
		break;
	case WRKWRK_RECV_BADPACKET:
	case WRKWRK_RECV_BADCONN:
		add_ev = 1;
		conn->error_count++;
		if (conn->app->stat != 0) {
			if (error == WRKWRK_RECV_BADPACKET) { 
				conn->w_stat->parse_error++;
				DBG("Error: HTTP response issue.");
			}
			if (error == WRKWRK_RECV_BADCONN) {
				conn->w_stat->connect_error++;
				DBG("Error: connection issue.");
			}
		}
		wrkwrk_clean_conn(conn, 1, 0); 
		break;
	}

	/* Check if we need ev readd/reconn */
	if (recvd_full) {
		DBG("HTTP: %d bytes response received.", conn->received_len);
		if (conn->debug_size > 0) {
			if (conn->received_len != conn->debug_size) {
				printf("DEBUG: received len %d, should be %d\n",
				    conn->received_len, conn->debug_size);
				exit(0);
			}
		}
		if ((!conn->keep_alive) || (conn->discnt)) {
			add_ev = 1;
		}
	}

	/* Readd events */
	if (add_ev) {
conn_retry:
		error = wrkwrk_connection_init(conn, conn->addr, conn->port); 
		if (error) {
			if (++conn->error_count > HTTP_ERROR_THRESHOLD) {
				APPERR("Too many errors happened.");
				exit(0);
			}
			goto conn_retry;
		}
		DBG("(Re)adding events for fd %d.", conn->fd);
		send_req = 1;
	}

	if (!send_req)
		return;

	/* Prepare request packet */
make_request:
	error = wrkwrk_make_request(conn, &conn->req, &conn->req_len, 
	    &conn->addr, &conn->port);
	if (error) {
		if (++conn->error_count > HTTP_ERROR_THRESHOLD) {
			APPERR("Too many errors happened.");
			exit(0);
		}
		goto make_request;
	}

	wrkwrk_clean_conn(conn, 0, 1); 

	/* Send req if necessary */
send_request:
	error = wrkwrk_connection_send(conn, conn->req, conn->req_len);
	if (error) {
		if (++conn->error_count > HTTP_ERROR_THRESHOLD) {
			APPERR("Too many errors happened.");
			exit(0);
		}
		goto send_request;
	}

	//pthread_spin_lock(&(conn->w_stat->lock));

	/* Update stats */
	//conn->w_stat->total_request++;
	//conn->w_stat->request++;

	//pthread_spin_unlock(&(conn->w_stat->lock));
}

void 
wrkwrk_interval_callback(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct wrkwrk_wio *wio;
	uint64_t time_now, time_diff;
	struct connection *conn;
	int error;

	if (atomic_load(&wrkwrk_status) == WRKWRK_STATUS_STOPING) {
		/* Cancel all events and quit */
		ev_break(loop, EVBREAK_ALL);
		DBG("Stopping all events.");
	} 

	wio = (struct wrkwrk_wio *)w;
	time_now = get_time_us();

	/* Iterate on all conns to see if we have any expired req */
	for (int i=0;i<wio->conn_cnt;i++) {
		conn = &wio->conn[i];

		if (likely(conn->recv_time != 0 || conn->send_time == 0))
			continue;
		time_diff = (time_now - conn->send_time) / 1000;
		if (time_diff > conn->app->req_timeout && conn->received_len == 0) {
			printf("fd %d timedout, diff %lu\n", conn->fd, time_diff);
			// Resend request
			error = wrkwrk_make_request(conn, &conn->req, &conn->req_len, 
			    &conn->addr, &conn->port);
			if (error)
				continue;
			wrkwrk_clean_conn(conn, 1, 1);
			error = wrkwrk_connection_init(conn, conn->addr, conn->port);
			if (error)
				continue;
			error = wrkwrk_connection_send(conn, conn->req, conn->req_len);
		}
	}
}

void *
wrkwrk(void *in) 
{
	int error;
	struct connection * conn;
	struct ev_loop *loop;

	struct wrkwrk_wio wio;
	struct wrkwrk_stat *w_stat;
	struct wrkwrk *app;
	
	app = ((struct thread_arg *)in)->app;

	if (app->connection > WRKWRK_MAX_CONNECTION) {
		APPERR("Connection number %d is over the limit %d.", 
		    app->connection, WRKWRK_MAX_CONNECTION);
		exit(0);
	}

	w_stat = ((struct thread_arg *)in)->w_stat;
	loop = ev_loop_new(0);

	conn = calloc(app->connection, sizeof(struct connection));
	w_stat->conns = conn;

	for (int i=0;i<app->connection;i++) {
		conn[i].fd = -1;		
		conn[i].proxy_mode = app->proxy;
		conn[i].app = app;
		conn[i].w_stat = w_stat;
		conn[i].loop = loop;
		conn[i].proxy.ver = SOCKS_VERSION;
		conn[i].proxy.state = SOCKS_STATE_DISCONNECTED;
		conn[i].proxy.method = 0xff;
		conn[i].resp_buffer = NULL;
		conn[i].fg_throughput = 0;
		conn[i].req = NULL;
		conn[i].req_len = 0;
		conn[i].debug_size = app->debug_size;

		error = wrkwrk_make_request(&conn[i], &conn[i].req, &conn[i].req_len, 
			    &conn[i].addr, &conn[i].port);
		if (error) {
			APPERR("Failed to make init request.\n");
			exit(0);
		}
		wrkwrk_connection_init(&conn[i], conn->addr, conn->port);
	}

	while (atomic_load(&wrkwrk_status) == WRKWRK_STATUS_READY) {
		
	}

	wio.conn = conn;
	wio.conn_cnt = app->connection; 

	ev_timer_init(&(wio.wio.tmout_w), &wrkwrk_interval_callback, 0.5, 1);
        ev_timer_start(loop, &(wio.wio.tmout_w));

	/* Send the first req */
	for (int i=0;i<app->connection;i++) {
		assert(conn[i].req != NULL);
		assert(conn[i].req_len > 0);

		error = wrkwrk_connection_send(&conn[i], conn[i].req, conn[i].req_len);
		if (error) {
			APPERR("Failed to send init request.\n");
			exit(0);
		}
	}

	ev_run(loop, 0);
	ev_loop_destroy(loop);

	free(conn);
	return (NULL);
}

int
main(int argc, char * argv[])
{
	int rt = 0, rt_stat = 0, ch, error;
	pthread_t * thr;
	pthread_t thr_stat;
	struct wrkwrk app;
	struct wrkwrk_stat *w_stat;
	struct thread_arg *t_arg;
	struct stat_arg s_arg;
	
	app.bind_addr = 0;
	app.bind_port = 0;
	app.proxy = 0;
	app.duration = 0;
	app.connection = 1;
	app.threads = 1;
	app.warmup = 1;
	app.fg_stat = 0;
	app.stat = 1;
	app.debug_size = 0;
	app.req_timeout = WRKWRK_REQ_TIMEOUT;
	while ((ch = getopt(argc, argv, "lt:f:d:s:p:B:b:T:m:c:r:w:PD:hv?")) != -1) {
		switch (ch) {
		case 'T':
			app.threads = atoi(optarg);
			break;
		case 't':	/* http trace file for replay */
			app.trace_file = strdup(optarg);
			app.mode = WRKWRK_MODE_TRACE_FILE;
			break;
		case 'f':	/* http path */
			app.http_path = strdup(optarg);
			app.mode = WRKWRK_MODE_HTTP_PATH;
			break;
		case 'd':	/* duration */
			app.duration = atoi(optarg);
			break;
		case 'v':
			app.verbose = 1;
			APP_VERBOSE = 1;
			break;
		case 's':
			app.proxy_addr = (uint32_t)inet_addr(optarg);
			break;
		case 'p':
			app.proxy_port = htons(atoi(optarg));
			break;
		case 'm':
			if (strcmp("socks", optarg) == 0) {
				app.proxy = WRKWRK_PROXY_MODE_SOCKS;
			} else if (strcmp("wanacc", optarg) == 0) {
				app.proxy = WRKWRK_PROXY_MODE_WANACC;
			} else if (strcmp("netlb", optarg) == 0) {
				app.proxy = WRKWRK_PROXY_MODE_NETLB;
			} else {
				app.proxy = WRKWRK_PROXY_MODE_NONE;
			}
			break;
		case 'B':
			app.bind_addr = (uint32_t)inet_addr(optarg);
			break;
		case 'b':
			app.bind_port = htons(atoi(optarg));
			break;
		case 'c':
			app.connection = atoi(optarg);
			break;
		case 'w':
			app.warmup = atoi(optarg);
			break;
		case 'P':
			app.fg_stat = 1;
			break;
		case 'l':
			app.stat = 0;
			break;
		case 'r':
			app.req_timeout = atof(optarg);
			break;
		case 'D':
			app.debug_size = atoi(optarg);
			break;
		case 'h':
		case '?':
		default:
			usage();
			exit(0);
		}
	}

	if (app.duration <= 0) {
		APPERR("Test duration must be greater than 0");
		exit(0);
	}

	if (app.proxy != WRKWRK_PROXY_MODE_NONE) {
		if (app.proxy_port == 0) {
			APPERR("Please specify proxy address and port.");
			exit(0);
		}
	}

	if (app.connection < 1) {
		APPERR("Connection has to be greater than 0");
		exit(0);
	}

	if (pthread_mutex_init(&thread_lock, NULL) != 0) {
		APPERR("Failed to initialize mutex.");
		exit(0);
	}

#ifdef TSC_CLOCK
	/* Init precise tsc clock */
	error = init_tsc();
	if (error) {
		INFO("tsc freq not found. Using clock_gettime for latency measurement.\n");
	}
#endif
	
	/* Allocate stat structures needed */
	w_stat = calloc(app.threads, sizeof(struct wrkwrk_stat)); 
	/* Thread structures */ 
	thr = calloc(app.threads, sizeof(pthread_t));
	/* targs */
	t_arg = calloc(app.threads, sizeof(struct thread_arg));
	/* sarg */
	s_arg.thread = app.threads;
	s_arg.app = &app;
	s_arg.w_stat = w_stat;

	/* Copy http path into buffer */
	if (app.mode == WRKWRK_MODE_HTTP_PATH) {
		raw_http_path_req_len = strlen(app.http_path);
		memcpy(raw_http_path_req, app.http_path, raw_http_path_req_len);
		raw_http_path_req[raw_http_path_req_len] = '\0';
	}

	/* Init trace file */
	if (app.mode == WRKWRK_MODE_TRACE_FILE) {
		INFO("Loading trace file..\n");
		app.trace_lines = init_trace_file(app.trace_file);
		if (app.trace_lines == 0) {
			APPERR("Empty trace file.");
			exit(0);
		}
		INFO("Loaded %d traces.\n", app.trace_lines);
	}

	atomic_init(&wrkwrk_status, WRKWRK_STATUS_READY);
	atomic_init(&wrkwrk_conn_cnt, app.connection * app.threads);

	DBG("Starting main thread(s)..");
	for (int i=0;i<app.threads;i++) {
		init_wrkwrk_stat(&(w_stat[i]), app.duration); 
		t_arg[i].id = i;
		t_arg[i].app = &app;
		t_arg[i].w_stat = &w_stat[i]; 
		rt = pthread_create(&(thr[i]), NULL, wrkwrk, (void *)&(t_arg[i]));
		DBG("Thread %d started.", i);
		sleep(1);
	}

	while (atomic_load(&wrkwrk_conn_cnt) != 0) {
	}
	atomic_store(&wrkwrk_status, WRKWRK_STATUS_RUNNING);
	/* TODO wake up all */
	
	rt_stat = pthread_create(&thr_stat, NULL, wrkwrk_stat, (void *)&s_arg);
	pthread_join(thr_stat, NULL);

	for (int i=0;i<app.threads;i++) {
		pthread_join(thr[i], NULL);
		free_wrkwrk_stat(&w_stat[i]);
	}

	free(w_stat);
	free(t_arg);
	free(thr);
	pthread_mutex_destroy(&thread_lock);

	if (app.mode == WRKWRK_MODE_TRACE_FILE)
		free_trace_file();

	return 0;
}
