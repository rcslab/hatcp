#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/timespec.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ev.h>

#include "utils.h"
#include "netutils.h"
#include "netlb.h"
#include "app.h"
#include "plugin/plugin.h"



void 
netload_read_cb(EV_P_ ev_io *w, int revents)
{
	struct netlb_ev_io *nei;
	struct netload_entry *netload, *tmp;
	int n, error, fd, rt, avail;
	struct netlb_worker *worker;

	nei = (struct netlb_ev_io *)w;
	netload = nei->netload;

	DBG("going to read netload type %d", nei->netload_type);
	
	switch (nei->netload_type) {
	case NETLOAD_IO_CLIFD:
		worker = netload->worker;

		avail = get_socket_avail_bytes(netload->cli_fd);
		avail = avail > netload->cli_buf_size ? netload->cli_buf_size: avail;
		n = readonce_socket(netload->cli_fd, netload->cli_buf, avail);
		if (n == -1) {
			APPERR("[W%d]Connection was closed by client (Err %d)(-1).\n", worker->id, errno);
			netload_clean(netload);
			return;
		}
		if (n == 0) {
			APPERR("[W%d]Connection was closed by client (Err %d)(0).\n", worker->id, errno);
			netload_clean(netload);
			return;
		}

		DBG("TRAFFIC - [W%d]Client fd %d sent %d byte(s).", worker->id, netload->cli_fd, n);
		for (int i=0;i<worker->app->n_plugins;i++) {
			if (worker->app->plugins[i].enabled) 
				error = (*(worker->app->plugins[i].netlb_plugin_src_packet_rx))(
				    netload, netload->cli_buf);
		}

		rt = write_socket(netload->fd, netload->cli_buf, n);
		assert(rt == n);
		break;
	case NETLOAD_IO_DSTFD:
		worker = netload->worker;

		avail = get_socket_avail_bytes(netload->fd);
		avail = avail > netload->dst_buf_size ? netload->dst_buf_size: avail;
		n = readonce_socket(netload->fd, netload->dst_buf, avail);
		if (n == 0) {
			APPERR("Connection was closed by remote (Err %d).\n", errno);
			netload_clean(netload);
			return;
		}
		if (n == -1) {
			DBG("TRAFFIC - Read returned errno %d.", errno);
			netload_clean(netload);
			return;
		}

		DBG("TRAFFIC - [W%d]Remote fd %d sent %d byte(s).", worker->id, netload->fd, n);
		for (int i=0;i<worker->app->n_plugins;i++)
			if (worker->app->plugins[i].enabled) 
				error = (*(worker->app->plugins[i].netlb_plugin_dst_packet_rx))(
				    netload, netload->dst_buf);
		
		DBG("Going to write");
		rt = write_socket(netload->cli_fd, netload->dst_buf, n);
		assert(rt == n);
		break;
	case NETLOAD_IO_LISTENFD:
#ifndef NETLB_MULTILISTEN
		DBG("Worker shouldn't receive event from listen fd.\n");
		exit(0);
#endif
		DBG("LISTEN - New client connection.");
		worker = (struct netlb_worker *)netload;
		fd = accept_socket(worker->listen_fd);
		if (fd <= 0) {
			APPERR("Cannot accept connection.\n");
			return;
		}
	
		DBG("LISTEN - [W%d]New connection fd %d", worker->id, fd);

		error = netload_new_client_connection(worker, fd, NULL);
		if (error)
			SYSERR(error, "Cannot accept new client connection.");

		break;
	default:
		break;
	}
}

int
netload_new_client_connection(struct netlb_worker *worker, int fd, struct netload_entry **nl)
{
	int error;
	struct netlb_app *app;
	struct netload_entry *netload;

	app = worker->app;

	netload = (struct netload_entry *)calloc(1, sizeof(struct netload_entry));
	if (!netload) {
		SYSERR(ENOMEM, 
		    "Cannot allocate enough memory for new connection.");
		close(fd);
		return ENOMEM;
	}

	error = create_socket(&netload->fd);
	if (error) {
		SYSERR(error, "Cannot create socket for backend server connection.");
		close(fd);
		free(netload);
		return error;
	}

	if (connect_socket(netload->fd, app->dst_addr, app->dst_port) < 0) {
		SYSERR(errno, "Cannot establish connection to backend server.");
		close(netload->fd);
		close(fd);
		free(netload);
		return error;
	}
	
	netload->cli_fd = fd;
	netload->cli_buf_size = NETLOAD_CLI_BUF_SIZE;
	netload->dst_buf_size = NETLOAD_DST_BUF_SIZE;
	netload->cli_buf = (char *)calloc(1, netload->cli_buf_size);
	netload->dst_buf = (char *)calloc(1, netload->dst_buf_size);
	netload->worker = worker;

	TAILQ_INSERT_TAIL(&(worker->netloads), netload, list);

	netload->cli_io.netload = netload;
	netload->cli_io.netload_type = NETLOAD_IO_CLIFD;
	ev_io_init(&netload->cli_io.evio, netload_read_cb, netload->cli_fd, EV_READ);
	ev_io_start(worker->loop, &netload->cli_io.evio);

	netload->dst_io.netload = netload;
	netload->dst_io.netload_type = NETLOAD_IO_DSTFD;
	ev_io_init(&netload->dst_io.evio, netload_read_cb, netload->fd, EV_READ);
	ev_io_start(worker->loop, &netload->dst_io.evio);

	if (nl) {
		*nl = netload;
	}

	return (0);
}


void
netload_clean(struct netload_entry *netload)
{
	if (netload->fd > 0) {
		DBG("Clean - closing remote fd %d", netload->fd);
		close(netload->fd);
	}
	if (netload->cli_fd > 0) {
		DBG("Clean - closing client fd %d", netload->cli_fd);
		close(netload->cli_fd);
	}

	ev_io_stop(netload->worker->loop, &netload->cli_io.evio);
	ev_io_stop(netload->worker->loop, &netload->dst_io.evio);

	TAILQ_REMOVE(&(netload->worker->netloads), netload, list);
	free(netload->cli_buf);
	free(netload->dst_buf);
	free(netload);
}

