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
#include "socks.h"
#include "hosts.h"
#include "stats.h"
#include "app.h"
#include "plugin/plugin.h"

int socks_method_server_read(struct socks_entry *socks, struct socks_methods *pkt);
int socks_method_server_send(struct socks_entry *socks, uint8_t ver, uint8_t method);
int socks_server_request_read(struct socks_entry *socks, struct socks_req *pkt);
int socks_server_request_send(struct socks_entry *socks, uint8_t rep);
int socks_create(struct socks_entry *socks);

int
socks_server_method_read(struct socks_entry *socks, struct socks_methods *pkt)
{
	char buf[258];
	bzero(buf, 258);

	if (socks == NULL || pkt == NULL) 
		return -1;

	if (read_socket(socks->cli_fd, buf, 2) == 0) {
		return (errno);
	}
	
	if (read_socket(socks->cli_fd, &(buf[2]), buf[1]) == 0) {
		return (errno);
	}
	
	pkt->ver = buf[0];
	pkt->nmethods = buf[1];
	if (pkt->nmethods > 255 || pkt->nmethods < 1) {
		pkt->nmethods = 0;
	}
	bzero(pkt->methods, 256);
	for (int i=0;i<pkt->nmethods;i++) {
		pkt->methods[(uint8_t)buf[i+2]] = 1;
	}
	return (0);
}

int 
socks_server_method_send(struct socks_entry *socks, uint8_t ver, uint8_t method)
{
	char pld[3];

	assert(socks != NULL);
	if (socks == NULL) {
		return -1;
	}

	pld[0] = ver;
	pld[1] = method;
	
	if (write_socket(socks->cli_fd, pld, 2) == 0)
		return (errno);

	return (0);
}

int
socks_server_method_handler(struct socks_entry *socks)
{
	struct socks_methods pkt;
	uint8_t method;
	int error;

	if (socks->state != SOCKS_STATE_DISCONNECTED)
		return (1);

	DBG("METHOD - reading client..."); 
	error = socks_server_method_read(socks, &pkt);
	if (error) {
		APPERR("Failed to handshake with client.(METHOD RCV)\n");
		return 1;
	}
	
	DBG("METHOD - Checking version %u...", pkt.ver);
	if (!socks_check_version(pkt.ver, socks->worker))
		return (1);
	DBG("METHOD - Choosing method...");
	method = socks_select_method(&pkt, socks->worker);
	if (method == SOCKS_METHOD_NONE)
		return (1);

	socks->ver = pkt.ver;
	socks->method = method;
	if (method == SOCKS_METHOD_NOAUTH)
		socks->state = SOCKS_STATE_CONNECTING;
	else
		socks->state = SOCKS_STATE_AUTH;

	DBG("METHOD - Reply...");
	error = socks_server_method_send(socks, socks->ver, method);
	if (error) {
		APPERR("Failed to handshake with client.(METHOD SND errno %d)\n", error);
		return 1;
	}
	DBG("METHOD - Done.");
	return (0);
}


int 
socks_server_request_read(struct socks_entry *socks, struct socks_req *pkt)
{
	char pld[263];
	int rt;
	struct hostaddr in;
	struct hostaddr *map = NULL;

	if (socks == NULL || pkt == NULL) 
		return -1;

	if (readonce_socket(socks->cli_fd, pld, 263) == 0) {
		return (errno);
	}

	pkt->ver = pld[0];
	DBG("REQ - Checking version...");
	if (!socks_check_version(pkt->ver, socks->worker))
		return (1);

	pkt->cmd = pld[1];
	pkt->rsv = pld[2];
	pkt->atyp = pld[3];
	switch (pkt->atyp) {
	case SOCKS_ATYP_IPV6:
		if (pkt->addr != inet_ntop(AF_INET6, pld + 4, pkt->addr, 
		    sizeof(pkt->addr))) {
			APPERR("Unrecognized IPV6 address.\n");
			return (-1);
		}

		/* TODO: add hosts support */

		//pkt->port = ntohs((uint16_t)(pld[4 + 16]));
		pkt->port = *(uint16_t *)&(pld[4 + 16]);
		break;
	case SOCKS_ATYP_IPV4:
		if (pkt->addr != inet_ntop(AF_INET, pld + 4, pkt->addr, 
		    sizeof(pkt->addr))) {
			APPERR("Unrecognized IPV4 address.\n");
			return (-1);
		}

		in.type = SOCKS_ATYP_IPV4;
		in.ip_addr = inet_addr(pkt->addr);
		rt = hosts_query(&in, &map);
		if (!rt) {
			switch (map->type) {
			case SOCKS_ATYP_IPV4:
				inet_ntop(AF_INET, &map->ip_addr, pkt->addr, 256);
				break;
			case SOCKS_ATYP_IPV6:
				break;
			}
			DBG("[hosts] Address update to %s\n", pkt->addr);
		}
		//pkt->port = ntohs((uint16_t)(pld[4 + 4]));
		pkt->port = *(uint16_t *)&(pld[4 + 4]);
		break;
	case SOCKS_ATYP_DOMAINNAME:
		memcpy(pkt->addr, pld + 5, pld[4]);
		pkt->addr[(uint8_t)pld[4]] = '\0';
		//pkt->port = ntohs((uint16_t)(pld[5 + pld[4]]));
		pkt->port = *(uint16_t *)&(pld[5 + pld[4]]);
		break;
	default:
		APPERR("Unrecognized atype %u\n", pkt->atyp);
		return (-1);
	}

	pkt->port = ntohs(pkt->port);
	return (0);

}

int
socks_server_request_send(struct socks_entry *socks, uint8_t rep)
{
	char pld[263];
	int len = 6;

	if (socks == NULL) 
		return (1);

	pld[0] = socks->ver;
	pld[1] = rep;
	pld[2] = 0;
	//pld[3] = socks->atyp;
	pld[3] = 1;
	if (socks->bind_atyp == SOCKS_ATYP_DOMAINNAME) {
		pld[4] = strlen(socks->bind_addr);
		strcpy(pld + 5, socks->bind_addr);
		len += (1+pld[4]);
	} else { /* IPv4 or IPv6 address */
		//TODO
		len += 4;
		bzero(pld + 4, 4);
	}
	//pld[len] = ((htons(socks->bind_port) >> 8) & 0xff);
	//pld[len + 1] = (htons(socks->bind_port) & 0xff);
	pld[len-2] = 0;
	pld[len-1] = 0;
	pld[len] = '\0';

	if (write_socket(socks->cli_fd, pld, len) == 0)
		return (errno);

	return (0);
}

int 
socks_server_request_handler(struct socks_entry *socks)
{
    	unsigned char pld[264];
	struct socks_req pkt;
	uint8_t rep = 0;
	int error;
	if (socks->state != SOCKS_STATE_CONNECTING)
		return (1);

	bzero(pld, sizeof(pld));
	error = socks_server_request_read(socks, &pkt);
	if (error) {
		APPERR("Failed to handshake with client.(REQ RCV)\n");
		return (1);
	}

	DBG("REQ - Checking version...");
	if (!socks_check_version(pkt.ver, socks->worker))
		return (1);
	
	switch (pkt.cmd) {
	case SOCKS_CMD_CONNECT:
		DBG("REQ - connecting to %s:%u...", pkt.addr, pkt.port);

		memcpy(socks->remote_addr, pkt.addr, strlen(pkt.addr) + 1);
		socks->remote_port = pkt.port;
		socks->atyp = pkt.atyp;

		socks->fd = init_socks_socket(pkt.addr, pkt.port, pkt.atyp, &rep);
		if (socks->fd <= 0) {
			APPERR("Failed to connect on SOCKS socket.\n");
			return (1);
		}
		socks->state = SOCKS_STATE_CONNECTED;

		//TODO
		socks->bind_atyp = SOCKS_ATYP_IPV4;
		strcpy(socks->bind_addr, "0.0.0.0");
		socks->bind_port = 0;
		break;
	case SOCKS_CMD_BIND:
		break;
	case SOCKS_CMD_UDP:
		break;
	default: 
		APPERR("Failed to handshake with client.(REQ CMD %d)\n", pkt.cmd);
		return (1);
		break;
	}

	DBG("REQ - Reply... rep code %u", rep);
	error = socks_server_request_send(socks, rep);
	if (error) {
		APPERR("Failed to handskake with client.(REQ SND errno %d)\n", error);
		return 1;
	}
	return (0);
}

int
socks_check_version(uint8_t ver, struct socks_worker *worker)
{
	if (worker == NULL) 
		return (0);
	if (ver > SOCKS_VERSION_MAX)
		return (0);
	return (worker->socks_version[ver]);
}

int 
socks_select_method(struct socks_methods *pkt, struct socks_worker *worker)
{
	if (pkt == NULL || worker == NULL) 
		return (SOCKS_METHOD_NONE);
	
	//TODO
	return (SOCKS_METHOD_NOAUTH);
}

int 
socks_create(struct socks_entry *socks)
{
	int error = 0;
	int rep;
	switch (socks->state) {
	case SOCKS_STATE_DISCONNECTED:
		/* Init this SOCKS connection */
		/* Method Selection */
		DBG("METHOD packet stage.");
		error = socks_server_method_handler(socks);
		if (error) {
			return (1);
		}
		break;
	case SOCKS_STATE_AUTH:
		//TODO
		INFO("TODO: add authorization path.\n");
		return (1);
		break;
	case SOCKS_STATE_CONNECTING:
		/* Request & reply */
		DBG("REQ packet stage.");
		error = socks_server_request_handler(socks); 
		if (error) {
			APPERR("Failed to handle client request.(REQ PRS)\n");
			return (1);
		}

		socks->dst_io.socks = socks;
		socks->dst_io.socks_type = SOCKS_IO_DSTFD;
		ev_io_init(&socks->dst_io.evio, socks_read_cb, 
		    socks->fd, EV_READ);

		ev_io_start(socks->worker->loop, &socks->dst_io.evio);
		break;
	case SOCKS_STATE_CONNECTED:
		/* Connection to remote break. Reconnect */
		ev_io_stop(socks->worker->loop, &socks->dst_io.evio);
		close(socks->fd);
		socks->fd = init_socks_socket(socks->remote_addr, 
		    socks->remote_port, socks->atyp, &rep);
		if (socks->fd <= 0) {
			APPERR("Failed to connect on SOCKS socket.\n");
			return (1);
		}

		socks->dst_io.socks = socks;
		socks->dst_io.socks_type = SOCKS_IO_DSTFD;
		ev_io_init(&socks->dst_io.evio, socks_read_cb, 
		    socks->fd, EV_READ);

		ev_io_start(socks->worker->loop, &socks->dst_io.evio);
		break;
	default:
		/* Unknown state */
		DBG("Unknown socks state %d", socks->state);
		return (1);
	}

	return (0);
}

void 
socks_read_cb(EV_P_ ev_io *w, int revents)
{
	struct socks_ev_io *sei;
	struct socks_entry *socks, *tmp;
	int n, error, fd, rt, avail;
#ifdef LATENCY_DIAG
	int ts_delta;
	int bkt;
#endif
	struct timespec ts;
	struct socks_worker *worker;

	sei = (struct socks_ev_io *)w;
	socks = sei->socks;

	DBG("going to read socktype %d", sei->socks_type);
	
	switch (sei->socks_type) {
	case SOCKS_IO_CLIFD:
		worker = socks->worker;

		if (socks->state != SOCKS_STATE_CONNECTED) {
			if (socks_create(socks)) {
				//remove this socks from out list.
				DBG("Socks instance was removed due to connection err.");
				socks_clean(socks);
			}
			return;
		}

		avail = get_sock_avail_bytes(socks->cli_fd);
		avail = avail > socks->cli_buf_size ? socks->cli_buf_size: avail;
		n = readonce_socket(socks->cli_fd, socks->cli_buf, avail);
		if (n == -1) {
			APPERR("[W%d]Connection was closed by client (Err %d)(-1).\n", worker->id, errno);
			socks_clean(socks);
			return;
		}
		if (n == 0) {
			APPERR("[W%d]Connection was closed by client (Err %d)(0).\n", worker->id, errno);
			socks_clean(socks);
			return;
		}

		DBG("TRAFFIC - [W%d]Client fd %d sent %d byte(s).", worker->id, socks->cli_fd, n);
		for (int i=0;i<worker->app->n_plugins;i++)
			if (worker->app->plugins[i].enabled) 
				error = (*(worker->app->plugins[i].socks_plugin_src_packet_rx))(
				    socks, socks->cli_buf);

		if (socks->debug_size != 0) {
			if (socks->debug_size_now != socks->debug_size && socks->debug_size_now!=0) {
				printf("DEBUG - bad payload size %u, should be %u diff %d\n",
				    socks->debug_size_now,
				    socks->debug_size, socks->debug_size_now * -1);
				exit(0);
			}
			socks->debug_size_now = 0;
		}

		rt = write_socket(socks->fd, socks->cli_buf, n);
		socks->recent_ts = get_ts_us(); 
		assert(rt == n);
		break;
	case SOCKS_IO_DSTFD:
		worker = socks->worker;

#ifdef LATENCY_DIAG
#define BUCKET_UNIT 100
		if (socks->recent_ts == 0) 
			goto DIAG_DONE;
		ts_delta = get_ts_us() - socks->recent_ts;
		socks->recent_ts = 0;
		
		if (ts_delta > socks->lat_stat_max)
			socks->lat_stat_max = ts_delta;

		bkt = ts_delta / BUCKET_UNIT;
		if (bkt > 9) 
		    bkt = 9;

		socks->lat_stat[bkt]++;
		if (socks->lat_stat_count++ > 1000) {
			printf("=================\n");
			printf("Latency stat\n");
			for (int i=0;i<10;i++) {
				printf("%d-%dus: %d\n", 
					i * BUCKET_UNIT, (i+1) * BUCKET_UNIT,
					socks->lat_stat[i]);
			}
			printf("MAX: %d\n", socks->lat_stat_max);
			socks->lat_stat_count = 0;
			socks->lat_stat_max = 0;
		}
DIAG_DONE:
#endif

		avail = get_sock_avail_bytes(socks->fd);
		avail = avail > socks->dst_buf_size ? socks->dst_buf_size: avail;
		n = readonce_socket(socks->fd, socks->dst_buf, avail);
		if (n == 0) {
			APPERR("Connection was closed by remote (Err %d).\n", errno);
#if 0
			if (socks_create(socks)) {
				socks_clean(socks);
				return;
			}
#else
			socks_clean(socks);
#endif
			return;
		}
		if (n == -1) {
			DBG("TRAFFIC - Read returned errno %d.", errno);
#if 0
			if (socks_create(socks)) {
				socks_clean(socks);
				return;
			}
#else
			socks_clean(socks);
#endif
			return;
		}

		DBG("TRAFFIC - [W%d]Remote fd %d sent %d byte(s).", worker->id, socks->fd, n);
		for (int i=0;i<worker->app->n_plugins;i++)
			if (worker->app->plugins[i].enabled) 
				error = (*(worker->app->plugins[i].socks_plugin_dst_packet_rx))(
				    socks, socks->dst_buf);
		
		if (socks->debug_size != 0) {
			socks->debug_size_now += n;
		}
		DBG("Going to write");
		rt = write_socket(socks->cli_fd, socks->dst_buf, n);
		assert(rt == n);
		break;
	case SOCKS_IO_LISTENFD:
#ifndef SOCKS_MULTILISTEN
		DBG("Worker shouldn't receive event from listen fd.\n");
		exit(0);
#endif
		DBG("LISTEN - New client connection.");
		worker = (struct socks_worker *)socks;
		fd = accept_socket(worker->listen_fd);
		if (fd <= 0) {
			APPERR("Cannot accept connection.\n");
			return;
		}
	
		DBG("LISTEN - [W%d]New connection fd %d", worker->id, fd);
		socks = (struct socks_entry *)calloc(1, sizeof(struct socks_entry));
		if (!socks) {
			SYSERR(ENOMEM, 
			    "Cannot allocate enough memory for new connection.");
			close(fd);
			return;
		}
		socks->cli_fd = fd;
		socks->fd = 0;
		socks->cli_buf_size = SOCKS_CLI_BUF_SIZE;
		socks->dst_buf_size = SOCKS_DST_BUF_SIZE;
		socks->cli_buf = (char *)calloc(1, socks->cli_buf_size);
		socks->dst_buf = (char *)calloc(1, socks->dst_buf_size);
		socks->ver = SOCKS_VERSION_5;
		socks->state = SOCKS_STATE_DISCONNECTED;
		socks->worker = worker;
		socks->debug_size = worker->app->debug_size;
		socks->debug_size_now = 0;
		TAILQ_INSERT_TAIL(&(worker->socks), socks, list);

		socks->cli_io.socks = socks;
		socks->cli_io.socks_type = SOCKS_IO_CLIFD;
		ev_io_init(&socks->cli_io.evio, socks_read_cb, 
		    socks->cli_fd, EV_READ);
		ev_io_start(worker->loop, &socks->cli_io.evio);

		break;
	default:
		break;
	}
}

void 
socks_stat_cb(EV_P_ struct ev_timer* w, int revents)
{
	struct stat_ev_io * sei;
	struct socks_app * app;
	struct socks_stats * ss;
	struct tcp_stat stat;
	struct socks_entry *socks, *tmp;
	int size;
	uint32_t avg_buf_size;
	uint32_t * tmp_arr;
	int cpu_usage;
	uint64_t mbuf, mbuf_9k, mem_size;
	struct socks_worker *worker;
	int cli_usage, smg_usage, app_usage;
	int app_cpuid;
#ifdef SOMIGRATION
	int fo_fd;
#endif
	static struct rusage rlast;

	sei = (struct stat_ev_io *)w;
	app = sei->app;
	ss = &app->stats;
	
	if (app->stats_enabled)
		printf("======================\n");

	somig_stat_get_net_memory_usage(&mem_size);

	//app_cpuid = somig_stat_get_current_app_cpu();
	somig_stat_refresh_cpu_usage();
	somig_stat_get_app_cpu(&app_usage, &rlast);

	// Average the APP CPU usage. Thus we get the per-worker usage.
	app_usage = (int)(app_usage * 1.0f / app->worker_count);

	for (int i=0;i<app->worker_count;i++) {
		worker = &app->workers[i];

		TAILQ_FOREACH_SAFE(socks, &worker->socks, list, tmp) {
			stat = get_tcp_info(socks->cli_fd);
			
			if (app->stats_enabled)
			    printf("Sec %d: fd %d buf size %u\n",
				ss->seconds, socks->cli_fd, stat.smg_bufsize);

#ifdef SOMIGRATION
			fo_fd = socks->cli_fd;

			if (app->usage_fp == NULL)
				continue;
    
			cli_usage = stat.smg_clicpu;
			smg_usage = stat.smg_smgcpu;
			somig_stat_get_cpu_usage(&cli_usage, &smg_usage);
			//somig_stat_get_mbuf_usage(&mbuf, &mbuf_9k);
			mbuf = 0;
			mbuf_9k = 0;

			/* second fd cli_cpu smg_cpu app_cpu mbuf mbuf9k mem */
			fprintf(app->usage_fp, "%d,%d,%d,%d,%d,%u,%u,%u\n", 
			    ss->seconds, socks->cli_fd, cli_usage, smg_usage, app_usage, mbuf, mbuf_9k, mem_size);
#endif
		}

	}

#ifdef SOMIGRATION
	if (app->usage_fp != NULL)
		fflush(app->usage_fp);
#endif
/*
	size = sizeof(ss->arr_bufsize) / sizeof(uint32_t);
	if (ss->seconds >= size - 1) {
		tmp_arr = (uint32_t *)realloc(ss->arr_bufsize, (size + SOCKS_STATS_ALLOCATION_STEP) * sizeof(uint32_t));
		if (tmp_arr == NULL) {
			SYSERR(errno, "No memory to save stats. Stats disabled.");
			ev_timer_stop(EV_DEFAULT, w);
			return;
		}

		ss->allocated_size += SOCKS_STATS_ALLOCATION_STEP;
		ss->arr_bufsize = tmp_arr;
	}
*/
	ss->seconds++;

#ifdef SOMIGRATION
	if (app->failover > 0) {
		if (ss->seconds >= app->failover) {
			struct somig_migopt opt;

			opt.node = 1;
			opt.flag = SOMIG_MIGRATION_FLAG_FORCE_FAIL;

			if (setsockopt(fo_fd, SOL_SOCKET, SO_MIG_MIGRATE, (char *)&opt, sizeof(opt))) {
				APPERR("Failed to trigger forced failover");
			}
		}
	}
#endif

}

void
socks_clean(struct socks_entry *socks)
{
	if (socks->fd > 0) {
		DBG("Clean - closing remote fd %d", socks->fd);
		close(socks->fd);
	}
	if (socks->cli_fd > 0) {
		DBG("Clean - closing client fd %d", socks->cli_fd);
		close(socks->cli_fd);
	}

	ev_io_stop(socks->worker->loop, &socks->cli_io.evio);
	ev_io_stop(socks->worker->loop, &socks->dst_io.evio);

	TAILQ_REMOVE(&(socks->worker->socks), socks, list);
	free(socks->cli_buf);
	free(socks->dst_buf);
	free(socks);
}

