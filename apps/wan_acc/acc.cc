#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ev.h>

#include "utils.h"
#include "netutils.h"
#include "io.h"
#include "app.h"
#include "acc.h"
#include "stats.h"
#include "worker.h"

void
wanacc_new_wan_cb(EV_P_ ev_io *ws, int revents)
{
	DBG("Dummy function. Shouldn't be called");
	exit(0);
}

void
wanacc_new_stream_cb(EV_P_ ev_io *ws, int revents)
{
	struct stream_ev_io *sei;
	struct wanacc_app *app;
	struct stream_entry *stream;
	struct worker *w, *bw;
	int fd;

	sei = (struct stream_ev_io *)ws;
	app = sei->app;

	switch (sei->stream_type) {
	case STREAM_IO_LISTENFD:
		DBG("LISTEN - New client connection.");
		
		fd = accept_socket(app->listen_fd);
		if (fd <= 0) {
			APPERR("Cannot accept client connection.\n");
			return;
		}
	
		//printf("new conn %d\n", fd);
		DBG("LISTEN - New connection fd %d", fd);
		stream = (struct stream_entry *)calloc(1, sizeof(struct stream_entry));
		if (!stream) {
			SYSERR(ENOMEM, 
			    "Cannot allocate enough memory for new connection.");
			close(fd);
			return;
		}

		/* Choose next worker */
		assert(app->front_worker_next < app->front_worker_count);
		w = &app->front_workers[app->front_worker_next++];
		if (app->front_worker_next >= app->front_worker_count)
			app->front_worker_next = 0;

		bw = &app->back_workers[app->back_worker_next++];
		if (app->back_worker_next >= app->back_worker_count)
			app->back_worker_next = 0;

		stream->fd = fd;
		stream->app = app;
		TAILQ_INIT(&stream->ioq);
		stream->hash = fd;	/* TODO replace with real hash */
		stream->worker = w;
		stream->b_worker = bw;
		stream->io.stream_type = STREAM_IO_CLIFD;
		stream->io.stream = stream;
		TAILQ_INSERT_TAIL(&(app->streams), stream, list);
		
		/* Register event into worker's evloop */
		ev_io_init(&stream->io.evio, front_worker_fd_cb, stream->fd, EV_READ);
		ev_io_start(w->loop, &stream->io.evio);
		
		DBG("Client fd%d registered to worker id%d type%d loop%p",
		    fd, w->id, w->type, w->loop);
		break;
	case STREAM_IO_WANFD:
		DBG("WANFD should not receive any new connection while running");
		exit(0);
		break;
	default:
		APPERR("Wrong stream type");
		exit(0);
	}
}

void 
wanacc_stat_cb(EV_P_ ev_io *w, int revents)
{
	uint64_t mbuf, mbuf_9k, mem_size;
	struct tcp_stat stat;
	struct stream_entry *stream, *tmp;
	struct wanacc_app *app;
	int stream_count = 0;
#ifdef SOMIGRATION
	int smg_usage;
#endif
	int cli_usage, app_usage;
#ifdef PERF_PROFILING
	uint64_t front_fd_avg, back_fd_avg, back_queue_avg, in_avg, out_avg;
	uint64_t front_fd_sum, back_fd_sum, back_queue_sum, in_sum, out_sum;
	uint64_t front_fd_cnt, back_fd_cnt, back_queue_cnt, in_cnt, out_cnt;
	uint64_t dedup_cycle_avg, compz_cycle_avg;
	uint64_t dedup_cycle_sum, compz_cycle_sum;
	uint64_t dedup_cycle_cnt, compz_cycle_cnt;
#endif
	int app_cpuid;
	struct stat_ev_io *sei;
	sei = (struct stat_ev_io *)w;

	app = sei->app;

	somig_stat_get_net_memory_usage(&mem_size);

	//app_cpuid = somig_stat_get_current_app_cpu();
	somig_stat_refresh_cpu_usage();

#ifdef PERF_PROFILING
	front_fd_sum = 0;
	back_fd_sum = 0;
	back_queue_sum = 0;
	in_sum = 0;
	out_sum = 0;
	front_fd_cnt = 0;
	back_fd_cnt = 0;
	back_queue_cnt = 0;
	in_cnt = 0;
	out_cnt = 0;
	dedup_cycle_sum = 0;
	compz_cycle_sum = 0;
	dedup_cycle_cnt = 0;
	compz_cycle_cnt = 0;

	for (int i=0;i<app->front_worker_count;i++) {
		front_fd_sum += app->front_workers[i].front_fd_total;
		front_fd_cnt += app->front_workers[i].front_fd_count;
		dedup_cycle_sum += app->front_workers[i].dedup_cycle_total;
		dedup_cycle_cnt += app->front_workers[i].dedup_cycle_count;

		app->front_workers[i].front_fd_total = 0;
		app->front_workers[i].front_fd_count = 0;
		app->front_workers[i].dedup_cycle_total = 0;
		app->front_workers[i].dedup_cycle_count = 0;
	}

	for (int i=0;i<app->back_worker_count;i++) {
		back_fd_sum += app->back_workers[i].back_fd_total;
		back_fd_cnt += app->back_workers[i].back_fd_count;

		back_queue_sum += app->back_workers[i].back_queue_total;
		back_queue_cnt += app->back_workers[i].back_queue_count;

		in_sum += app->back_workers[i].in_path_total;
		in_cnt += app->back_workers[i].in_path_count;

		out_sum += app->back_workers[i].out_path_total;
		out_cnt += app->back_workers[i].out_path_count;

		compz_cycle_sum += app->back_workers[i].compz_cycle_total;
		compz_cycle_cnt += app->back_workers[i].compz_cycle_count;

		app->back_workers[i].back_fd_total = 0;
		app->back_workers[i].back_fd_count = 0;
		app->back_workers[i].back_queue_total = 0;
		app->back_workers[i].back_queue_count = 0;
		app->back_workers[i].in_path_total = 0;
		app->back_workers[i].in_path_count = 0;
		app->back_workers[i].out_path_total = 0;
		app->back_workers[i].out_path_count = 0;
		app->back_workers[i].compz_cycle_total = 0;
		app->back_workers[i].compz_cycle_count = 0;
	}

	if (front_fd_cnt == 0) front_fd_cnt = 1;
	if (back_fd_cnt == 0) back_fd_cnt = 1;
	if (back_queue_cnt == 0) back_queue_cnt = 1;
	if (in_cnt == 0) in_cnt = 1;
	if (out_cnt == 0) out_cnt = 1;
	if (dedup_cycle_cnt == 0) dedup_cycle_cnt = 1;
	if (compz_cycle_cnt == 0) compz_cycle_cnt = 1;

	front_fd_avg = front_fd_sum / front_fd_cnt;
	back_fd_avg = back_fd_sum / back_fd_cnt;
	back_queue_avg = back_queue_sum / back_queue_cnt;
	in_avg = in_sum / in_cnt;
	out_avg = out_sum / out_cnt;
	dedup_cycle_avg = dedup_cycle_sum / dedup_cycle_cnt;
	compz_cycle_avg = compz_cycle_sum / compz_cycle_cnt;
#endif

	somig_stat_get_app_cpu(&app_usage, &app->rlast);
	TAILQ_FOREACH_SAFE(stream, &(app->streams), list, tmp) {
		stream_count++;
	}
	app_usage = (int)(app_usage * 1.0 / stream_count);

	TAILQ_FOREACH_SAFE(stream, &(app->streams), list, tmp) {
		stat = get_tcp_info(stream->fd);

#ifdef SOMIGRATION
		if (app->usage_fp == NULL)
			break;

		cli_usage = stat.smg_clicpu;
		smg_usage = stat.smg_smgcpu;
		somig_stat_get_cpu_usage(&cli_usage, &smg_usage);

		//somig_stat_get_mbuf_usage(&mbuf, &mbuf_9k);
		mbuf = 0;
		mbuf_9k = 0;

#ifdef PERF_PROFILING
		fprintf(app->usage_fp, "%d,%d,%d,%d,%d,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n", 
			    app->run_time, stream->fd, 
			    cli_usage, smg_usage, app_usage, 
			    mbuf, mbuf_9k, mem_size,
			    front_fd_avg, back_fd_avg, back_queue_avg,
			    in_avg, out_avg, dedup_cycle_sum, dedup_cycle_avg, 
			    compz_cycle_sum, compz_cycle_avg);
#else
		fprintf(app->usage_fp, "%d,%d,%d,%d,%d,%u,%u,%u\n", 
			    app->run_time, stream->fd, 
			    cli_usage, smg_usage, app_usage, 
			    mbuf, mbuf_9k, mem_size);
#endif

		fflush(app->usage_fp);
#endif
	}

	app->run_time++;

#ifdef SOMIGRATION
	if (app->failover > 0) {
		if (app->run_time >= app->failover) {
			struct somig_migopt opt;

			opt.node = 1;
			opt.flag = SOMIG_MIGRATION_FLAG_FORCE_FAIL;

			stream = TAILQ_FIRST(&app->streams);
			if (setsockopt(stream->fd, SOL_SOCKET, SO_MIG_MIGRATE, (char *)&opt, sizeof(opt))) {
				APPERR("Failed to trigger forced failover");
			}
		}
	}
#endif
}

#ifdef PERF_PROFILING
void 
wanacc_perf_cb(EV_P_ ev_timer *w, int revents)
{
	struct wanacc_app *app;
	uint64_t front_fd_avg, back_fd_avg, back_queue_avg, in_avg, out_avg;
	uint64_t front_fd_sum, back_fd_sum, back_queue_sum, in_sum, out_sum;
	uint64_t front_fd_cnt, back_fd_cnt, back_queue_cnt, in_cnt, out_cnt;
	uint64_t dedup_cycle_avg, compz_cycle_avg;
	uint64_t dedup_cycle_sum, compz_cycle_sum;
	uint64_t dedup_cycle_cnt, compz_cycle_cnt;
	struct stat_ev_io *sei;
	sei = (struct stat_ev_io *)w;

	app = sei->app;

	dedup_cycle_sum = 0;
	compz_cycle_sum = 0;
	dedup_cycle_cnt = 0;
	compz_cycle_cnt = 0;
	front_fd_sum = 0;
	back_fd_sum = 0;
	back_queue_sum = 0;
	in_sum = 0;
	out_sum = 0;
	front_fd_cnt = 0;
	back_fd_cnt = 0;
	back_queue_cnt = 0;
	in_cnt = 0;
	out_cnt = 0;

	for (int i=0;i<app->front_worker_count;i++) {
		front_fd_sum += app->front_workers[i].front_fd_total;
		front_fd_cnt += app->front_workers[i].front_fd_count;
		dedup_cycle_sum += app->front_workers[i].dedup_cycle_total;
		dedup_cycle_cnt += app->front_workers[i].dedup_cycle_count;

		app->front_workers[i].front_fd_total = 0;
		app->front_workers[i].front_fd_count = 0;
		app->front_workers[i].dedup_cycle_total = 0;
		app->front_workers[i].dedup_cycle_count = 0;
	}

	for (int i=0;i<app->back_worker_count;i++) {
		back_fd_sum += app->back_workers[i].back_fd_total;
		back_fd_cnt += app->back_workers[i].back_fd_count;

		back_queue_sum += app->back_workers[i].back_queue_total;
		back_queue_cnt += app->back_workers[i].back_queue_count;

		in_sum += app->back_workers[i].in_path_total;
		in_cnt += app->back_workers[i].in_path_count;

		out_sum += app->back_workers[i].out_path_total;
		out_cnt += app->back_workers[i].out_path_count;
		
		compz_cycle_sum += app->back_workers[i].compz_cycle_total;
		compz_cycle_cnt += app->back_workers[i].compz_cycle_count;

		app->back_workers[i].back_fd_total = 0;
		app->back_workers[i].back_fd_count = 0;
		app->back_workers[i].back_queue_total = 0;
		app->back_workers[i].back_queue_count = 0;
		app->back_workers[i].in_path_total = 0;
		app->back_workers[i].in_path_count = 0;
		app->back_workers[i].out_path_total = 0;
		app->back_workers[i].out_path_count = 0;
		app->back_workers[i].compz_cycle_total = 0;
		app->back_workers[i].compz_cycle_count = 0;
	}

	if (front_fd_cnt == 0) front_fd_cnt = 1;
	if (back_fd_cnt == 0) back_fd_cnt = 1;
	if (back_queue_cnt == 0) back_queue_cnt = 1;
	if (in_cnt == 0) in_cnt = 1;
	if (out_cnt == 0) out_cnt = 1;
	if (dedup_cycle_cnt == 0) dedup_cycle_cnt = 1;
	if (compz_cycle_cnt == 0) compz_cycle_cnt = 1;

	front_fd_avg = front_fd_sum / front_fd_cnt;
	back_fd_avg = back_fd_sum / back_fd_cnt;
	back_queue_avg = back_queue_sum / back_queue_cnt;
	in_avg = in_sum / in_cnt;
	out_avg = out_sum / out_cnt;
	dedup_cycle_avg = dedup_cycle_sum / dedup_cycle_cnt;
	compz_cycle_avg = compz_cycle_sum / compz_cycle_cnt;

	printf("%u,%u,%u,%u,%u,%u,%u,%u,%u\n", front_fd_avg, back_fd_avg, \
					 back_queue_avg, in_avg, out_avg, \
					 dedup_cycle_sum, dedup_cycle_avg, \
					 compz_cycle_sum, compz_cycle_avg);

#if defined(SOMIGRATION) && defined(SMG_PROFILING)
	if (app->somig_mode == WANACC_SERVER_SMG_REPLICA) {
		struct stream_entry *se, *tmp;
		struct tcp_stat ts;
		printf("=connb==================\n");
		TAILQ_FOREACH_SAFE(se, &app->streams, list, tmp) {
			ts = get_tcp_info(se->fd);
			printf("Conn %d: %u\n", se->fd, ts.smg_bufsize);
		}
		printf("========================\n");
	}
#endif
}

#endif

void
stream_clean(struct stream_entry *stream)
{
	ev_io_stop(stream->worker->loop, &stream->io.evio);
	close(stream->fd);
	TAILQ_REMOVE(&stream->app->streams, stream, list);
	free(stream);
	printf("NOT IMPLEMENTED\n");
}
