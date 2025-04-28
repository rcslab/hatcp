#ifndef WORKER_H_
#define WORKER_H_

#include <sys/queue.h>

#include <ev.h>

#include "acc/chunk.h"

#include "app.h"

/*
 *		    MiddleServer		    EndServer
 * Front worker: [ cli_rx + dedup ]		[ rem_rx + dedup ]
 *
 * Back worker:  [ cmpz + wan_es_tx ]		[ cmpz + wan_ms_tx ]
 *		 [ wan_es_rx + decmpz + cli_tx]	[ wan_ms_rx + decmpz + rem_tx ]
 */

#define WANACC_WORKER_FRONT	1
#define WANACC_WORKER_BACK	2

#define WANACC_WORKER_MAX	32 

TAILQ_HEAD(data_queue, data_entry);

struct data_entry {
	int len;

	uint32_t flag;
#ifdef PERF_PROFILING
	uint64_t ts;
#endif

	struct stream_entry *stream;
	struct chunk *data;

	TAILQ_ENTRY(data_entry) list;
};

struct worker {
	int id;
	int type;

	struct stream_entry *wan_stream;
	int stream_count;

	struct ev_loop *loop;
	struct wanacc_app *app;

	/* Only used for front worker */
	int next_back_worker;

	/* Only used for back worker */
	struct queue_ev_io ev_queue;
	struct io_buffer_queue	ioq;	/* Lock free, modified only by curr worker thread */
	struct data_queue dtq;	/* Guarded by dtq_mtx */
	pthread_mutex_t dtq_mtx;

	struct hashtable ht;

#ifdef PERF_PROFILING
	uint64_t front_fd_total;
	uint64_t front_fd_count;

	uint64_t back_fd_total;
	uint64_t back_fd_count;

	uint64_t back_queue_total;
	uint64_t back_queue_count;

	uint64_t in_path_total;
	uint64_t in_path_count;

	uint64_t out_path_total;
	uint64_t out_path_count;

	uint64_t dedup_cycle_total;
	uint64_t dedup_cycle_count;

	uint64_t compz_cycle_total;
	uint64_t compz_cycle_count;
#endif
};

void front_worker_queueing_cb(EV_P_ ev_async *w, int revents);
void back_worker_queueing_cb(EV_P_ ev_async *w, int revents);

void front_worker_fd_cb(EV_P_ ev_io *w, int revents);
void back_worker_fd_cb(EV_P_ ev_io *w, int revents);

void* worker_loop(void *worker);

#endif
