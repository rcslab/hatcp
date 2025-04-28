#ifndef STAT_H_
#define STAT_H_

#include <ev.h>

#ifdef LATENCY_DIAG
#define	BUCKET_UNIT 100
#endif

struct ws_ev_io {
	ev_timer tmout_w;
	struct stat_arg * s_arg;
};

struct wrkwrk_stat {
	pthread_spinlock_t lock;

	struct connection *conns;

	uint32_t total_request;
	uint32_t total_transfered;

	uint32_t total_rexmt_prev;

	uint32_t connect_error;
	uint32_t parse_error;
	
	//uint32_t http_status_code[600];

	/* Temperorary data counter */
	uint32_t latency;
	uint32_t latency_count;
#ifdef LATENCY_DIAG
	uint32_t lat_dist[11];
	uint32_t lat_max;
#endif
	uint32_t throughput;
	uint32_t request;

	/* Per-second data */
	uint32_t * arr_latency;
	uint32_t * arr_throughput;
	uint32_t * arr_request;

	uint32_t trace_done;
	uint32_t seconds;
};

void init_wrkwrk_stat(struct wrkwrk_stat *ws, int duration);
void free_wrkwrk_stat(struct wrkwrk_stat *ws);

void* wrkwrk_stat(void *s_arg);

#endif
