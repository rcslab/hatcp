#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdatomic.h>
#include <errno.h>
#include <pthread.h>

#include <ev.h>

#include "stat.h"
#include "utils.h"
#include "netutil.h"
#include "wrkwrk.h"

void
init_wrkwrk_stat(struct wrkwrk_stat *ws, int duration)
{
	int ret;
	ret = pthread_spin_init(&(ws->lock), PTHREAD_PROCESS_SHARED);

	ws->total_request = 0;
	ws->total_transfered = 0;

	ws->connect_error = 0;
	ws->parse_error = 0;

	//memset(ws->http_status_code, 0, sizeof(ws->http_status_code));

	ws->latency = 0;
	ws->throughput = 0;
	ws->request = 0;

	ws->arr_latency = calloc(duration, sizeof(uint32_t));
	ws->arr_throughput = calloc(duration, sizeof(uint32_t));
	ws->arr_request = calloc(duration, sizeof(uint32_t));

	ws->trace_done = 0;
	ws->seconds = 0;
}

void
free_wrkwrk_stat(struct wrkwrk_stat *ws)
{
	free(ws->arr_latency);
	free(ws->arr_throughput);
	free(ws->arr_request);
}

static void
wrkwrk_stat_callback(EV_P_ struct ev_timer* w, int revents)
{
	int done = 0, idx, trace_done = 0, thread_done = 0, error = 0;
	uint32_t latency, latency_count, throughput, request;
	struct ws_ev_io *ws = (struct ws_ev_io *)w;
	struct stat_arg *s_arg = ws->s_arg;
	int prt_second, prt_thread;
	uint32_t prt_latency, prt_throughput, prt_request, prt_rexmt = 0;
	uint16_t prt_port = 0;

    	int duration = s_arg->app->duration;
	int thread = s_arg->thread;
	struct wrkwrk * app = s_arg->app;
	struct wrkwrk_stat * w_stat = s_arg->w_stat;
	
	int conn_ready_count = 0;
	uint32_t fg_counter[WRKWRK_MAX_CONNECTION][9];

	uint32_t rexmt, rexmt_prev = 0;
	struct tcp_stat ts;

	if (app->stat == 0) {
		for (int i=0;i<thread;i++) {
			conn_ready_count = atomic_load(&wrkwrk_conn_cnt);
			trace_done = w_stat[i].trace_done;

			if (conn_ready_count == 0) {
				w_stat[i].seconds++;
			}

			if (trace_done == app->connection)
				thread_done++;
		
			if (w_stat[i].seconds >= duration + app->warmup) {
				atomic_store(&wrkwrk_status, WRKWRK_STATUS_STOPING);
				done = 1;
			}
		}
		goto check_thread_done; 
	}

	memset(&fg_counter, 0, sizeof(fg_counter));

	for (int i=0;i<thread;i++) {
		idx = w_stat[i].seconds;

		pthread_spin_lock(&(w_stat[i].lock));

#ifdef LATENCY_DIAG
		printf("================\n");
		for (int j=0;j<10;j++) {
			printf("[%d-%dus]: %d\n", 
				j*BUCKET_UNIT, (j+1)*BUCKET_UNIT, 
				w_stat[i].lat_dist[j]);
		}
		printf("[%dus +]: %d\n", 10*BUCKET_UNIT, w_stat[i].lat_dist[10]);
		printf("MAX: %d\n", w_stat[i].lat_max);

		memset(w_stat[i].lat_dist, 0, sizeof(w_stat[i].lat_dist));
		w_stat[i].lat_max = 0;
#endif

		latency_count = w_stat[i].latency_count;
		latency = w_stat[i].latency;
		throughput = w_stat[i].throughput;
		request = w_stat[i].request;
		
		trace_done = w_stat[i].trace_done;

		w_stat[i].latency_count = 0;
		w_stat[i].latency = 0;
		w_stat[i].throughput = 0;
		w_stat[i].request = 0;
		
		/*
		 * Grab per-connection tcp-info
		 */
		rexmt = 0;
		rexmt_prev = w_stat[i].total_rexmt_prev;
		for (int c=0;c<app->connection;c++) {
			fg_counter[c][0] = w_stat[i].conns[c].fg_throughput;
			w_stat[i].conns[c].fg_throughput = 0;

			error = get_tcp_stat(w_stat[i].conns[c].fd, &ts);
			if (error == 0) {
				rexmt += ts.snd_rexmitpkt;
				fg_counter[c][1] = ts.snd_wscale;
				fg_counter[c][2] = ts.rcv_wscale;
				fg_counter[c][3] = ts.rtt;
				fg_counter[c][4] = ts.snd_cwnd;
				fg_counter[c][5] = ts.rcv_space;
				fg_counter[c][6] = ts.snd_rexmitpkt;
			}
			fg_counter[c][7] = w_stat[i].conns[c].local_conn_port;
		}
		w_stat[i].total_rexmt_prev = rexmt;
		prt_rexmt = (rexmt > rexmt_prev ? (rexmt - rexmt_prev) : 0);

		pthread_spin_unlock(&(w_stat[i].lock));
		prt_second = w_stat[i].seconds;
		prt_thread = i;
		prt_port = w_stat[i].conns[0].local_conn_port;
		if (latency_count != 0) {
			w_stat[i].arr_latency[idx] = latency / latency_count;
			w_stat[i].arr_throughput[idx] = throughput;
			w_stat[i].arr_request[idx] = request;

			prt_latency = latency / latency_count;
			prt_throughput = throughput;
			prt_request = request;
		} else {
			w_stat[i].total_request -= request;
			w_stat[i].total_transfered -= throughput;
			w_stat[i].arr_latency[idx] = 0;
			w_stat[i].arr_throughput[idx] = 0;
			w_stat[i].arr_request[idx] = 0;

			prt_latency = 0;
			prt_throughput = throughput;
			prt_request = 0;
		}

		conn_ready_count = atomic_load(&wrkwrk_conn_cnt);
		if (conn_ready_count == 0) {
			/*
			 * second, thread id, latency, throughput, request,
			 * rexmt
			 */
			if (prt_second - app->warmup >= 0) {
				printf("%d,%d,%u,%u,%u,%u,%u\n", 
					prt_second - app->warmup,
					prt_thread, 
					prt_latency, 
					prt_throughput / 1000, 
					prt_request,
					prt_rexmt,
					prt_port); 
			}

			if (app->fg_stat && (prt_second - app->warmup >= 0))
				for (int c=0;c<app->connection;c++) {   
					printf("conn:%d,%u,%u,%u,%u,%u,%u,%u,%u\n", 
					    c, fg_counter[c][0] / 1000,
					    fg_counter[c][1], fg_counter[c][2],
					    fg_counter[c][3], fg_counter[c][4],
					    fg_counter[c][5], fg_counter[c][6],
					    fg_counter[c][7]
					);
					memset(&fg_counter[c], 0, 8);
				}
		
			w_stat[i].seconds++;
			//DBG("TIME: %d", w_stat[i].seconds);
		}

		if (trace_done == app->connection)
			thread_done++;
		
		if (w_stat[i].seconds >= duration + app->warmup) {
			atomic_store(&wrkwrk_status, WRKWRK_STATUS_STOPING);
			done = 1;
		}
	}

check_thread_done:
	if (thread_done == app->threads) {
		atomic_store(&wrkwrk_status, WRKWRK_STATUS_STOPING);
		done = 1;
	}

	if (done)
		ev_break(EV_A_ EVBREAK_ALL);
}

void *
wrkwrk_stat(void *s_arg)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct ws_ev_io wio;

	int duration = ((struct stat_arg *)s_arg)->app->duration;
	int threads = ((struct stat_arg *)s_arg)->thread;
	
	struct wrkwrk_stat * ws = ((struct stat_arg *)s_arg)->w_stat;

	wio.s_arg = s_arg;

	uint32_t latency, throughput, request;

	printf("Time,thread,latency(us),throughput(KB),request,rexmt,rport\n");

        ev_timer_init(&(wio.tmout_w), wrkwrk_stat_callback, 1, 1);
        ev_timer_start(loop, &(wio.tmout_w));

        ev_run(loop, 0);
	ev_loop_destroy(loop);
	
	return (NULL);

	/* Collect and dump data */
	printf("Time,latency(us),throughput(KB),request\n");
	for (int j=0;j<ws[0].seconds;j++) {
		latency = 0;
		throughput = 0;
		request = 0;
		for (int i=0;i<threads;i++) {
			latency += ws[i].arr_latency[j];
			throughput += ws[i].arr_throughput[j] / 1000;
			request += ws[i].arr_request[j];
		}
		printf("%d,%u,%u,%u\n", j, latency, throughput, request);
		//printf("============================================\n");
		//printf("%u MB data received, %u requests issued, in %u secs.\n",
		//    ws[i].total_transfered/1000/1000, ws[i].total_request, ws[i].seconds);
		//printf("============================================\n");
	}

	return (NULL);

}
