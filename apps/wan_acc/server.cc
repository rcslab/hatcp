#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <sys/resource.h>
#include <pthread.h>
#include <ev.h>

#include "io.h"
#include "app.h"
#include "worker.h"
#include "acc/dedup.h"
#include "server.h"
#include "stats.h"
#include "utils.h"
#include "netutils.h"

static void server_loop(struct wanacc_app *app);
static int init_wan(struct stream_entry *s, struct wanacc_app *app);

extern int DEDUP_ENABLED;
extern int COMPRESSION_ENABLED;

int
init_server(struct wanacc_app *app) 
{
	int error = 0;

#ifdef PERF_PROFILING
#ifdef TSC_CLOCK
	init_tsc();
#endif
#endif

	dedup_init();

#ifdef HASH_SKEIN_256
	DBG("Hash: Skein_256.");
#elif HASH_SHA3_256
	DBG("Hash: SHA3_256.");
#elif HASH_MD5
	DBG("Hash: MD5");
#else
	DBG("Hash: SHA2_256.");
#endif
	
	if (app->mode != WANACC_MID_SERVER && app->mode != WANACC_SERVER) {
		APPERR("Unrecognized app mode.");
		exit(0);
	}

	if (app->connect_to_wan && app->listen_on_wan) {
		APPERR("Cannot connect/listen to WAN port simultaneously.");
		exit(0);
	}
	
	if (app->mode == WANACC_MID_SERVER) {
		error = init_socket_somig(&(app->listen_fd), app->mode, app->app_addr, 
			    app->app_port, app->somig_mode, app->mso_addr, app->ctl_port,
			    app->rso_addr, app->ctl_port);
		if (error) {
			DBG("Failed to initialize socket");
			return (error);
		}

		if (app->listen_on_wan) {
			error = init_socket_somig(&(app->listen_fd_wan), 
				    app->mode, app->wan_addr, app->wan_port, 
				    app->somig_on_wan ? app->somig_mode : 0, 
				    app->mso_addr, app->ctl_port,
				    app->rso_addr, app->ctl_port);
			if (error) {
				DBG("Failed to initialize wan socket");
				return (error);
			}
		}
	}

	if (app->mode == WANACC_SERVER) {
		if (app->connect_to_wan) {
			// do nothing
		} else {
			error = init_socket_somig(&(app->listen_fd), app->mode,
				    app->app_addr, app->app_port, app->somig_mode, 
				    app->mso_addr, app->ctl_port, app->rso_addr,
				    app->ctl_port);
			if (error) {
				DBG("Failed to initialize socket");
				exit(1);
			}
		}
	}

	return (error);
}

static int
init_wan(struct stream_entry *s, struct wanacc_app *app)
{
	int error;
	int fd = -1;

	switch (app->mode) {
	case WANACC_MID_SERVER:
		if (app->listen_on_wan) {
			/* Accept mid server connections */
			DBG("Waiting for incoming WAN connections from ES..");
			fd = accept_socket(app->listen_fd_wan);
			DBG("Accepted a WAN connection from ES.");
		} else {
			/* Connect to end server */
			error = init_socket(&fd);
			if (error) {
				DBG("Cannot init wan fd");
				return (-1);
			}
			DBG("Connecting to end wan @ %u:%u..", app->wan_addr, app->wan_port);
			error = connect_socket(fd, app->wan_addr, app->wan_port, 
				    app->somig_on_wan ? app->somig_mode : 0, app->mso_addr, app->ctl_port,
				    app->rso_addr, app->ctl_port);
			if (error) {
				DBG("Cannot connect to end wan");
				perror("Reason");
				return (-1);
			}
			DBG("Connected to end wan @ %u:%u..", app->wan_addr, app->wan_port);
		}
		break;
	case WANACC_SERVER:
		if (app->connect_to_wan) {
			error = init_socket(&fd);
			if (error) {
				DBG("Cannot init wan fd");
				return (-1);
			}
			DBG("Connecting to mid wan @ %u:%u..", app->app_addr, app->app_port);
			error = connect_socket(fd, app->app_addr, app->app_port, 
				    0, 0, 0, 0, 0);
			if (error) {
				DBG("Cannot connect to mid wan");
				perror("Reason");
				return (-1);
			}
			DBG("Connected to mid wan @ %u:%u..", app->app_addr, app->app_port);
		} else {
			/* Accept mid server connections */
			DBG("Waiting for incoming WAN connections from MS..");
			fd = accept_socket(app->listen_fd);
			DBG("Accepted a WAN connection from MS.");
		}
		break;
	}

	if (fd > 0) {
		s->fd = fd;
		s->hash = fd; /* TODO: replace with real hash */
	}

	return (fd);
}

static void
server_loop(struct wanacc_app *app) 
{
	struct stream_ev_io ev_io_listenfd;
	struct stream_entry *wan_stream;
	pthread_t *thread_front, *thread_back;
	struct worker *w;
	int rt, worker_count, fd;
	
	if (app->mode == WANACC_MID_SERVER) {
		DBG("Starting middle server...");
	} else if (app->mode == WANACC_SERVER) {
		DBG("Starting end server...");
	}

	/* Spawn front and back workers */
	worker_count = 0;
	thread_front = calloc(app->front_worker_count, sizeof(pthread_t));
	thread_back = calloc(app->back_worker_count, sizeof(pthread_t));
	for (int i=0;i<app->front_worker_count;i++) {
		rt = pthread_create(&(thread_front[i]), NULL, 
			worker_loop, (void*)&(app->front_workers[i]));
		if (rt) {
			APPERR("Failed to start front worker thread. \n");
			exit(0);
		}
	}
	for (int i=0;i<app->back_worker_count;i++) {
		rt = pthread_create(&(thread_back[i]), NULL, 
			worker_loop, (void*)&(app->back_workers[i]));
		if (rt) {
			APPERR("Failed to start back worker thread. \n");
			exit(0);
		}
	}

	while (worker_count < app->front_worker_count + app->back_worker_count) {
		pthread_mutex_lock(&app->worker_mtx);
		worker_count = app->worker_count;
		pthread_mutex_unlock(&app->worker_mtx);
	}

	assert(app->wan_count == app->back_worker_count);
	/* Setup wan connections */
	for (int i=0;i<app->wan_count;i++) {
		wan_stream = (struct stream_entry *)calloc(1, sizeof(struct stream_entry)); 

		rt = init_wan(wan_stream, app); 
		if (rt <= 0) {
			APPERR("Failed to connect to end server. \n");
			exit(0);
		}
		TAILQ_INSERT_TAIL(&(app->wan_streams), wan_stream, list);

		w = &app->back_workers[i];
		w->wan_stream = wan_stream;

		wan_stream->worker = w;
		wan_stream->app = app;

		wan_stream->io.stream_type = STREAM_IO_WANFD;
		wan_stream->io.stream = wan_stream;

		/* Register wan port event to the corresponding back worker */
		ev_io_init(&wan_stream->io.evio, back_worker_fd_cb, wan_stream->fd, EV_READ);
		ev_io_start(w->loop, &wan_stream->io.evio);
	}

	/* Register client listening socket to app's evloop */
	ev_io_listenfd.app = app;
	ev_io_listenfd.stream_type = STREAM_IO_LISTENFD;
	if (app->mode == WANACC_MID_SERVER) {
		ev_io_init(&ev_io_listenfd.evio, wanacc_new_stream_cb, app->listen_fd, EV_READ);
	} else {
		if (!app->connect_to_wan)
			ev_io_init(&ev_io_listenfd.evio, wanacc_new_wan_cb, app->listen_fd, EV_READ);
		else 
			app->listen_fd = -1;
	}

	if (app->listen_fd != -1)
		ev_io_start(app->loop, &ev_io_listenfd.evio);

	/* Setup remote connections if needed */
	if (app->mode == WANACC_SERVER && app->listen_on_remote) {
		app->remote_fds = calloc(app->back_worker_count, sizeof(int));
		
		if (app->somig_mode == WANACC_SERVER_SMG_REPLICA)
			usleep(200000);

		rt = init_socket_somig(&(app->listen_fd_remote), app->mode,
				    app->wan_addr, app->wan_port, app->somig_mode, 
				    app->wan_mso_addr, app->wan_ctl_port, 
				    app->wan_rso_addr, app->wan_ctl_port);
		if (rt) {
			DBG("Failed to initialize socket");
			exit(1);
		}
    
		for (int i=0;i<app->back_worker_count;i++) {
			DBG("Waiting for incoming connections from remote..");
			fd = accept_socket(app->listen_fd_remote);
			app->remote_fds[i] = fd;
			DBG("Accepted a connection from remote fd %d.",
			    fd);
		}
	}

	/* Start the loop for stat/wan port listening */
	DBG("wanacc started...");
	ev_run(app->loop, 0);

	DBG("stopping wanacc...");
	ev_loop_destroy(app->loop);

	for (int i=0;i<app->front_worker_count;i++) {
		pthread_join(thread_front[i], NULL);
	}
	for (int i=0;i<app->back_worker_count;i++) {
		pthread_join(thread_back[i], NULL);
	}
}

void
start_server(struct wanacc_app *app)
{
#ifdef SOMIGRATION
	struct stat_ev_io sio;
#endif
#ifdef PERF_PROFILING
	struct stat_ev_io pio;
#endif
	struct queue_ev_io *qio;
	struct worker *w;

	INFO("Dedup: %d\n", DEDUP_ENABLED);
	INFO("Compression: %d\n", COMPRESSION_ENABLED);

	getrusage(RUSAGE_SELF, &app->rlast);
	app->loop = ev_loop_new(0);
	app->front_workers = calloc(app->front_worker_count, sizeof(struct worker));
	app->back_workers = calloc(app->back_worker_count, sizeof(struct worker));
	for (int i=0;i<app->front_worker_count;i++) {
		w = &app->front_workers[i];
		w->id = i;
		w->type = WANACC_WORKER_FRONT;
		w->stream_count = 0;
		w->app = app;
		w->next_back_worker = 0;

		qio = &w->ev_queue;
		qio->worker = w;
		ev_async_init(&qio->io, front_worker_queueing_cb);
	}
	for (int i=0;i<app->back_worker_count;i++) {
		w = &app->back_workers[i];
		w->id = i;
		w->type = WANACC_WORKER_BACK;
		w->stream_count = 0;
		w->app = app;

		TAILQ_INIT(&w->ioq);
		TAILQ_INIT(&w->dtq);
		w->dtq_mtx = PTHREAD_MUTEX_INITIALIZER;

		hashtable_init(&w->ht);

		qio = &w->ev_queue;
		qio->worker = w;
		ev_async_init(&qio->io, back_worker_queueing_cb);
	}

	if (app->usage_fn != NULL) {
		app->usage_fp = fopen(app->usage_fn, "w");
		if (app->usage_fp != NULL) {
#ifdef PERF_PROFILING
			fprintf(app->usage_fp, "second,fd,cli_cpu,smg_cpu,app_cpu,mbuf,mbuf9k,mem,ff,bf,bq,in,out\n");
#else
			fprintf(app->usage_fp, "second,fd,cli_cpu,smg_cpu,app_cpu,mbuf,mbuf9k,mem\n");
#endif
			stats_init();
		}
	}
#ifdef PERF_PROFILING
	else { 
		printf("ff,bf,bq,in,out,dedup_cyc_sum,dedup_cyc_avg,compz_cyc_sum,compz_cyc_avg\n");
		
		pio.app = app;
		ev_timer_init(&(pio.tmout_w), &wanacc_perf_cb, 1, 1);
		ev_timer_start(app->loop, &(pio.tmout_w));
	}
#endif

#ifdef SOMIGRATION
	if (app->usage_fp != NULL || app->failover > 0) {
		sio.app = app;
		ev_timer_init(&(sio.tmout_w), wanacc_stat_cb, 1, 1);
		ev_timer_start(app->loop, &(sio.tmout_w));
	}
#endif

	server_loop(app);

#ifdef SOMIGRATION
	if (app->usage_fp != NULL)
		fclose(app->usage_fp);
#endif

	if (app->remote_fds)
		free(app->remote_fds);
	free(app->front_workers);
	free(app->back_workers);
}

