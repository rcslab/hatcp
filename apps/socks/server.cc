#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <ev.h>
#include <pthread.h>

#include "app.h"
#include "server.h"
#include "utils.h"
#include "netutils.h"

static void spin_cb(EV_P_ struct ev_timer* w, int revents);


static void
spin_cb(EV_P_ struct ev_timer* w, int revents)
{
	// TODO remove timer if we got something in the loop
}

void 
start_server(void *worker)
{
	int error = 0;
	struct socks_ev_io ev_io_listenfd;
	struct socks_worker *sw = (struct socks_worker *)worker;
	struct socks_entry *socks, *tmp;
	struct stat_ev_io sio;

	sw->loop = ev_loop_new(0);

#ifdef SOCKS_MULTILISTEN
	error = init_socket_socks(&(sw->listen_fd), sw->app->mode, 
		    sw->app->app_addr, sw->app->app_port, 
		    sw->app->somig_mode, sw->app->mso_addr, 
		    sw->app->ctl_port, sw->app->rso_addr, 
		    sw->app->ctl_port);
	if (error) {
		APPERR("Cannot init server socket.\n");
		exit(0);
	}
#endif

	DBG("Worker thread %d started..\n", sw->id);
#ifdef SOCKS_MULTILISTEN
	ev_io_listenfd.worker = sw;
	ev_io_listenfd.socks_type = SOCKS_IO_LISTENFD;
	ev_io_init(&ev_io_listenfd.evio, socks_read_cb, sw->listen_fd, EV_READ);

	ev_io_start(sw->loop, &ev_io_listenfd.evio);
#else
	sio.app = sw->app;
	ev_timer_init(&(sio.tmout_w), spin_cb, 5, 1);
	ev_timer_start(sw->loop, &(sio.tmout_w));
#endif
	ev_loop(sw->loop, 0);
	ev_loop_destroy(sw->loop);

	TAILQ_FOREACH_SAFE(socks, &sw->socks, list, tmp) {
		TAILQ_REMOVE(&sw->socks, socks, list);
		free(socks);
	}
}

