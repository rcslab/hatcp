#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <ev.h>
#include <pthread.h>

#include <sys/socket.h>

#include "app.h"
#include "server.h"
#include "utils.h"
#include "netutils.h"

struct mig_ev_io {
	ev_timer tmout_w;
	int second;
	struct netlb_app *app;
};
static void mig_cb(EV_P_ struct ev_timer* w, int revents);

static void
mig_cb(EV_P_ struct ev_timer* w, int revents)
{
#ifdef SOMIGRATION
	struct somig_migopt opt;
	struct netlb_worker *worker;
	struct netload_entry *netload, *tmp;
	int *sec = &((struct mig_ev_io *)w)->second;
	struct netlb_app *app = ((struct mig_ev_io *)w)->app;
	
	if (app->migration == 0)
		return;

	(*sec)++;
	if (*sec < app->migration)
		return;

	/* Start the migration process */
	for (int i=0;i<app->worker_count;i++) {
		worker = &app->workers[i];
		TAILQ_FOREACH_SAFE(netload, &worker->netloads, list, tmp) {
			opt.node = 1;
			opt.flag = SOMIG_MIGRATION_FLAG_FAIL;
			if (setsockopt(netload->cli_fd, SOL_SOCKET, 
				       SO_MIG_MIGRATE, (char *)&opt, 
				       sizeof(opt))) {
				APPERR("Failed to trigger migration");
			}
		}
	}

	app->migration = 0;
#else
	return;
#endif
}

void 
start_server(void *worker)
{
	int error = 0;
	struct netlb_ev_io ev_io_listenfd;
	struct netlb_worker *sw = (struct netlb_worker *)worker;
	struct netload_entry *netload, *tmp;
	struct mig_ev_io mio;

	sw->loop = ev_loop_new(0);

#ifdef NETLB_MULTILISTEN
	error = init_socket(&(sw->listen_fd), sw->app->mode, 
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
#ifdef NETLB_MULTILISTEN
	ev_io_listenfd.worker = sw;
	ev_io_listenfd.netload_type = NETLOAD_IO_LISTENFD;
	ev_io_init(&ev_io_listenfd.evio, netload_read_cb, sw->listen_fd, EV_READ);

	ev_io_start(sw->loop, &ev_io_listenfd.evio);
#endif

	mio.second = 0;
	mio.app = sw->app;
	ev_timer_init(&(mio.tmout_w), mig_cb, 1, 1);
	ev_timer_start(sw->loop, &(mio.tmout_w));
	ev_loop(sw->loop, 0);
	ev_loop_destroy(sw->loop);

	TAILQ_FOREACH_SAFE(netload, &sw->netloads, list, tmp) {
		TAILQ_REMOVE(&sw->netloads, netload, list);
		netload_clean(netload);
	}
}

