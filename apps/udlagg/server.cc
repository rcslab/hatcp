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
#include "udlagg.h"
#include "netutils.h"

struct timer_ev_io {
	ev_timer tmout_w;
	struct udlagg_app *app;
};
static void timer_cb(EV_P_ struct ev_timer* w, int revents);

static void
timer_cb(EV_P_ struct ev_timer* w, int revents)
{
	return;
}

void 
start_server(void *udlagg)
{
	int error = 0;
	struct timer_ev_io tio;
	struct udlagg_app *app = (struct udlagg_app *)udlagg;
	struct lagg_ev_io lei;

	app->loop = ev_loop_new(0);

	tio.app = app;
	ev_timer_init(&tio.tmout_w, timer_cb, 1, 1);
	ev_timer_start(app->loop, &tio.tmout_w);

	lei.lagg = init_lagg(app);
	ev_io_init(&lei.evio, lagg_ev_cb, lei.lagg->fd, EV_READ);
	ev_io_start(app->loop, &lei.evio);

	INFO("udlagg is running..\n");

	ev_run(app->loop, 0);
	ev_loop_destroy(app->loop);
	free(lei.lagg);
}

