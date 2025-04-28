#ifndef        APP_H
#define        APP_H

#include <sys/queue.h>
#include <sys/resource.h>

#include <ev.h>
#include "netlb.h"

#define NETLB_SERVER_SMG_NONE		0
#define NETLB_SERVER_SMG_PRIMARY	1
#define NETLB_SERVER_SMG_REPLICA	2

#define NETLB_MAX_PLUGINS		64

#define NETLB_STATS_ALLOCATION_STEP   60

TAILQ_HEAD(netload_queue, netload_entry);

struct netlb_worker {
	struct netlb_app *app;
	int id;
	int listen_fd;
	int netload_count;

	struct netload_queue netloads;
	struct ev_loop *loop;
};

struct netlb_app {
	uint16_t app_port;
	uint32_t app_addr;
	uint16_t dst_port;
	uint32_t dst_addr;
	uint16_t ctl_port;
	uint32_t mso_addr;
	uint32_t rso_addr;

	int somig_mode;			// Pri/Rep/Non

	int worker_count;
	struct netlb_worker *workers;
	int next_worker;
	int global_listen_fd;

#ifdef SOMIGRATION
	int migration;
#endif

	int verbose;
	int load_builtin_plugins, load_dy_plugins;

	int n_plugins;
	struct netlb_plugin plugins[NETLB_MAX_PLUGINS];
};

int init_app(struct netlb_app *app);	    
int parse_args(struct netlb_app *app, int argc, char *argv[]);
void start_app(struct netlb_app *app);
void clean_app(struct netlb_app *app);
void usage();

#endif
