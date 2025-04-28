#ifndef        APP_H
#define        APP_H

#include <sys/queue.h>
#include <sys/resource.h>

#include <ev.h>
#include "socks.h"

#define SOCKS_SERVER			0
#define SOCKS_CLIENT			1

#define SOCKS_SERVER_SMG_NONE		0
#define SOCKS_SERVER_SMG_PRIMARY	1
#define SOCKS_SERVER_SMG_REPLICA	2

#define SOCKS_MAX_PLUGINS		64

#define SOCKS_STATS_ALLOCATION_STEP   60

TAILQ_HEAD(socks_queue, socks_entry);

struct socks_stats {
	uint32_t * arr_bufsize;
	uint32_t allocated_size;
	uint32_t seconds;
};

struct socks_worker {
	struct socks_app *app;
	int id;
	int listen_fd;
	int socks_count;

	struct rusage rlast;

	struct socks_queue socks;
	uint8_t socks_version[SOCKS_VERSION_COUNT];
	struct ev_loop *loop;
};

struct socks_app {
	uint16_t app_port;
	uint32_t app_addr;
	uint16_t ctl_port;
	uint32_t mso_addr;
	uint32_t rso_addr;

	int mode;			// Ser/Cli
	int somig_mode;			// Pri/Rep/Non
	uint8_t socks_version[SOCKS_VERSION_COUNT];

	int hosts;
	char *hosts_file;
					
	int worker_count;
	struct socks_worker *workers;
	int next_worker;
	int global_listen_fd;

	int stats_enabled;
	struct socks_stats stats;
	FILE * usage_fp;
	char * usage_file;

#ifdef SOMIGRATION
	int failover;
#endif
	int debug_size;

	int verbose;
	int load_builtin_plugins, load_dy_plugins;

	int n_plugins;
	struct socks_plugin plugins[SOCKS_MAX_PLUGINS];
};

int init_app(struct socks_app *app);	    
int parse_args(struct socks_app *app, int argc, char *argv[]);
void start_app(struct socks_app *app);
void clean_app(struct socks_app *app);
void usage();

#endif
