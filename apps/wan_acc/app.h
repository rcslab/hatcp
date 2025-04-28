#ifndef        APP_H_
#define        APP_H_

#include <sys/queue.h>
#include <sys/resource.h>

#include <ev.h>
#include "io.h"
#include "acc.h"

#define	WANACC_VERSION_MAJOR		0
#define	WANACC_VERSION_MINOR		2

// Mid-box
#define WANACC_MID_SERVER		0
// End-box
#define WANACC_SERVER			1

#define WANACC_SERVER_SMG_NONE		0
#define WANACC_SERVER_SMG_PRIMARY	1
#define WANACC_SERVER_SMG_REPLICA	2

#define WANACC_IO_BUFFER_SIZE		9200

#define WANACC_MAX_PLUGINS		64

TAILQ_HEAD(stream_queue, stream_entry);

struct wanacc_app {
	uint16_t app_port;
	uint32_t app_addr;
	// For Mid-Server, this is End-Server address
	// For End-Server, this is listening address
	uint16_t wan_port;
	uint32_t wan_addr;
	uint16_t ctl_port;
	uint32_t mso_addr;
	uint32_t rso_addr;
	uint16_t wan_ctl_port;
	uint32_t wan_mso_addr;
	uint32_t wan_rso_addr;

	int listen_fd;
	int listen_fd_wan;
	int listen_fd_remote;
	int *remote_fds;

	int front_worker_count;
	int back_worker_count;
	struct worker *front_workers;
	struct worker *back_workers;
	pthread_mutex_t	worker_mtx;
	int	worker_count;

	struct rusage rlast;

	int front_worker_next;
	int back_worker_next;

	int mode;			// Ser/Cli
	int somig_mode;			// Pri/Rep/Non
	int streams_count;
	struct stream_queue streams;
	pthread_mutex_t	streams_mtx;
	int somig_on_wan;
	int listen_on_wan;
	int connect_to_wan;
	int listen_on_remote;

	int wan_count;
	struct stream_queue wan_streams;

	FILE * usage_fp;
	char * usage_fn;
	int run_time;
	struct ev_loop *loop;

#ifdef SOMIGRATION
	int failover;
#endif
	
	int verbose;
	int load_builtin_plugins, load_dy_plugins;

	int n_plugins;
	struct wanacc_plugin plugins[WANACC_MAX_PLUGINS];
	struct wanacc_plugin_list *plugins_head_io;
	struct wanacc_plugin_list *plugins_head_init;
	struct wanacc_plugin_list *plugins_head_clean;
};

int init_app(struct wanacc_app *app);	    
int parse_args(struct wanacc_app *app, int argc, char *argv[]);
void start_app(struct wanacc_app *app);
void clean_app(struct wanacc_app *app);
void usage();

#endif
