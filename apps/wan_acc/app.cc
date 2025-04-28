#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "io.h"
#include "app.h"
#include "utils.h"
#include "worker.h"
#include "server.h"
#include "plugin/plugin.h"

extern int APP_VERBOSE;
extern int DEDUP_ENABLED;
extern int COMPRESSION_ENABLED;

int 
init_app(struct wanacc_app *app) 
{
	int n, error;
	char enabled;
	//void *dyp;

	if (app == NULL) 
		return (1);

	app->mode = -1;
	app->somig_mode = WANACC_SERVER_SMG_NONE;
	app->streams_count = 0;
	//app->streams = TAILQ_HEAD_INITIALIZER(app->streams);
	TAILQ_INIT(&app->streams);
	app->streams_mtx = PTHREAD_MUTEX_INITIALIZER;
	//app->ioq = TAILQ_HEAD_INITIALIZER(app->ioq);
	app->usage_fp = NULL;
	app->usage_fn = NULL;
	app->run_time = 0;
	app->verbose = 0;

	app->front_worker_count = 1;
	app->front_workers = NULL;

	app->back_worker_count = 1;
	app->back_workers = NULL;

	app->front_worker_next = 0;
	app->back_worker_next = 0;

	app->worker_mtx = PTHREAD_MUTEX_INITIALIZER;
	app->worker_count = 0;

	app->connect_to_wan = 0;
	app->listen_on_wan = 0;
	app->listen_on_remote = 0;
	app->somig_on_wan = 0;

	app->wan_count = 1;
	TAILQ_INIT(&app->wan_streams);

	app->n_plugins = 0;
#ifdef SOMIGRATION
	app->failover = 0;
#endif
	app->load_builtin_plugins = 1;
	app->load_dy_plugins = 1;
	app->plugins_head_io = NULL;
	app->plugins_head_init = NULL;
	app->plugins_head_clean = NULL;

	APP_VERBOSE = 0;

	if (app->load_builtin_plugins) {
		n = sizeof(plugins)/sizeof(const void *);
		for (int i=0;i<n;i++) {
			error = (*plugins[i])(&app->plugins[app->n_plugins++]);
			if (error)
				app->n_plugins--;
			else 
				app->plugins[app->n_plugins-1].enabled = 1;
		}
	}
	if (app->load_dy_plugins) {
		//TODO
		//dyp = dlopen(plugin_path, RTLD_NOW|RTLD_GLOBAL);
	}

	INFO("== Plugins ==\n");
	for (int i=0;i<app->n_plugins;i++) {
		enabled = 'X';
		if (app->plugins[i].enabled) {
			enabled = 'O';
			error = (*app->plugins[i].wanacc_plugin_init)(app);
			if (error) {
				app->plugins[i].enabled = 0;
				enabled = 'F';
			}
		}
		INFO("[%c] %s (Version: %s)\n", enabled, app->plugins[i].name,
		    app->plugins[i].ver);
	}

	//init_plugins(app->plugins, app);
	return (0);
}

void 
start_app(struct wanacc_app *app)
{
	int error = 0;
    	if (app == NULL) 
		return;

	DBG("Initializing server...");
	error = init_server(app);
	if (error) {
		APPERR("Failed to init server.\n");
		exit(0);
	}

	start_server(app);
}

void
clean_app(struct wanacc_app *app)
{
	struct stream_entry *stream, *tmp;
	TAILQ_FOREACH_SAFE(stream, &app->streams, list, tmp) {
		TAILQ_REMOVE(&app->streams, stream, list);
		free(stream);
	}

	TAILQ_FOREACH_SAFE(stream, &app->wan_streams, list, tmp) {
		TAILQ_REMOVE(&app->wan_streams, stream, list);
		free(stream);
	}

	wanacc_plugin_list_clean(app->plugins_head_io);
	wanacc_plugin_list_clean(app->plugins_head_init);
	wanacc_plugin_list_clean(app->plugins_head_clean);
}

int 
parse_args(struct wanacc_app *app, int argc, char *argv[])
{
	int ch, error = 0;
	int opt;
	
	if (app == NULL) 
		return (1);

	while ((ch = getopt(argc, argv, "M:E:e:m:S:p:A:a:R:r:G:g:Q:q:u:K:f:o:b:dwLchv?")) != -1) {
		switch (ch) {
		case 'E':
			app->wan_addr = (uint32_t)inet_addr(optarg);
			break;
		case 'e':
			app->wan_port = htons(atoi(optarg));
			break;
		case 'M':
			if (strcmp("ms", optarg) == 0) {
				app->mode = WANACC_MID_SERVER;
			} else if (strcmp("es", optarg) == 0) {
				app->mode = WANACC_SERVER;
			} else {
				APPERR("Invalid server mode. See usage[-h].\n");
				exit(0);
			}
			break;	
		case 'w':
			app->listen_on_wan = 1;
			break;
		case 'c':
			app->connect_to_wan = 1;
			break;
		case 'L':
			app->listen_on_remote = 1;
			break;
		case 'o':
#define OPT_NO_DEDUP	    0x1
#define OPT_NO_COMPRESSION  0x2
			opt = atoi(optarg);
			DEDUP_ENABLED = !(opt & OPT_NO_DEDUP);
			COMPRESSION_ENABLED = !(opt & OPT_NO_COMPRESSION);
			break;
		case 'm':
#ifdef SOMIGRATION
			if (strcmp("mso", optarg) == 0) {
				app->somig_mode = WANACC_SERVER_SMG_PRIMARY;
			} else if (strcmp("rso", optarg) == 0) {
				app->somig_mode = WANACC_SERVER_SMG_REPLICA;
			} else {
				APPERR("Invalid operation mode. See usage[-h].\n");
				exit(0);
			}
#else
			APPERR("Current kernel does not have SOMIG support.\n");
			exit(0);
#endif
			break;
		case 'S':
			app->app_addr = (uint32_t)inet_addr(optarg);
			break;
		case 'p':
			app->app_port = htons(atoi(optarg));
			break;
		case 'A':
			app->mso_addr = (uint32_t)inet_addr(optarg);
			break;
		case 'a':
		case 'r':
			app->ctl_port = htons(atoi(optarg));
			break;
		case 'R':
			app->rso_addr = (uint32_t)inet_addr(optarg);
			break;
		case 'G':
			app->wan_mso_addr = (uint32_t)inet_addr(optarg);
			break;
		case 'Q':
			app->wan_rso_addr = (uint32_t)inet_addr(optarg);
			break;
		case 'g':
		case 'q':
			app->wan_ctl_port = htons(atoi(optarg));
			break;
		case 'v':
			app->verbose = 1;
			APP_VERBOSE = 1;
			break;
		case 'f':
			if (atoi(optarg) < 1 || atoi(optarg) > WANACC_WORKER_MAX) {
				APPERR("Invalid front worker number.");
				exit(0);
			}
			app->front_worker_count = atoi(optarg);
			break;
		case 'b':
			if (atoi(optarg) < 1 || atoi(optarg) > WANACC_WORKER_MAX) {
				APPERR("Invalid back worker number.");
				exit(0);
			}
			app->back_worker_count = atoi(optarg);
			app->wan_count = app->back_worker_count;
			break;
		case 'd':
			app->somig_on_wan = 1;
			break;
		case 'u':
#ifdef SOMIGRATION
			app->usage_fn = optarg;
#else
			printf("u option is for SOMIG only.");
			exit(0);
#endif
			break;
		case 'K':
#ifdef SOMIGRATION
			app->failover = atoi(optarg);
			break;
#else
			printf("K option is for SOMIG only.");
			exit(0);
#endif
		case 'h':
		case '?':
		default:
			usage();
			exit(0);
		}
	}

	return (error);
}

void
usage()
{
	printf("wanacc version %d.%d\n", WANACC_VERSION_MAJOR, WANACC_VERSION_MINOR);
	printf("Usage [-v] [-E <End-server/WAN address>] [-e <End-server/WAN port>] \n");
	printf("[-M <Server working mode>] [-m <TCP working mode>] \n");
	printf("[-S <App/MS WAN address>] [-p <App/MS WAN port>] \n");
	printf("[-f <Front worker count> ] [-b <Back worker count> ] \n");
	printf("[-o <bit flag option \n     0x1 NO_DEDUP \n     0x2 NO_COMPRESSION \n    >] \n");
#ifdef SOMIGRATION
	printf("[-A <Primary address>] [-a <Primary port>] \n");
	printf("[-R <Replica address>] [-r <Replica port>] \n");
	printf("[-G <WAN Primary address>] [-g <WAN Primary port>] \n");
	printf("[-Q <WAN Replica address>] [-q <WAN Replica port>] \n");
	printf("[-d Enable somig on WAN connection]\n");
	printf("[-w Listen on WAN port] [-L Listen on remote port]\n");
	printf("[-c Connect to WAN port]\n");
#endif
	printf("[-v] [-h|-?]\n");
}
