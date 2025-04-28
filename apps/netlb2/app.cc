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

#include "app.h"
#include "server.h"
#include "utils.h"
#include "plugin/plugin.h"

extern int APP_VERBOSE;

static void start_listener(int fd, struct netlb_app * app);
static void listener_cb(EV_P_ ev_io *w, int revents);

int 
init_app(struct netlb_app *app) 
{
	int n, error;
	char enabled;
	//void *dyp;

	if (app == NULL) 
		return (1);

	app->somig_mode = NETLB_SERVER_SMG_NONE;
	app->worker_count = 1;

	app->verbose = 0;
	app->n_plugins = 0;
	app->load_builtin_plugins = 1;
	app->load_dy_plugins = 1;

#ifdef SOMIGRATION
	app->migration = 0;
#endif

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

	INFO("== Plugins List ==\n");
	for (int i=0;i<app->n_plugins;i++) {
		enabled = 'X';
		if (app->plugins[i].enabled) {
			enabled = 'O';
			error = (*app->plugins[i].netlb_plugin_init)();
			if (error) {
				app->plugins[i].enabled = 0;
				enabled = 'F';
			}
		}
		INFO("[%c] %s (Version: %s)\n", enabled, app->plugins[i].name,
		    app->plugins[i].ver);
	}
	INFO("\n");

	return (0);
}

void 
start_app(struct netlb_app *app)
{
	int error = 0, rt;
	struct netlb_worker *worker;
	pthread_t *worker_threads;
#ifndef NETLB_MULTILISTEN
	int listen_fd;
#endif

    	if (app == NULL) 
		return;

	app->workers = NULL;
	if (app->worker_count > 0) {
		app->workers = calloc(app->worker_count, sizeof(struct netlb_worker));
		worker_threads = calloc(app->worker_count, sizeof(pthread_t));
		if (!app->workers) {
			APPERR("Failed to allocate memory\n");
			exit(0);
		}
	} else {
		APPERR("Invalid netlb worker number\n");
		exit(0);
	}

#ifndef NETLB_MULTILISTEN
	error = init_socket(&listen_fd, 
		    app->app_addr, app->app_port, 
		    app->somig_mode, app->mso_addr, 
		    app->ctl_port, app->rso_addr, 
		    app->ctl_port);
	if (error) {
		APPERR("Cannot init server socket.\n");
		exit(0);
	}

	app->global_listen_fd = listen_fd;
#endif

	DBG("Starting server...");
	for (int i=0;i<app->worker_count;i++) {
		worker = &app->workers[i];
		worker->id = i;
		worker->app = app;
#ifndef NETLB_MULTILISTEN
		worker->listen_fd = listen_fd;
#endif
		TAILQ_INIT(&worker->netloads);

		rt = pthread_create(&(worker_threads[i]), NULL,
			start_server, (void*)worker);
		if (rt) {
		    APPERR("Failed to start socks worker thread. \n");
		    exit(0);
		}

		if (app->somig_mode == NETLB_SERVER_SMG_REPLICA) {
			sleep(1);
		}
	}
#ifndef NETLB_MULTILISTEN
	start_listener(listen_fd, app);
#endif
	
	// join
	for (int i=0;i<app->worker_count;i++) {
		pthread_join(worker_threads[i], NULL);
	}

	free(worker_threads);
}

void
clean_app(struct netlb_app *app)
{
	// ??
	free(app->workers);
}

static void 
start_listener(int fd, struct netlb_app * app)
{
	struct netlb_ev_io ev_io_listenfd;
	struct ev_loop *loop;

	app->next_worker = 0;

	loop = ev_loop_new(0);
	ev_io_listenfd.netload = app;
	ev_io_listenfd.netload_type = NETLOAD_IO_LISTENFD;
	ev_io_init(&ev_io_listenfd.evio, listener_cb, fd, EV_READ);
	ev_io_start(loop, &ev_io_listenfd.evio);

	printf("Start listening..\n");
	ev_loop(loop, 0);

	ev_loop_destroy(loop);
}

static void
listener_cb(EV_P_ ev_io *w, int revents)
{
	struct netlb_ev_io *nei;
	struct netlb_app *app;
	struct netlb_worker *worker;
	struct netload_entry *netload;
	int fd, error;

	nei = (struct netlb_ev_io *)w;
	app = (struct netlb_app *)nei->netload;
	
	worker = &app->workers[app->next_worker];

	fd = accept_socket(app->global_listen_fd);
	if (fd <= 0) {
		SYSERR(ENOMEM, 
		    "Cannot allocate enough memory for new connection.");
		close(fd);
		return;
	}

	DBG("LISTEN - [W%d]New connection fd %d", app->next_worker, fd);

	error = netload_new_client_connection(worker, fd, NULL);
	if (!error) {
		app->next_worker++;
		if (app->next_worker >= app->worker_count)
			app->next_worker = 0;
	} else {
		SYSERR(error, "Cannot accept new client connection.");
	}
}

int 
parse_args(struct netlb_app *app, int argc, char *argv[])
{
	int ch, error = 0;
	
	if (app == NULL) 
		return (1);

	while ((ch = getopt(argc, argv, "m:S:P:s:p:A:a:R:r:K:w:H:hv?")) != -1) {
		switch (ch) {
		case 'm':
#ifdef SOMIGRATION
			if (strcmp("mso", optarg) == 0) {
				app->somig_mode = NETLB_SERVER_SMG_PRIMARY;
			} else if (strcmp("rso", optarg) == 0) {
				app->somig_mode = NETLB_SERVER_SMG_REPLICA;
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
			app->dst_addr = (uint32_t)inet_addr(optarg);
			break;
		case 'P':
			app->dst_port = htons(atoi(optarg));
			break;
		case 's':
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
		case 'v':
			app->verbose = 1;
			APP_VERBOSE = 1;
			break;
		case 'w':
			app->worker_count = atoi(optarg);
			break;
		case 'K':
#ifdef SOMIGRATION
			app->migration = atoi(optarg);
			break;
#else
			APPERR("Benchmark feature, kernel SOMIG support required.");
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
	printf("Usage: \n");
	printf("[-s <App address>] [-p <App port>]\n");
	printf("[-S <Backend server address>] [-P <Backend server port>] \n");
#ifdef SOMIGRATION
	printf("[-m <working mode>] \n");
	printf("[-A <Primary address>] [-a <Primary port>] \n");
	printf("[-R <Replica address>] [-r <Replica port>] \n");
#endif
	printf("[-K <Migration Time>] \n");
	printf("[-w <worker number>] \n");
	printf("[-v] [-h|-?]\n");
}
