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
#include "client.h"
#include "utils.h"
#include "hosts.h"
#include "stats.h"
#include "plugin/plugin.h"

extern int APP_VERBOSE;

static void init_stats(struct socks_app * app);
static void free_stats(struct socks_app * app);
static void stat_loop(void * app);
static void start_stat_worker(pthread_t *thr, struct socks_app *app);
static void stop_stat_worker(pthread_t *thr, struct socks_app *app);
static void start_listener(int fd, struct socks_app * app);
static void listener_cb(EV_P_ ev_io *w, int revents);

int 
init_app(struct socks_app *app) 
{
	int n, error;
	char enabled;
	//void *dyp;

	if (app == NULL) 
		return (1);

	app->mode = -1;
	app->somig_mode = SOCKS_SERVER_SMG_NONE;
	app->worker_count = 1;
	//app->socks = TAILQ_HEAD_INITIALIZER(app->socks);
	app->verbose = 0;
	bzero(&app->socks_version, SOCKS_VERSION_COUNT);
	app->socks_version[5] = 1;
	app->n_plugins = 0;
	app->load_builtin_plugins = 1;
	app->load_dy_plugins = 1;
	app->stats_enabled = 0;
	app->usage_fp = NULL;
	app->usage_file = NULL;
	app->debug_size = 0;
	app->hosts = 0;

#ifdef SOMIGRATION
	app->failover = 0;
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
			error = (*app->plugins[i].socks_plugin_init)();
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
start_app(struct socks_app *app)
{
	int error = 0, rt;
	struct socks_worker *worker;
	pthread_t *worker_threads;
	pthread_t stat_thr;
#ifndef SOCKS_MULTILISTEN
	int listen_fd;
#endif

    	if (app == NULL) 
		return;

	if (app->stats_enabled) {
		init_stats(app);
	}

	if (app->hosts) {
		rt = hosts_init(app->hosts_file);
		if (rt == 0) {
			app->hosts = 0;
		}
	}

	app->workers = NULL;
	if (app->worker_count > 0) {
		app->workers = calloc(app->worker_count, sizeof(struct socks_worker));
		worker_threads = calloc(app->worker_count, sizeof(pthread_t));
		if (!app->workers) {
			APPERR("Failed to allocate memory\n");
			exit(0);
		}
	} else {
		APPERR("Invalid socks worker number\n");
		exit(0);
	}

#ifndef SOCKS_MULTILISTEN
	error = init_socket_socks(&listen_fd, app->mode, 
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
		getrusage(RUSAGE_SELF, &worker->rlast);
#ifndef SOCKS_MULTILISTEN
		worker->listen_fd = listen_fd;
#endif
		TAILQ_INIT(&worker->socks);
		memcpy(worker->socks_version, app->socks_version, SOCKS_VERSION_COUNT);

		if (app->mode == SOCKS_SERVER) {
			rt = pthread_create(&(worker_threads[i]), NULL,
				    start_server, (void*)worker);
			if (rt) {
				APPERR("Failed to start socks worker thread. \n");
				exit(0);
			}

		} else if (app->mode == SOCKS_CLIENT) {
			APPERR("Client mode is not supported.\n");
			exit(0);
		} else {
			APPERR("Unrecognized app mode.\n");
			exit(0);
		}

		if (app->somig_mode == SOCKS_SERVER_SMG_REPLICA) {
			sleep(1);
		}
	}
	start_stat_worker(&stat_thr, app);
#ifndef SOCKS_MULTILISTEN
	start_listener(listen_fd, app);
#endif
	stop_stat_worker(&stat_thr, app);
	
	// join
	for (int i=0;i<app->worker_count;i++) {
		pthread_join(worker_threads[i], NULL);
	}

	free(worker_threads);
}

void
clean_app(struct socks_app *app)
{
	struct socks_worker *worker;
	struct socks_entry *socks, *tmp;

	free(app->workers);

	if (app->stats_enabled) {
		free_stats(app);
	}
}

static void 
init_stats(struct socks_app * app)
{
	app->stats.arr_bufsize = (uint32_t *)calloc(SOCKS_STATS_ALLOCATION_STEP, sizeof(uint32_t)); 
	app->stats.allocated_size = SOCKS_STATS_ALLOCATION_STEP;
	app->stats.seconds = 0;

	if (app->usage_file != NULL) {
		app->usage_fp = fopen(app->usage_file, "w");
		if (app->usage_fp != NULL) {
			fprintf(app->usage_fp, "second,fd,cli_cpu,smg_cpu,app_cpu,mbuf,mbuf9k,mem\n");
			stats_init();
		}
	}
}

static void 
free_stats(struct socks_app * app)
{
	free(app->stats.arr_bufsize);
}

static void
stat_loop(void * app)
{
	struct stat_ev_io sio;
	struct ev_loop *loop;

	init_stats((struct socks_app *)app);

	loop = ev_loop_new(0);

	sio.app = (struct socks_app *)app;

	ev_timer_init(&(sio.tmout_w), socks_stat_cb, 1, 1);
	ev_timer_start(loop, &(sio.tmout_w));
    
	ev_loop(loop, 0);

	ev_loop_destroy(loop);
}

static void 
start_stat_worker(pthread_t *thr, struct socks_app *app)
{
	int rt;
	rt = pthread_create(thr, NULL, stat_loop, (void*)app);
}

static void 
stop_stat_worker(pthread_t *thr, struct socks_app *app)
{
	pthread_join(*thr, NULL);
	if (app->usage_fp != NULL)
		fclose(app->usage_fp);
}

static void 
start_listener(int fd, struct socks_app * app)
{
	struct socks_ev_io ev_io_listenfd;
	struct ev_loop *loop;

	app->next_worker = 0;

	loop = ev_loop_new(0);
	ev_io_listenfd.socks = app;
	ev_io_listenfd.socks_type = SOCKS_IO_LISTENFD;
	ev_io_init(&ev_io_listenfd.evio, listener_cb, fd, EV_READ);
	ev_io_start(loop, &ev_io_listenfd.evio);

	ev_loop(loop, 0);

	ev_loop_destroy(loop);
}

static void
listener_cb(EV_P_ ev_io *w, int revents)
{
	struct socks_ev_io *sei;
	struct socks_app *app;
	struct socks_worker *worker;
	struct socks_entry *socks;
	int fd;

	sei = (struct socks_ev_io *)w;
	app = (struct socks_app *)sei->socks;
	
	worker = &app->workers[app->next_worker];

	fd = accept_socket(app->global_listen_fd);
	if (fd <= 0) {
		SYSERR(ENOMEM, 
		    "Cannot allocate enough memory for new connection.");
		close(fd);
		return;
	}

	DBG("LISTEN - [W%d]New connection fd %d", app->next_worker, fd);

	socks = (struct socks_entry *)calloc(1, sizeof(struct socks_entry));
	if (!socks) {
		SYSERR(ENOMEM, 
		    "Cannot allocate enough memory for new connection.");
		close(fd);
		return;
	}
	
	socks->cli_fd = fd;
	socks->cli_buf_size = SOCKS_CLI_BUF_SIZE;
	socks->dst_buf_size = SOCKS_DST_BUF_SIZE;
	socks->cli_buf = (char *)calloc(1, socks->cli_buf_size);
	socks->dst_buf = (char *)calloc(1, socks->dst_buf_size);
	socks->fd = 0;
	socks->ver = SOCKS_VERSION_5;
	socks->state = SOCKS_STATE_DISCONNECTED;
	socks->worker = worker;
	socks->debug_size = worker->app->debug_size;
	socks->debug_size_now = 0;
	TAILQ_INSERT_TAIL(&(worker->socks), socks, list);

	socks->cli_io.socks = socks;
	socks->cli_io.socks_type = SOCKS_IO_CLIFD;
	ev_io_init(&socks->cli_io.evio, socks_read_cb, 
	    socks->cli_fd, EV_READ);
	ev_io_start(worker->loop, &socks->cli_io.evio);
	
	app->next_worker++;
	if (app->next_worker >= app->worker_count)
		app->next_worker = 0;
}

int 
parse_args(struct socks_app *app, int argc, char *argv[])
{
	int ch, error = 0;
	
	if (app == NULL) 
		return (1);

	while ((ch = getopt(argc, argv, "csm:S:p:A:a:R:r:u:K:d:iw:H:hv?")) != -1) {
		switch (ch) {
		case 'c':
			app->mode = SOCKS_CLIENT;
			break;
		case 's':
			app->mode = SOCKS_SERVER;
			break;	
		case 'm':
#ifdef SOMIGRATION
			if (strcmp("mso", optarg) == 0) {
				app->somig_mode = SOCKS_SERVER_SMG_PRIMARY;
			} else if (strcmp("rso", optarg) == 0) {
				app->somig_mode = SOCKS_SERVER_SMG_REPLICA;
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
		case 'v':
			app->verbose = 1;
			APP_VERBOSE = 1;
			break;
		case 'u':
			app->usage_file = optarg;
			break;
		case 'i':
			app->stats_enabled = 1;
			break;
		case 'd':
			app->debug_size = atoi(optarg);
			break;
		case 'w':
			app->worker_count = atoi(optarg);
			break;
		case 'K':
#ifdef SOMIGRATION
			app->failover = atoi(optarg);
			break;
#else
			APPERR("Benchmark feature, kernel SOMIG support required.");
			exit(0);
#endif
		case 'H':
			app->hosts = 1;
			app->hosts_file = optarg;
			break;
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
	printf("Usage [-v] [-s] [-c] [-i] [-m <working mode>] [-S <App address>] \n");
	printf("[-p <App port>] \n");
#ifdef SOMIGRATION
	printf("[-A <Primary address>] [-a <Primary port>] \n");
	printf("[-R <Replica address>] [-r <Replica port>] \n");
#endif
	printf("[-K <Failover Time>] [-d <Debug Size>] \n");
	printf("[-w <worker number>] \n");
	printf("[-H <hosts file>] \n");
	printf("[-v] [-h|-?]\n");
}
