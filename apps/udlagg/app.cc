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


int 
init_app(struct udlagg_app *app) 
{
	int n, error;
	char enabled;
	//void *dyp;

	if (app == NULL) 
		return (1);

	app->verbose = 0;
	app->n_plugins = 0;
	app->load_builtin_plugins = 1;
	app->load_dy_plugins = 1;
	app->key = LACP_DEFAULT_KEY;
	app->initiator = 1;

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
			error = (*app->plugins[i].udlagg_plugin_init)();
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
start_app(struct udlagg_app *app)
{
	int error = 0, rt;

    	if (app == NULL) 
		return;

	start_server((void *)app);
}

void
clean_app(struct udlagg_app *app)
{
	// ??
}

int 
parse_args(struct udlagg_app *app, int argc, char *argv[])
{
	int ch, error = 0;
	
	if (app == NULL) 
		return (1);

	while ((ch = getopt(argc, argv, "s:p:i:k:H:lhv?")) != -1) {
		switch (ch) {
		case 's':
			app->addr = (uint32_t)inet_addr(optarg);
			break;
		case 'p':
			app->port = htons(atoi(optarg));
			break;
		case 'i':
			app->device = optarg;
			break;
		//case 'f':
		//	app->initiator = 1;
		//	break;
		case 'k':
			app->key = atoi(optarg);
			if (atoi(optarg) > 0xffff) {
				INFO("Invalid key. Has to be uint16 range.\n");
				exit(0);
			}
			break;
		case 'v':
			app->verbose = 1;
			APP_VERBOSE = 1;
			break;
		case 'l':
			show_devices();
			exit(0);
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
	printf("[-i <Device name>] \n");
	printf("[-k <Lacp key>] \n");
	//printf("[-f Initiator] \n");
	printf("[-l List devices] \n");
	printf("[-v] [-h|-?]\n");
}
