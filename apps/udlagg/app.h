#ifndef        APP_H
#define        APP_H

#include <sys/queue.h>
#include <sys/resource.h>

#include <ev.h>
#include "plugin/plugin.h"
#include "udlagg.h"

#define MAX_PLUGINS		64

#define LACP_DEFAULT_KEY 12345

struct udlagg_app {
	uint16_t port;
	uint32_t addr;

	char *device;

	int initiator;
	uint16_t key;

	struct ev_loop *loop;

	int verbose;
	int load_builtin_plugins, load_dy_plugins;

	int n_plugins;
	struct udlagg_plugin plugins[MAX_PLUGINS];
};

int init_app(struct udlagg_app *app);	    
int parse_args(struct udlagg_app *app, int argc, char *argv[]);
void start_app(struct udlagg_app *app);
void clean_app(struct udlagg_app *app);
void usage();

#endif
