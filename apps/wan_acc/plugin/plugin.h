#ifndef PLUGIN_H_
#define PLUGIN_H_

#define WANACC_PLUGIN_STAGE_IO		0
#define WANACC_PLUGIN_STAGE_PROTOCOL	1
#define WANACC_PLUGIN_STAGE_INIT	2
#define WANACC_PLUGIN_SYAGE_CLEAN	3

#define WANACC_PLUGINS_MAX		255 

struct wanacc_app;
struct stream_entry;

struct wanacc_plugin {
	char name[255];
	char producer[255];
	char desc[2048];
	char ver[255];
	int enabled;
	int stage;
	int order;
	int (*wanacc_plugin_init)(struct wanacc_app *app);
	void* (*wanacc_plugin_src_packet_rx)(
	    struct wanacc_app *app, struct stream_entry *stream, char **pld, int len);
	void* (*wanacc_plugin_dst_packet_rx)(struct stream_entry *stream, char **pld, int len);
	int (*wanacc_plugin_clean)();
};

struct wanacc_plugin_list {
	struct wanacc_plugin *plugin;
	struct wanacc_plugin_list *next;
};

struct wanacc_plugin_list * wanacc_plugin_list_entry_init();
void wanacc_plugin_list_entry_clean(struct wanacc_plugin_list *entry);
void wanacc_plugin_list_clean(struct wanacc_plugin_list *head);
//void init_plugins(struct wanacc_plugin *plugins_head, struct wanacc_app *app);

static int (*plugins[])(struct wanacc_plugin *) = {
};



#endif
