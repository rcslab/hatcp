#include <stdio.h>
#include <stdlib.h>

#include "plugin.h"
#include "../app.h"

struct wanacc_plugin_list * 
wanacc_plugin_list_entry_init() 
{
	struct wanacc_plugin_list *n;
	n = (struct wanacc_plugin_list *)
		calloc(1, sizeof(struct wanacc_plugin_list));
	n->next = NULL;

	return (n);
}

void
wanacc_plugin_list_entry_clean(struct wanacc_plugin_list *entry)
{
	if (entry) 
		free(entry);
}

void 
wanacc_plugin_list_clean(struct wanacc_plugin_list *head)
{
	struct wanacc_plugin_list *curr, *next;

	if (!head)
		return;

	curr = head;
	while (curr) {
		next = curr->next;
		wanacc_plugin_list_entry_clean(curr);
		curr = next;
	}

	head = NULL;
}

void 
init_plugins(struct wanacc_plugin *plugins_head, struct wanacc_app *app) 
{
	int n, n_sub;
	struct wanacc_plugin_list *plist, *tmp, *idx; 

	n = sizeof(plugins_head)/sizeof(const void *);
	for (int i=0;i<n;i++) {
		plist = NULL;
		switch (plugins_head[i].stage) {
		case WANACC_PLUGIN_STAGE_IO:
			plist = app->plugins_head_io; 
			break;
		case WANACC_PLUGIN_STAGE_INIT:
			plist = app->plugins_head_init;
			break;
		case WANACC_PLUGIN_SYAGE_CLEAN:
			plist = app->plugins_head_clean;
			break;
		}

		if (plist == NULL) {
			plist = wanacc_plugin_list_entry_init();
			plist->plugin = &plugins_head[i];
			continue;   
		}

		idx = plist;
		tmp = wanacc_plugin_list_entry_init();
		tmp->plugin = &plugins_head[i];
		while (idx) {
			if (idx->plugin->order < plugins_head[i].order) {
				tmp->next = idx->next;
				idx->next = tmp;
				break;
			}
			if (!idx->next) {
				idx->next = tmp;
				break;
			}
			idx = idx->next;
		}
	}
}

