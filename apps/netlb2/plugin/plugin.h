#ifndef PLUGIN_H_
#define PLUGIN_H_

struct netlb_plugin {
	char name[255];
	char producer[255];
	char desc[2048];
	char ver[255];
	int enabled;
	int order;
	int (*netlb_plugin_init)();
	int (*netlb_plugin_src_packet_rx)(struct netload_entry *socks, char *pld);
	int (*netlb_plugin_dst_packet_rx)(struct netload_entry *socks, char *pld);
	int (*netlb_plugin_clean)();
};

#ifdef ANTIVIRUS
#include "antivirus/antivirus.h"
#endif

static int (*plugins[])(struct netlb_plugin *) = {
#ifdef ANTIVIRUS
	socks_antivirus,
#endif
};


#endif
