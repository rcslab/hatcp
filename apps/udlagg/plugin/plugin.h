#ifndef PLUGIN_H_
#define PLUGIN_H_

struct udlagg_plugin {
	char name[255];
	char producer[255];
	char desc[2048];
	char ver[255];
	int enabled;
	int order;
	int (*udlagg_plugin_init)();
	int (*udlagg_plugin_src_packet_rx)(char *pld);
	int (*udlagg_plugin_dst_packet_rx)(char *pld);
	int (*udlagg_plugin_clean)();
};

#ifdef ANTIVIRUS
#include "antivirus/antivirus.h"
#endif

static int (*plugins[])(struct udlagg_plugin *) = {
#ifdef ANTIVIRUS
	antivirus,
#endif
};


#endif
