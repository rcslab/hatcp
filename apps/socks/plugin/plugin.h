#ifndef PLUGIN_H_
#define PLUGIN_H_

struct socks_plugin {
	char name[255];
	char producer[255];
	char desc[2048];
	char ver[255];
	int enabled;
	int order;
	int (*socks_plugin_init)();
	int (*socks_plugin_src_packet_rx)(struct socks_entry *socks, char *pld);
	int (*socks_plugin_dst_packet_rx)(struct socks_entry *socks, char *pld);
	int (*socks_plugin_clean)();
};

#ifdef ANTIVIRUS
#include "antivirus/antivirus.h"
#endif

static int (*plugins[])(struct socks_plugin *) = {
#ifdef ANTIVIRUS
	socks_antivirus,
#endif
};


#endif
