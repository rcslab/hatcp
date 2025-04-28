#ifndef UDLAGG_H_
#define UDLAGG_H_

#include <pcap.h>
#include "ieee8023ad_lacp.h"

#define UDLAGG_PCAP_RULE_SLOWPROTO_FILTER "ether proto 0x8809"  //0x8809
//#define UDLAGG_PCAP_RULE_SLOWPROTO_FILTER ""

struct lagg {
	int fd;
	struct lacp_peerinfo local_info;
	struct lacp_peerinfo peer_info;
	uint8_t local_mac[ETHER_ADDR_LEN];
	uint8_t state;
	int initiator;
	uint16_t key;
	int ntt;
	int marker_ts_id;

	pcap_t *handle;
	pcap_if_t *dev;
};

struct lagg_ev_io {
	ev_io evio;
	struct lagg *lagg;
};

struct lagg * init_lagg(void *udlagg);
void show_devices();

void lagg_ev_cb(EV_P_ ev_io *w, int revents);

#endif
