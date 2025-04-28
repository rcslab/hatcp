#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <time.h>

#include <ev.h>

#include <sys/socket.h>

#include "app.h"
#include "utils.h"
#include "netutils.h"

const uint8_t ethermulticastaddr_slowprotocols[ETHER_ADDR_LEN] = \
    { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x02 };

static void lagg_input(u_char *user, const struct pcap_pkthdr *h, const u_char *p);
static int  ether_send(pcap_t *handle, const u_char *p, int len, 
			    uint8_t *src, uint8_t *dst);
static int lagg_lacp_init(struct lagg *lagg);
static int lagg_lacp_update_info(struct lagg *lagg, struct lacpdu *ldu);
static int lagg_lacpdu_send(struct lagg *lagg);
static int lagg_lacpdu_mux(struct lagg *lagg);
static int lagg_marker_send(struct lagg *lagg);
static int lagg_lacp_compare_peerinfo(struct lacp_peerinfo *a, struct lacp_peerinfo *b);


static pcap_if_t *
init_device(char *dev)
{
	char error[PCAP_ERRBUF_SIZE];
	pcap_if_t *ifname, *i;

	if (pcap_findalldevs(&ifname, error) == -1) {
		goto err;
	}

	for (i=ifname;i;i=i->next) {
		if (strcmp(i->name, dev) == 0) {
			return i;
		}
	}	

err:
	SYSERR(0, "Failed to find devices.\n");
	return NULL;
}

static int
set_flags(pcap_t *handle)
{
	int error;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!handle)
		return (-1);
	
	error = pcap_setnonblock(handle, 1, errbuf);
	if (error) {
		SYSERR(0, "pcap_setnonblock %s\n", errbuf);
		return (-1);
	}

	error = pcap_set_promisc(handle, 1);
	if (error) {
		SYSERR(0, "Failed to pcap_set_promisc\n");
		return (-1);
	}

	return (0);
}

static int
set_filters(pcap_t *handle, const char *rule)
{
	int error;
	struct bpf_program pgm;

	error = pcap_compile(handle, &pgm, rule, 1, PCAP_NETMASK_UNKNOWN);
	if (error) {
		SYSERR(error, "Failed to compile pcap filter rules.\n");
		return (error);
	}

	error = pcap_setfilter(handle, &pgm);
	if (error) {
		SYSERR(error, "Failed to set pcap filter.\n");
		return (error);
	}

	return (0);
}

void
show_devices()
{
	char error[PCAP_ERRBUF_SIZE];
	pcap_if_t *ifname, *i;

	if (pcap_findalldevs(&ifname, error) == -1) {
		printf("No devices found.\n");
		return;
	}

	printf("Devices available:\n");
	for (i=ifname;i!=NULL;i=i->next) {
		printf("  %s\n", i->name); 
	}

	pcap_freealldevs(ifname);
}

struct lagg *
init_lagg(void *udlagg)
{
	int error = 0;
	uint64_t mac;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev;
	pcap_t *handle;
	struct udlagg_app *app = (struct udlagg_app *)udlagg;
	struct lagg *rt = NULL;

	srand(time(NULL));

	dev = init_device(app->device);
	if (!dev) {
		exit(0);
	}

	handle = pcap_create(app->device, errbuf);
	if (!handle) {
		SYSERR(0, "handle pcap_create %s\n", errbuf);
		exit(0);
	}

	error = set_flags(handle);
	if (error) {
		APPERR("Failed to set_flags for handle.\n");
		exit(0);
	}

	error = pcap_activate(handle);
	if (error) {
		pcap_close(handle);
		SYSERR(error, "Failed to activate handle\n");
		exit(0);
	}

	error = set_filters(handle, UDLAGG_PCAP_RULE_SLOWPROTO_FILTER);
	if (error) {
		pcap_close(handle);
		SYSERR(error, "Failed to apply filter\n");
		exit(0);
	}

	rt = (struct lagg *)calloc(1, sizeof(struct lagg));
	if (!rt) {
		SYSERR(ENOMEM, "Failed to create lagg structure.\n");
		pcap_close(handle);
		return (NULL);
	}

	rt->handle = handle;
	rt->fd = pcap_get_selectable_fd(handle);
	rt->dev = dev;
	rt->key = app->key;
	rt->initiator = app->initiator;
	error = get_if_mac(app->device, rt->local_mac);
	if (error) {
		SYSERR(error, "Failed to get local mac.\n");
		pcap_close(handle);
		free(rt);
		return (NULL);
	}

	assert(rt->fd != -1);

	error = lagg_lacp_init(rt);
	if (error) {
		SYSERR(error, "Failed to init lacp.\n");
		pcap_close(handle);
		free(rt);
		return (NULL);
	}

	//return (rt);
	
	printf("Starting pcap loop..\n"); 
	pcap_loop(rt->handle, 0, lagg_input, rt);

	return (rt);
}

static int
lagg_lacp_compare_peerinfo(struct lacp_peerinfo *a, struct lacp_peerinfo *b)
{
	return (memcmp(a, b, offsetof(struct lacp_peerinfo, lip_state)));
}

static void
lagg_marker_input(struct lagg *lagg, struct markerdu *mdu)
{
	uint8_t lladdr[ETHER_ADDR_LEN];
	int error = 0;

	if (!mdu)
		return;

	if (memcmp(&mdu->mdu_eh.ether_dhost,
	    &ethermulticastaddr_slowprotocols, ETHER_ADDR_LEN)) {
		goto bad;
	}

	if (mdu->mdu_sph.sph_version != 1) {
		goto bad;
	}
	
	// our info
	if (mdu->mdu_tlv.tlv_type == MARKER_TYPE_INFO &&
	    memcmp(mdu->mdu_info.mi_rq_system, lagg->local_mac, ETHER_ADDR_LEN) == 0) {
		return;
	}

	// others info
	if (mdu->mdu_tlv.tlv_type == MARKER_TYPE_RESPONSE &&
	    memcmp(mdu->mdu_info.mi_rq_system, lagg->local_mac, ETHER_ADDR_LEN)) {
		return;
	}

	DBG("Received markerdu.\n");

	switch (mdu->mdu_tlv.tlv_type) {
	case MARKER_TYPE_INFO:
		break;
	case MARKER_TYPE_RESPONSE:
		if (lagg->marker_ts_id == 1) {
			INFO("Ready.\n");
		}
		lagg->ntt = 0;
		break;
	default:
		goto bad;
	}
	
	return;
bad:
	DBG("Bad marker frame.\n");
	return;
}

static int
lagg_lacp_update_info(struct lagg *lagg, struct lacpdu *ldu)
{
	struct lacp_peerinfo *lpi;
	int ntt = lagg->ntt;
	
	lpi = &lagg->local_info;

	if (lagg_lacp_compare_peerinfo(&ldu->ldu_partner, lpi)) {
		DBG("Partner returned different info.\n");
		return (0);
	}

	lagg->ntt = (ldu->ldu_actor.lip_state == lagg->peer_info.lip_state) &&
		    (lagg->marker_ts_id == 0);

	memcpy((void *)&lagg->peer_info, &ldu->ldu_actor, sizeof(lagg->peer_info));

	return ((!ntt) && (!lagg->ntt));
}

static void
lagg_lacp_input(struct lagg *lagg, struct lacpdu *ldu)
{
	int ack, req = 0;

	if (!ldu)
		return;

	if (memcmp(&ldu->ldu_eh.ether_dhost,
	    &ethermulticastaddr_slowprotocols, ETHER_ADDR_LEN)) {
		goto bad;
	}

	DBG("Received lacpdu.\n");

	// ignore our sent
	if (!lagg_lacp_compare_peerinfo(&ldu->ldu_actor, &lagg->local_info)) {
		DBG("Packet we sent..Ignoring..\n");
		return;
	}

	// ignore others
	if (ldu->ldu_partner.lip_portid.lpi_portno != lagg->local_info.lip_portid.lpi_portno) {
		DBG("Other's packet..Ingoring..\n");
		return;
	}

	// update local info
	ack = lagg_lacp_update_info(lagg, ldu);
	DBG("ack %d\n", ack);
	if (ack) {
		req = lagg_lacpdu_mux(lagg);
		if (req == SLOWPROTOCOLS_SUBTYPE_LACP)
			lagg_lacpdu_send(lagg);
	}
	DBG("req %d\n", req);

	if (req == SLOWPROTOCOLS_SUBTYPE_LACP) {
		req = lagg_lacpdu_mux(lagg);
		lagg_lacpdu_send(lagg);
		lagg->ntt = 1;
	} else if (req == SLOWPROTOCOLS_SUBTYPE_MARKER) {
		// send marker
		lagg_marker_send(lagg);

	}
	
	return;
bad:
	DBG("Bad lacpdu frame.\n");
	return;
}

static int
lagg_lacpdu_mux(struct lagg *lagg)
{
	struct lacp_peerinfo *lpi, *rpi;
	uint8_t r_state;

	lpi = &lagg->local_info;
	rpi = &lagg->peer_info;

	r_state = rpi->lip_state;

	if (!(r_state & LACP_STATE_ACTIVITY)) {
		DBG("Partner closed.\n");
		exit(0);
	}

	if (lagg->state != lpi->lip_state) {
		DBG("Partner flag inconsistent pkt%u local%u\n",
		    lpi->lip_state, lagg->state);
		lpi->lip_state = lagg->state;
		return (SLOWPROTOCOLS_SUBTYPE_LACP);
	}

	if (!(lagg->state & LACP_STATE_SYNC)) {
		DBG("Tell partner SYNC\n");
		lagg->state |= LACP_STATE_SYNC;
		lagg->state |= LACP_STATE_COLLECTING;
		lagg->state |= LACP_STATE_DISTRIBUTING;
		lpi->lip_state = lagg->state;
		return (SLOWPROTOCOLS_SUBTYPE_LACP);
	}

	if ((r_state & LACP_STATE_SYNC) && !(r_state & LACP_STATE_COLLECTING)) {
		DBG("Tell partner Collecting\n");
		lagg->state |= LACP_STATE_COLLECTING;
		lpi->lip_state = lagg->state;
		return (SLOWPROTOCOLS_SUBTYPE_LACP);
	}

	if ((r_state & LACP_STATE_SYNC) && (r_state & LACP_STATE_COLLECTING) &&
	    (r_state & LACP_STATE_DISTRIBUTING)) {
		if (lagg->marker_ts_id == 0) {
			return (SLOWPROTOCOLS_SUBTYPE_MARKER);
		} else {
			return (SLOWPROTOCOLS_SUBTYPE_LACP);
		}
	}

	return (0);
}

static void
lagg_input(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	uint32_t len;
	uint16_t frame_type;
	struct lagg *lagg;
	struct lacpdu *ldu;
	struct markerdu *mdu;
	struct slowprothdr *sp_hdr;
	struct ether_header *eth_hdr;

	assert(h->len >= sizeof(struct ether_header));

	lagg = (struct lagg *)user;

	eth_hdr = (struct ether_header *)p;
	len = h->len;
	frame_type = ntohs(eth_hdr->ether_type);

	switch (frame_type) {
	case ETHER_TYPE_SLOWPROTO:
		sp_hdr = (struct slowprothdr *)(eth_hdr + 1);
		switch (sp_hdr->sph_subtype) {
		case SLOWPROTOCOLS_SUBTYPE_LACP:
			DBG("LACP packet size %d, local struct type %d",
			    len, sizeof(struct lacpdu));
			//assert(len == sizeof(struct lacpdu));

			ldu = (struct lacpdu *)p;
			lagg_lacp_input(lagg, ldu);
			break;
		case SLOWPROTOCOLS_SUBTYPE_MARKER:
			DBG("Marker packet size %d, local struct type %d",
			    len, sizeof(struct markerdu));
			//assert(len == sizeof(struct markerdu));

			mdu = (struct markerdu *)p;
			lagg_marker_input(lagg, mdu);
			break;
		default:
			DBG("Bad slowproto header.\n");
			break;
		}
		break;
	default:
		return;
	}
}

static int
lagg_lacp_init(struct lagg *lagg)
{
	int error;
	struct lacp_peerinfo *li, *pi;

	li = &lagg->local_info;

	li->lip_systemid.lsi_prio = htons(32768);
	memcpy(&li->lip_systemid.lsi_mac, lagg->local_mac, ETHER_ADDR_LEN);
	li->lip_key = htons(lagg->key);
	li->lip_portid.lpi_prio = htons(32768);
	li->lip_portid.lpi_portno = htons(rand() % 0x10000);
	if (lagg->initiator) {
		li->lip_state = LACP_STATE_ACTIVITY | 
			LACP_STATE_AGGREGATION | LACP_STATE_EXPIRED;
	} else {
		li->lip_state = LACP_STATE_ACTIVITY | LACP_STATE_AGGREGATION | 
				LACP_STATE_SYNC | LACP_STATE_COLLECTING;
	}

	lagg->state = li->lip_state;

	pi = &lagg->peer_info;
	if (lagg->initiator) {
		pi->lip_state = LACP_STATE_TIMEOUT;
	} else {
		pi->lip_state = LACP_STATE_ACTIVITY | LACP_STATE_AGGREGATION | 
				LACP_STATE_SYNC | LACP_STATE_COLLECTING | 
				LACP_STATE_DISTRIBUTING;
	}

	error = lagg_lacpdu_send(lagg);
	if (error) {
		DBG("Failed to send lacp init du.\n");
		return (error);
	}
	
	lagg->ntt = 1;
	lagg->marker_ts_id = 0;

	return (0);
}

static int 
lagg_marker_send(struct lagg *lagg)
{
	int error;
	struct markerdu mdu;
	struct lacp_peerinfo *li;

	li = &lagg->local_info;

	mdu.mdu_eh.ether_type = htons(ETHER_TYPE_SLOWPROTO);

	mdu.mdu_sph.sph_subtype = SLOWPROTOCOLS_SUBTYPE_MARKER;
	mdu.mdu_sph.sph_version = 0x1;

	TLV_SET(&mdu.mdu_tlv, MARKER_TYPE_INFO, sizeof(mdu.mdu_info));
	mdu.mdu_info.mi_rq_port = li->lip_portid.lpi_portno;
	memcpy(mdu.mdu_info.mi_rq_system, lagg->local_mac, ETHER_ADDR_LEN);

	mdu.mdu_info.mi_rq_xid = htonl(++(lagg->marker_ts_id));
	mdu.mdu_info.mi_pad[0] = 0;
	mdu.mdu_info.mi_pad[1] = 0;

	memset(&mdu.mdu_tlv_term, 0, sizeof(mdu.mdu_tlv_term));
	memset(&mdu.mdu_resv, 0, sizeof(mdu.mdu_resv));

	error = ether_send(lagg->handle, (u_char *)&mdu, sizeof(struct markerdu),
		    lagg->local_mac, ethermulticastaddr_slowprotocols);
	if (error) {
		DBG("Failed to lacp init du.\n");
		return (error);
	}
}

static int 
lagg_lacpdu_send(struct lagg *lagg)
{
	int error;
	struct lacp_peerinfo *li, *pi;
	struct lacpdu ldu;

	li = &lagg->local_info;
	pi = &lagg->peer_info;

	ldu.ldu_eh.ether_type = htons(ETHER_TYPE_SLOWPROTO);

	ldu.ldu_sph.sph_subtype = SLOWPROTOCOLS_SUBTYPE_LACP;
	ldu.ldu_sph.sph_version = 0x1;

	TLV_SET(&ldu.ldu_tlv_actor, LACP_TYPE_ACTORINFO, sizeof(ldu.ldu_actor));
	memcpy(&ldu.ldu_actor, li, sizeof(ldu.ldu_actor));

	ldu.ldu_actor.lip_state = lagg->state;

	TLV_SET(&ldu.ldu_tlv_partner, LACP_TYPE_PARTNERINFO, sizeof(ldu.ldu_partner));
	memcpy(&ldu.ldu_partner, pi, sizeof(ldu.ldu_partner));

	TLV_SET(&ldu.ldu_tlv_collector, LACP_TYPE_COLLECTORINFO, 
		    sizeof(ldu.ldu_collector));
	memset(&ldu.ldu_collector, 0, sizeof(ldu.ldu_collector));
	memset(&ldu.ldu_tlv_term, 0, sizeof(ldu.ldu_tlv_term));
	memset(&ldu.ldu_resv, 0, 54);
	
	// send
	error = ether_send(lagg->handle, (u_char *)&ldu, sizeof(struct lacpdu),
		    lagg->local_mac, ethermulticastaddr_slowprotocols);
	if (error) {
		DBG("Failed to lacp init du.\n");
		return (error);
	}

	lagg->state &= ~LACP_STATE_EXPIRED;
	
	return (0);
}

static int
ether_send(pcap_t *handle, const u_char *p, int len, uint8_t *src, uint8_t *dst)
{
	int error;
	char *errp;

	if (len < ETHER_ADDR_LEN * 2 + 2) {
		DBG("Bad ether packet.\n");
		return (-1);
	}

	if (src != NULL)
		memcpy(p, dst, ETHER_ADDR_LEN);
	if (dst != NULL)
		memcpy(p + ETHER_ADDR_LEN, src, ETHER_ADDR_LEN);

	error = pcap_sendpacket(handle, p, len); 
	if (error) {
		errp = pcap_geterr(handle);
		DBG("Bad ether send. %s\n", errp);
		return (-1);
	}

	DBG("Ether send %d\n", len);

	return (0);
}

void
lagg_ev_cb(EV_P_ ev_io *w, int revents)
{
	struct lagg_ev_io *lei;
	struct lagg *lagg;

	DBG("Ether frame received.\n");
	lei = (struct lagg_ev_io *)w;
	lagg = lei->lagg;
	
	pcap_dispatch(lagg->handle, 0, lagg_input, (u_char *)lagg);
}


