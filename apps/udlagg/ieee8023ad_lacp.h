#ifndef IEEE8023AD_LACP_H_
#define IEEE8023AD_LACP_H_

#define	ETHER_ADDR_LEN		6
#define	ETHER_TYPE_SLOWPROTO	0x8809

#define	SLOWPROTOCOLS_SUBTYPE_LACP	1
#define	SLOWPROTOCOLS_SUBTYPE_MARKER	2

#define	MARKER_TYPE_INFO	0x01
#define	MARKER_TYPE_RESPONSE	0x02

#define	LACP_TYPE_ACTORINFO	1
#define	LACP_TYPE_PARTNERINFO	2
#define	LACP_TYPE_COLLECTORINFO	3

#define	LACP_STATE_ACTIVITY	(1<<0)
#define	LACP_STATE_TIMEOUT	(1<<1)
#define	LACP_STATE_AGGREGATION	(1<<2)
#define	LACP_STATE_SYNC		(1<<3)
#define	LACP_STATE_COLLECTING	(1<<4)
#define	LACP_STATE_DISTRIBUTING	(1<<5)
#define	LACP_STATE_DEFAULTED	(1<<6)
#define	LACP_STATE_EXPIRED	(1<<7)

#define	TLV_SET(tlv, type, length) \
do { \
	(tlv)->tlv_type = (type); \
	(tlv)->tlv_length = sizeof(*tlv) + (length); \
} while (/*CONSTCOND*/0)

struct ether_header {
	u_char	    ether_dhost[ETHER_ADDR_LEN];
	u_char	    ether_shost[ETHER_ADDR_LEN];
	u_short	    ether_type;
} __packed;

struct slowprothdr {
	uint8_t	    sph_subtype;
	uint8_t	    sph_version;
} __packed;

struct tlvhdr {
	uint8_t	    tlv_type;
	uint8_t	    tlv_length;
} __packed;

struct lacp_systemid {
	uint16_t    lsi_prio;
	uint8_t	    lsi_mac[6];
} __packed;

struct lacp_portid {
	uint16_t    lpi_prio;
	uint16_t    lpi_portno;
} __packed;

struct lacp_peerinfo {
	struct lacp_systemid    lip_systemid;
	uint16_t		lip_key;
	struct lacp_portid	lip_portid;
	uint8_t			lip_state;
	uint8_t			lip_resv[3];
} __packed;

struct lacp_collectorinfo {
	uint16_t    lci_maxdelay;
	uint8_t	    lci_resv[12];
} __packed;

struct lacpdu {
	struct ether_header	    ldu_eh;
	struct slowprothdr	    ldu_sph;

	struct tlvhdr		    ldu_tlv_actor;
	struct lacp_peerinfo	    ldu_actor;
	struct tlvhdr		    ldu_tlv_partner;
	struct lacp_peerinfo	    ldu_partner;
	struct tlvhdr		    ldu_tlv_collector;
	struct lacp_collectorinfo   ldu_collector;
	struct tlvhdr		    ldu_tlv_term;
	uint8_t			    ldu_resv[50];
	uint8_t			    fcs[4];
} __packed;

struct lacp_markerinfo {
	uint16_t    mi_rq_port;
	uint8_t	    mi_rq_system[ETHER_ADDR_LEN];
	uint32_t    mi_rq_xid;
	uint8_t	    mi_pad[2];
} __packed;

struct markerdu {
	struct ether_header	mdu_eh;
	struct slowprothdr	mdu_sph;

	struct tlvhdr		mdu_tlv;
	struct lacp_markerinfo  mdu_info;
	struct tlvhdr		mdu_tlv_term;
	uint8_t			mdu_resv[90];
} __packed;


#endif
