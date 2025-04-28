/*
 *
 * tcp_migration.h
 *
 *
 *
 */
#ifndef _TCP_MIGRATION_H_
#define _TCP_MIGRATION_H_

#ifdef _KERNEL

#include <netinet/tcp_migration_var.h>

#define TM_MAGIC 1934279058

#define SMG_REXMT_THRES		16
/* If buffered_size >= RWND * FACTOR, then we set the throttle flag */
#define SMG_THROTTLE_FACTOR	2
#define SMG_GARBAGE_FACTOR	SMG_THROTTLE_FACTOR + 2

/* Defs: Internal types for logging */
#define SMGLOG_INFO		0
#define SMGLOG_DEBUG		1

#define SMGLOG_NOP		0
#define SMGLOG_GENERAL		1
#define SMGLOG_CURR		2   /* Current debugging */
#define SMGLOG_TCP		3   /* TCP Events */
#define SMGLOG_SOMIG		4   /* SOMIG Events */
#define SMGLOG_MBUFOP		5   /* Mbuf OPs */
#define SMGLOG_PEERCOMMU	6   /* Pkt info flow between nodes */

/* TOGGLES: all debugging features in SOMIG */
#define SMGDEBUG 0

#define SMGLOG 1	/* LOGPRINT enabled */
#define SMGMBUFLOG 0	/* Mbuf print in LOGPRINT enabled */

static const int SMGLOG_SW[] = {
	0,	//KEEP 0 FOR THIS 
	0,	//SMGLOG_GENERAL
	1,	//SMGLOG_CURR
	1,	//SMGLOG_TCP
	0,	//SMGLOG_SOMIG
	0,	//SMGLOG_MBUFOP
	0	//SMGLOG_PEERCOMMU
};

#define INFOPRINT(...) \
    somig_logprint(SMGLOG_INFO, 0, __func__, __LINE__, NULL, __VA_ARGS__)

#define LOGPRINT(st, ...) \
    somig_logprint(SMGLOG_DEBUG, (st), __func__, __LINE__, NULL, __VA_ARGS__) 
#define LOGPRINTM(st, m, ...) \
    somig_logprint(SMGLOG_DEBUG, (st), __func__, __LINE__, (m), __VA_ARGS__) 

#define INSTANT_ACK_BEGIN(t) (t)->instant_ack_delivery = 1
#define INSTANT_ACK_END(t) (t)->instant_ack_delivery = 0
#define INSTANT_ACK(t) ((t)->instant_ack_delivery == 1)

#define CONTINUOUS_PACKET_BEGIN(t) (t)->continuous_packet_delivery = 1
#define CONTINUOUS_PACKET_END(t) (t)->continuous_packet_delivery = 0
#define CONTINUOUS_PACKET(t) ((t)->continuous_packet_delivery == 1)

#define FLUSH_PACKET_BEGIN(t) (t)->flushpkt = 1
#define FLUSH_PACKET_END(t) (t)->flushpkt = 0
#define FLUSH_PACKET(t) ((t)->flushpkt == 1)



/* Header Protocol:
 * cmd field + status field
 *	To send a request: cmd(any) + status(NULL)
 *	To reply: cmd(original) + status(any but NULL)
 */

/*
 * Operation defs for so role change
 */
#define	TM_PROMOTE		0 
#define	TM_DEMOTE		1
#define	TM_UPDATE		2 /* Update peer role only */

/*
 * Defs for somig struct type
 */
#define	TM_STURCT_TMVER		0
#define	TM_STRUCT_TMNODE	1
#define	TM_STRUCT_TMHDR		2
#define	TM_STRUCT_TMSTATE	3

/*
 * Defs for tcpmig_send send type
 */
#define	TM_SEND_SINGLE		0
#define	TM_SEND_BCAST		1

#define TM_PKT_BUFFER		0
#define TM_PKT_SENDNOW		1

/*
 * Flags used in PPSHDR (bit)
 */
#define	TM_FLAG_THROTTLE	0x1
#define	TM_FLAG_HEARTBEAT	0x2
#define	TM_FLAG_DONTACK		0x4

/*
 * Flags used in TMMIGRATION
 *
 */
#define	TM_MIGRATION_FLAG_LB			0x00000001
#define	TM_MIGRATION_FLAG_FAIL			0x00000002
#define	TM_MIGRATION_FLAG_OLD_KINGS_DEAD	0x10000000

/*
 * Error codes used in SOMIG
 */
#define	TM_ERR_UNKNOWN		900
#define	TM_ERR_OVERLOAD		901

/*
 * Falling behind maximum
 */
#define	TM_FALLBEHIND_MAXIMUM	0x7fffffff

/*
 * Packet size threshold for applying the m_copypacket optimiation
 */
#define	TM_FRAG_OPTIMIZATION_THRESH 9000

/*
 * The factor for calculating the space left in PRIMARY's congestion window   
 */
#ifdef SOMIG_DYNAMIC_CWND
#define TM_DYNAMIC_CWND_FACTOR		2
#endif

extern struct somig_func so_mig_func;
extern int SOMIG_TIME_TEST_LOG;

/*
 * Migration version struct (verctl) 
 * Used only in handshake period.
 */
struct tmver {
	uint16_t major;
	uint16_t minor;
	uint32_t feature;
};

/*
 * Migration node info 
 * Used mostly in handshake period.
 * Note: For now, this is used 100% during HS
 */
struct tmnode {
	uint8_t id;
	uint8_t role; 
#ifdef SMCP
	uint16_t p_port;	/* Used only in JOIN msg */
	uint32_t p_addr;	/* Used only in JOIN msg */
#else
	uint16_t port;
#endif
	uint32_t ip;
};


/*
 * Per-packet status header. 32bytes
 * This includes:
 *	[Primary/Replica]
 *	    flag
 *	[(to) Primary ONLY]
 *	    seq,		(A)
 *	    rcv_nxt,
 *	    snd_max,
 *	    buf_size
 *	[(to) Replica ONLY]
 *	    rwnd,		(A)
 *	    ts_recent,
 *	    ts_recent_age
 *
 */
struct ppshdr {
	uint32_t flag;
	union {
		uint32_t seq;		// (A) Primary
		uint32_t rwnd;		// (A) Replica
	};
	uint32_t rcv_nxt;
	uint32_t snd_max;
	uint32_t snd_off;		// offset of sequence number (e.g non-deterministic wnd upd)
	uint32_t snd_cwnd;
	uint32_t ts_recent;
	uint32_t ts_recent_age;
	uint32_t buf_size;
	uint32_t pri_ts;
};

/*
 * Internal states struct
 * Includes socket + tcp
 */
struct tmstate {
	in_addr_t laddr;
	in_addr_t faddr;
	u_int16_t lport;
	u_int16_t fport;
	
	u_int32_t ts_offset;		/* our timestamp offset */
	u_int32_t ts;
	u_int32_t ts_ecr;

	tcp_seq	snd_una;		/* sent but unacknowledged */
	tcp_seq	snd_max;		/* highest sequence number sent;
					 * used to recognize retransmits
					 */
	tcp_seq	snd_nxt;		/* send next */
	tcp_seq	snd_up;			/* send urgent pointer */
	tcp_seq	last_ack_sent;
	tcp_seq	rcv_up;			/* receive urgent pointer */
	tcp_seq	rcv_nxt;		/* receive next */
	tcp_seq	rcv_adv;		/* advertised window */
	unsigned char	request_r_scale;/* pending window scaling */
	tcp_seq	snd_wl1;		/* window update seg seq number */
	tcp_seq	snd_wl2;		/* window update seg ack number */
	tcp_seq	irs;			/* initial receive sequence number */
	tcp_seq	iss;		        /* initial send sequence number */
	uint32_t rcv_wnd;		/* receive window */
	uint32_t snd_wnd;		/* send window */
	uint32_t snd_cwnd;		/* congestion-controlled window */

	int	t_state;		/* TCP fsm state */
};

struct tmmigration {
	uint32_t flag;
};

#define SOISPRIMARY(so) (so->so_mig_role == SOMIG_PRIMARY)
#define SOISREPLICA(so) (so->so_mig_role == SOMIG_REPLICA)
#define ISSOCONNECTED(so) (so->so_state & SS_ISCONNECTED)

#define SOMIG_PKT_ENTRY_INIT(p, m, o, g, s, t, dh, tl, tp, d, pt) do {	\
	(p)->m = (m);						\
	(p)->offp = (o);					\
	(p)->gack = (g);					\
	(p)->seq = (s);						\
	(p)->thflags = (t);					\
	(p)->drop_hdrlen = (dh);				\
	(p)->tlen = (tl);					\
	(p)->sent = 0;						\
	(p)->flag = 0;						\
	(p)->port = pt;						\
	(p)->data = ((caddr_t)(d));				\
	(p)->rej_count = 0;					\
} while (0)
    
#define PKTSYN(t) (((t) & (TH_SYN | TH_ACK)) == TH_SYN)
#define PKTACK(t) (((t) & (TH_SYN | TH_ACK | TH_PUSH)) == TH_ACK)
#define PKTPUSHACK(t) (((t) & (TH_SYN | TH_ACK | TH_PUSH)) == (TH_ACK | TH_PUSH))
#define PKTSYNACK(t) (((t) & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
#define PKTFIN(t) ((t) & TH_FIN)
#define PKTRST(t) ((t) & TH_RST)

#ifdef SMCP
void tcpmig_ctlinput(struct mbuf *m, void *smcp, int *drop_hdrlen, int tlen);
void tcpmig_flushpkt_migration(void *, int);
int tcpmig_nodeconnect(struct socket *hso, struct tmnode *node, uint32_t, uint16_t, uint32_t);
void tcpmig_setstates(struct socket *so, void *, struct tmstate *tms, int init);

int tcpmig_sendreply_m(void *, int type, int status, struct mbuf *mp);
#else
void tcpmig_ctlinput(struct mbuf *m, struct tcpcb *tp, struct inpcb* inp, 
    int *drop_hdrlen, int tlen);
void tcpmig_flushpkt_migration(struct socket *so, int migration);
int tcpmig_nodeconnect(struct socket *hso, struct tmnode *node);
void tcpmig_setstates(struct socket *so, struct socket *ctl_so, 
    struct tmstate *tms, int init);

int tcpmig_sendreply_m(struct socket *so, int type, int status, struct mbuf *mp);
#endif
int tcpmig_output(struct mbuf *m, struct tcpcb *tp); 

void tcpmig_pktinput(struct mbuf *m, struct socket *so, int *offp, uint32_t seq, 
    int thflags, int drop_hdrlen, int tlen, struct somig_pkt_data_syn *syndata, 
    uint32_t flag, uint16_t port);
/*
void tcpmig_pktinput(struct mbuf *m, struct somig_pkt_entry *smpe, 
    struct inpcb *inp, int drop_hdrlen, int tlen); 
*/

void tcpmig_syncache_respond(struct somig_pkt_data_syn *data);
int tcpmig_pktstate_check(struct somig_pkt_entry *pkt, struct tcpcb *tp);

/*
 * Utility functions
 */
void tcpmig_spetotn(struct somig_peer_entry *peer, struct tmnode *node, int self);
void tcpmig_getstates(struct socket *so, struct tmstate *tms);

void tcpmig_cksum(struct mbuf *m, struct ip *ip, struct tcphdr *th);
void tcpmig_strippld(struct mbuf *m, int pld_size);

void tcpmig_flushpkt(struct socket *so);
void tcpmig_flushpkt_timo(struct socket *so);
void tcpmig_flushpkt_continuous(struct socket *so, int output_len);

void tcpmig_rolechange_done(struct socket *so);

#ifdef SOMIG_FASTMIG
void tcpmig_add_ifa(struct ifnet *ifp, uint32_t addr); 
#endif

/*
 * Used in TCP stack
 */
void tcpmig_ipinput(struct somig_pkt_entry *pkt, struct socket *hso);
struct mbuf *	tcpmig_compose_tcp_ack(struct socket *so); 
int	tcpmig_need_tcp_ack(struct socket *so);
void	tcpmig_direct_ip_input(struct mbuf *m, struct tcpcb *tp);

/*
 * Used in Carp
 */
#define CARP_CHANGING_IN_PROGRESS	0
#define CARP_CHANGING_DONE		1
void tcpmig_carp_master_down_callback(struct ifaddr **, int, int);

/*
 * Helpers 
 */
struct mbuf *	tcpmig_m_rearrange(struct mbuf *, int);
void somig_logprint(int type, int subtype, const char *func, 
    int line, struct mbuf *m, ...);
static __inline void MBUFPRINT(struct mbuf *m);
static __inline void INCPRINT(struct in_conninfo *inc);

static __inline void
INCPRINT(struct in_conninfo *inc)
{
	if (inc == NULL) 
		return;

	printf("======in_conninfo @ %p\n", inc);
	printf("inc_flags %u | inc_len %u | inc_fibnum %u\n", inc->inc_flags,
	    inc->inc_len, inc->inc_fibnum);
	printf("in_endpoints: la: %u lp: %u, fa: %u, fp: %u\n",	
	    inc->inc_laddr.s_addr, inc->inc_lport, 
	    inc->inc_faddr.s_addr, inc->inc_fport);
	printf("========================\n");
}

static __inline void
TPPRINT(struct tcpcb *tp)
{
	if (tp == NULL) 
		return;

	printf("======tcpcb @ %p\n", tp);
	printf("rcv_wnd %u\n", tp->rcv_wnd);
	printf("rcv_nxt %u\n", tp->rcv_nxt);
	printf("rcv_adv %u\n", tp->rcv_adv);
	printf("snd_max %u\n", tp->snd_max);
	printf("========================\n");
}


#endif

#endif
