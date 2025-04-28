/*
 * tcp_migration.c
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#ifdef SOMIG_FASTMIG
#include <sys/rmlock.h>
#endif

#include <net/vnet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet/in_fib.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <net/route/nhop.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_carp.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_fastopen.h>
#include <netinet/tcp_offload.h>
#include <netinet/tcp_syncache.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_migration.h>
#include <netinet/cc/cc.h>
#ifdef SOMIG_FASTMIG
#include <netinet/if_ether.h>
#endif

#ifdef SOMIG_TASKQUEUE
#include <sys/kthread.h>
#endif
#ifdef SMCP
#include <netinet/smcp.h>
#endif

#include <machine/stdarg.h>
#include <machine/in_cksum.h>

#define TCPMIG_INTERNAL		0x0
#define TCPMIG_UIPC_SOCKET	0x1

#define TCPMIG_CARP_ADJ		100

static void	tcpmig_compose_migration_packet(struct mbuf *m, int flag);
static int	tcpmig_pktinput_internal(struct mbuf *m, 
		    struct somig_pkt_entry *smpe, struct inpcb *inp, 
		    int drop_hdrlen, int tlen, int flag);
static int	tcpmig_bcast(struct mbuf *m, struct tcpcb *tp);
static int	tcpmig_bcast_internal(struct mbuf *m, struct tcpcb *tp, int flag);

#ifdef SMCP
static void	tcpmig_replica_send_ack(struct smcpcb *, struct socket *hso, 
		    uint32_t flag, uint32_t seq, uint32_t pri_ts);
static void	tcpmig_senddrop(struct mbuf *m, struct smcpcb *);

static int	tcpmig_send(struct mbuf *m, struct smcpcb *);
static int	tcpmig_send_internal(struct mbuf *m, struct smcpcb *, int);

static int	tcpmig_soconnect(void *smcp, uint16_t v_major, uint16_t v_minor, 
		    uint32_t v_feature);
static int	tcpmig_sosync(void *smcp);
static int	tcpmig_ctlinput_packet(struct smcpcb *, struct mbuf *m0, 
		    int status, int tlen);
static void	tcpmig_flushpkt_internal(struct smcpcb *, int *acc, int *rej, 
		    int skip_sent);
static struct tcphdr *	tcpmig_updatehdr_addr(struct mbuf *m0, struct smcpcb *, 
		    struct socket *ctlso, int len, int *tlen);
static int	tcpmig_sendcmd(struct smcpcb *, int mode, int type, ...);
static int	tcpmig_somigrate(void *, uint32_t flag, uint32_t who);
static int	tcpmig_newsmcpcb(void **, void *);
#else
static void	tcpmig_replica_send_ack(struct socket *so, struct socket *hso, 
		    uint32_t flag, uint32_t seq, uint32_t pri_ts);
static void	tcpmig_senddrop(struct mbuf *m, struct tcpcb *tp);

static int	tcpmig_send(struct mbuf *m, struct tcpcb *);
static int	tcpmig_send_internal(struct mbuf *m, struct tcpcb *, int);

static int	tcpmig_soconnect(struct socket *so, uint16_t v_major, 
		    uint16_t v_minor, uint32_t v_feature);
static int	tcpmig_sosync(struct socket *so);
static int	tcpmig_ctlinput_packet(struct socket *so, struct mbuf *m0, 
		    int status, int tlen);
static void	tcpmig_flushpkt_internal(struct socket *so, int*, int*, int);
static struct tcphdr *	tcpmig_updatehdr_addr(struct mbuf *m0, struct socket *so, 
		    struct socket *ctlso, int len, int *tlen);
static int	tcpmig_sendcmd(struct socket *so, int mode, int type, ...);
static int	tcpmig_somigrate(struct socket *so, uint32_t flag, uint32_t who);
#endif
static int	tcpmig_sojoin(struct socket *head, struct socket *so, int role);
static int	tcpmig_sodisconnect(struct socket *so);
static int	tcpmig_soupdateoptions(struct socket *so);
static int	tcpmig_getaddrtuple(struct socket *so, struct sockaddr *sa,
		    int which);

static int	tcpmig_fragdup(struct mbuf *m, struct mbuf **n, int off, int len, 
		    int tlen, int first);
static void	tcpmig_updaterole(struct socket *hso, 
		    struct somig_peer_entry *new, struct somig_peer_entry *old, 
		    int op);
static void	tcpmig_updatecb(struct socket *hso);
static void	tcpmig_updatestate(struct tcpcb *tp, struct socket *so, struct ppshdr *ppsh);
static void	tcpmig_updatets(struct tcpcb *tp, u_char *cp, int cnt, 
		    struct ppshdr *ppsh);
static struct tcphdr *	tcpmig_updatehdr_tcp(struct mbuf *m0, struct socket *so,
		    int tlen);
static void	tcpmig_updatehdr_tcp_off(struct somig_pkt_entry *pkt, struct tcpcb *tp);
static struct mbuf *	tcpmig_mbuf_somigize(struct mbuf *m, struct mbuf *m0);
static void	tcpmig_mbuf_desomig(struct mbuf *m);

static void	tcpmig_getcb(struct socket *so, void *buf, int buf_len, 
		    int who, int *len);
static int	tcpmig_get_livepeer_count(struct socket *so);
#ifdef SOMIG_FASTMIG
static void	tcpmig_if_down(struct socket *so);
static void	tcpmig_if_promote(struct ifnet *ifp, struct ifaddr *ifa );
#endif
#ifndef SMCP
static int	tcpmig_sendreply(struct socket *so, int type, int status);
#endif

static struct mbuf *	tcpmig_m_fixhdr(struct mbuf *m, struct socket *so, int len);
static void	tcpmig_m_catpkt(struct mbuf **m, struct mbuf *n, struct socket *so);

static struct mbuf *	tcpmig_m_extract_ack(struct mbuf *m, int pld_len, 
		    int fix_cksum, int update_th, uint32_t new_seq, uint32_t new_ack);
static uint32_t		tcpmig_find_next_ack(struct socket *so, uint32_t orig_ack);
static struct mbuf *	tcpmig_compose_tcpip_pkt(uint32_t ip_src, uint32_t ip_dst, 
		    uint16_t port_src, uint16_t port_dst, uint8_t th_flag, uint32_t seq, 
		    uint32_t ack, uint16_t th_win, struct mbuf *pld, int tlen, 
		    struct ifnet *ifn, struct socket *so, int cksum);
static inline int	tcpmig_need_throttle(struct ppshdr *ppsh, struct tcpcb *tp);

#ifdef SOMIG_TASKQUEUE
static void	tcpmig_tcp_bcast_task(void *s);
#endif

#ifdef SOMIG_TIMING_DIAG
static void	somig_timing_bucket_add(struct socket *so, uint32_t time);
static uint32_t timing_bucket[SOMIG_TIMING_BUCKET_COUNT];
uint32_t	stime_from_mso; 
#endif

static int	TCPMIG_INC_PACKET = 0;
int		SOMIG_TIME_TEST_LOG = 0;
/*
 * Clean the mbuf chain to remove all (m_len = 0) mbuf chunks, plus,
 * rearrange all mbufs to make sure each packet header is in a contiguous memory
 * region that allows mtod access.
 */
struct mbuf *
tcpmig_m_rearrange(struct mbuf *m0, int len)
{
	struct mbuf *m, *first, *prev;
	int size = 0;

	/*
	 * Skip leading empty mbufs to find head.
	 * XXX: Potential MEM leak here. (Does it really necessary to have this)
	 */
	m = m0;
	while (m != NULL && m->m_len == 0) {
		m = m_free(m);
	}
	
	if (m != NULL)
		first = m;
	else {
		LOGPRINT(SMGLOG_MBUFOP, "Null mbuf chain\n");
		return (m0);
	}
	
	if (m == NULL)
		return (m0);

	/*
	 * Remove all empty mbufs in the chain
	 */
	prev = m;
	while (m) {
		if (m->m_len == 0) {
			m = m_free(m);
			prev->m_next = m;
		} else {
			prev = m;
			m = m->m_next;
		}
	}

	if (len >= sizeof(struct tmhdr))
		size = sizeof(struct tmhdr);
	if (len >= size + sizeof (struct ppshdr))
		size += sizeof(struct ppshdr);
	if (len >= size + sizeof(struct ip) + sizeof(struct tcphdr)) 
		size += sizeof(struct ip) + sizeof(struct tcphdr);

	size = min(size, m_length(first, NULL));

	if (size > 0 && first->m_len < size)
		first = m_pullup(first, size);
	return (first);
}

/*
 * tcpmig_ctlinput
 * Extract tcpmig header from mbuf
 * Based on header, this function consumes this mbuf
 *
 */
//void __attribute__((optnone))
void
#ifdef SMCP
tcpmig_ctlinput(struct mbuf *m0, void *smcpcb, int *drop_hdrlen, int tlen)
#else
tcpmig_ctlinput(struct mbuf *m0, struct tcpcb *tp, struct inpcb* inp, 
    int *drop_hdrlen, int tlen)
#endif
{
	char			*off, *roff;
	int			size, msize, len = 0, exlen, peeridx, error;
	int			remainder = 0;
	int			rt_status, op;
	uint16_t		flags, status;//, plen;
	struct mbuf		*peerm = NULL, *m = NULL;
	struct mbuf		*ack_m;
	struct tmnode		*tmpeer, *tmn;
	struct tmstate		*tms;
	struct tmhdr		*tmth, *tmthp;
	struct tmver		*tmv, *tmvp;
	struct socket		*so = NULL;
	struct socket		*incomp_so = NULL;
	struct socket		*hso = NULL;
	struct somig_peer_entry *peer, *chkpr;
	struct tcpcb		*htp;
	struct mbuf		*next_m = NULL;
	struct tmmigration	*tmmig;
	struct in_ifaddr	*ia;
	struct sockaddr_in	*sa;
#ifdef SMCP
	struct smcpcb		*new_smcp, *smcp;
#endif
	
	/*
	 * TODO: 0 might means we got TH_FIN on CtlSo. If that's the case
	 *	we need to check if HSO got the FIN or we compose a FIN.
	 */
	if (tlen == 0) {
		return;
	}

#ifdef SMCP
	smcp = smcpcb;

	KASSERT(smcp->inp != NULL, ("%s: inp == NULL", __func__));
	so = smcp->inp->inp_socket;
#else
	so = inp->inp_socket;
#endif
	KASSERT(so != NULL, ("%s: so == NULL", __func__));
#ifdef SMCP
	hso = so;
#else
	hso = so->so_mig_hostso;
#endif

	m = m0;

	/*
	 * Fix the header if its missing.
	 * TODO: saw a null ptr (m), with giant tlen. 
	 */
	if (!(m->m_flags & M_PKTHDR)) {
		m = tcpmig_m_fixhdr(m, so, tlen);
	}
	
	/*
	 * If current mbuf size is equal to tlen, no need to rearrange.
	 */
	if (m->m_len != tlen || m_length(m, NULL) != tlen)
		m = tcpmig_m_rearrange(m, tlen);

	off = mtod(m, char *);
	tmth = (struct tmhdr *)(off);
	
	/*
	 * It's hard to control TCP not buffering our packet. 
	 * So if we receive a packet and the size of payload is
	 * smaller than the exlen indicated in tmhdr,
	 * we then buffer this packet and wait for the next until 
	 * we got all of them.
	 */
	if (hso->so_mig_pending_m != NULL) {
		int new_tlen = tlen;
		struct tmhdr *prev_tmth; 
		char *prev_off;
		struct mbuf *tmp_m;
		
		if (hso->so_mig_pending_tlen + tlen < sizeof(struct tmhdr)) {
			tcpmig_m_catpkt(&hso->so_mig_pending_m, m, so);
			hso->so_mig_pending_tlen += tlen;
			return;
		}

		/*
		 * If we can get full tmhdr, compose it first.
		 */
		if (hso->so_mig_pending_tlen < sizeof(struct tmhdr)) {
			new_tlen = sizeof(struct tmhdr) - hso->so_mig_pending_tlen;
			tmp_m = m_split(m, new_tlen, M_NOWAIT);
			KASSERT(tmp_m != NULL, 
			    ("%s:%d: Bad mbuf", __func__, __LINE__));
			tcpmig_m_catpkt(&hso->so_mig_pending_m, m, so);
			hso->so_mig_pending_tlen = sizeof(struct tmhdr);
			m = tmp_m;
			new_tlen = tlen - new_tlen;
			hso->so_mig_pending_m = tcpmig_m_rearrange(
			    hso->so_mig_pending_m, sizeof(struct tmhdr));
		}
		
		prev_off = mtod(hso->so_mig_pending_m, char *);
		prev_tmth = (struct tmhdr *)prev_off;

		if (prev_tmth->magic != TM_MAGIC) {
			MBUFPRINT(hso->so_mig_pending_m);
			panic("Wrong TM_MAGIC");
		}
		/* 
		 * Check if current payload contains frags of prev packet 
		 */
//CTR4(KTR_SPARE5, "LINE %d pending_tlen %d, prev_tmth->len %d, savem %p\n", __LINE__, hso->so_mig_pending_tlen, prev_tmth->len,
//    hso->so_mig_pending_m);
		remainder = prev_tmth->len - hso->so_mig_pending_tlen;
		if (new_tlen <= remainder) {
//CTR4(KTR_SPARE5, "LINE %d new_tlen %d remainder %d, savem %p\n", __LINE__, new_tlen, remainder, hso->so_mig_pending_m);
			/*
			 * All payloads in current pkt belongs to prev
			 */
			tcpmig_m_catpkt(&hso->so_mig_pending_m, m, so);
			if (new_tlen == remainder) {
				next_m = hso->so_mig_pending_m;
				hso->so_mig_pending_m = NULL;
				hso->so_mig_pending_tlen = 0;
				KASSERT(next_m != NULL, 
				    ("%s:%d: Bad mbuf", __func__, __LINE__));
#ifdef SMCP
				tcpmig_ctlinput(next_m, smcp, drop_hdrlen, 
				    prev_tmth->len);
#else
				tcpmig_ctlinput(next_m, tp, inp, drop_hdrlen, 
				    prev_tmth->len);
#endif
			} else {
				hso->so_mig_pending_tlen += new_tlen;
prev_tmth = (struct tmhdr *)(mtod(hso->so_mig_pending_m, char *));
//CTR3(KTR_SPARE5, "LINE %d pending_tlen %d tmthlen %d\n", __LINE__, hso->so_mig_pending_tlen, prev_tmth->len);
if (prev_tmth->len != remainder + (hso->so_mig_pending_tlen - new_tlen)) {
    CTR4(KTR_SPARE5, "%p pending_tlen %d tmthlen %d newtl %d\n", 
	hso->so_mig_pending_m, hso->so_mig_pending_tlen, prev_tmth->len, new_tlen);
    panic("Check thtm len.");
}
				LOGPRINT(SMGLOG_MBUFOP, "Saving EXTRA, tlen %d, pendinglen %d\n", 
				    tlen, hso->so_mig_pending_tlen);
			}
		} else {
			/*
			 * This pkt contains extra.
			 * Split the current one and the extra one.
			 */
			next_m = m_split(m, remainder, M_NOWAIT);
			KASSERT(next_m != NULL, 
			    ("%s:%d: Bad mbuf", __func__, __LINE__));
			/*
			 * Merge and deliver the previous one 
			 */
			tcpmig_m_catpkt(&hso->so_mig_pending_m, m, so);
			m = hso->so_mig_pending_m;

			hso->so_mig_pending_m = NULL;
			hso->so_mig_pending_tlen = 0;
			KASSERT(m != NULL, 
			    ("%s:%d: Bad mbuf", __func__, __LINE__));
#ifdef SMCP
			tcpmig_ctlinput(m, smcp, drop_hdrlen, prev_tmth->len);
#else
			tcpmig_ctlinput(m, tp, inp, drop_hdrlen, prev_tmth->len);
#endif


			new_tlen = new_tlen - remainder;
			/* 
			 * We deliver the extra packet again 
			 */
			KASSERT(next_m != NULL, 
			    ("%s:%d: Bad mbuf", __func__, __LINE__));
#ifdef SMCP
			tcpmig_ctlinput(next_m, smcp, drop_hdrlen, new_tlen);
#else
			tcpmig_ctlinput(next_m, tp, inp, drop_hdrlen, new_tlen);
#endif
		}
		return;
	} 

	if (tlen < sizeof(struct tmhdr))
		goto incomp_pkt_save;

	if (tmth->magic != TM_MAGIC) {
		printf("[!!!]Wrong MAGIC in pkt tlen %d magic val %u tmth %p\n", 
		    tlen, tmth->magic, tmth);
		MBUFPRINT(m);
		m_freem(m);
		return;
	}

	KASSERT(tmth->magic == TM_MAGIC, ("Magic check failed\n"));

	flags = tmth->cmd;
	status = tmth->status;
	len = tmth->len;
	exlen = tmth->exlen;
	KASSERT(hso != NULL, ("Parent so is NULL\n"));

	if (len - tlen > 0) {
incomp_pkt_save:
		/* 
		 * This is an incomplete packet, store it 
		 */
		if (hso->so_mig_pending_m != NULL) {
			MBUFPRINT(hso->so_mig_pending_m);
			MBUFPRINT(m);
		}
		KASSERT(hso->so_mig_pending_m == NULL, ("Stored pkt existed"));
		if (hso->so_mig_pending_m != NULL)
			m_freem(hso->so_mig_pending_m);
		hso->so_mig_pending_m = m;
		hso->so_mig_pending_tlen = tlen;
		return;
	} else if (len - tlen < 0) {
		/* 
		 * This packet contains extra packet, deliver them seperately 
		 */
		remainder = tlen - len;
		next_m = m_split(m, len, M_NOWAIT);
		KASSERT(next_m != NULL, 
		    ("%s:%d: Bad mbuf", __func__, __LINE__));
	}

	/* 
	 * Find the corresponding CtlSo in HostSO peer list 
	 */
#ifdef SMCP
	chkpr = smcp->so_mig_pentry;
#else
	chkpr = so->so_mig_pentry;
#endif
	KASSERT(chkpr != NULL, ("Peer entry is NULL\n"));
	//KASSERT(tlen == tmth->len, ("Inconsistent length tlen %d, tmth %d\n", 
	//    tlen, tmth->len));
	
	switch (status) {
	case TM_STATUS_NULL:
		switch (flags) {
		/*
		 * Primary->Send back ok + tmver + nodelist
		 * Replica->Send back ok + tmver
		 */
		case TM_CMD_HANDSHAKE:
			rt_status = TM_STATUS_OK;
			KASSERT(((hso->so_mig_role == SOMIG_PRIMARY) ||
			    (hso->so_mig_role == SOMIG_REPLICA)), 
			    ("sotype: %d shouldn't receive HS.\n", 
			     hso->so_mig_role)); 
			//if (chkpr->state != SOMIG_SO_PENDING) {
			//	panic("TM_CMD_HANDSHAKE wrong pkt type");
			//	return;
			//}

#ifdef SMCP
			/*
			 * Create corresponding smcp for this new replica
			 */
			tcpmig_newsmcpcb((void **)&new_smcp, hso);
			new_smcp->so_mig_pentry = (struct somig_peer_entry *)malloc(
			    sizeof(struct somig_peer_entry), M_TEMP, 
			    M_NOWAIT | M_ZERO);
			new_smcp->so_mig_pentry->state = SOMIG_SO_PENDING; 
			new_smcp->so_mig_pentry->hso = hso;
			new_smcp->so_mig_pentry->role = SOMIG_REPLICA;
#endif
			
			tmv = (struct tmver *)(off + sizeof(struct tmhdr));
			tmn = (struct tmnode *)(off + sizeof(struct tmhdr) +
			    sizeof(struct tmver));

			/*
			 * If the HS is a replica join, then the ID is in the
			 * hdr. Otherwise its a fresh join on primary, we
			 * allocate the ID
			 */
			if (hso->so_mig_role == SOMIG_REPLICA) {
				if (tmn->id > hso->so_mig_id_seed) 
					hso->so_mig_id_seed = tmn->id + 1;
#ifdef SMCP
				new_smcp->so_mig_pentry->id = tmn->id;
				new_smcp->id = tmn->id;
				hso->so_mig_gack_full |= (1<<tmn->id); 
#else
				so->so_mig_pentry->id = tmn->id;
				so->so_mig_id = tmn->id;
				hso->so_mig_gack_full |= (1<<so->so_mig_id); 
#endif
			}
#ifdef SMCP	    
			else {
				new_smcp->id = somig_alloc_id(hso);
				new_smcp->so_mig_pentry->id = new_smcp->id;
			}
			
			/*
			 * At the point when receiving HS, we could init 
			 * smcpcb for this specific replica.
			 */
			new_smcp->l_addr = smcp->l_addr;
			smcp_bind((void *)new_smcp, 0, 0, smcp->l_addr, 1);

			new_smcp->f_addr = ntohl(tmn->ip);
			if (hso->so_mig_role == SOMIG_PRIMARY) {
				if (hso->so_options & SO_ACCEPTCONN) {
					new_smcp->r_addr = ntohl(sotoinpcb(hso)->inp_laddr.s_addr);
					new_smcp->r_port = ntohs(sotoinpcb(hso)->inp_lport);
				} else {
					new_smcp->r_addr = ntohl(sotoinpcb(hso)->inp_faddr.s_addr);
					new_smcp->r_port = ntohs(sotoinpcb(hso)->inp_fport);
				}
			} else {
				new_smcp->r_addr = smcp->r_addr;
				new_smcp->r_port = smcp->r_port;
			}
			new_smcp->so_mig_pentry->smcpcb = new_smcp;
			new_smcp->so_mig_pentry->ip = tmn->ip;

			somig_add_peer_to_hostso(hso, new_smcp->so_mig_pentry, 0); 
#else
			so->so_mig_pentry->ip = tmn->ip;
			so->so_mig_pentry->port = tmn->port;
#endif

			/* 
			 * Check size of the group 
			 */
			//SOCK_LOCK(hso);
			size = hso->so_mig_peer_size + 1;
			if (size - 1 >= SOMIG_MAXNODE) {
				rt_status = TM_STATUS_FULL;
				tmth->cmd = 0;
				tmth->status = TM_STATUS_FULL;
				SOCK_UNLOCK(hso);
				panic("Group full. TODO..\n");
				/* XXX send */
				/* XXX kick */
			}

			/* 
			 * Prepare mbuf for packet 
			 */
			msize = sizeof(struct tmhdr) + sizeof(struct tmver);
			if ((hso->so_mig_role == SOMIG_PRIMARY) && 
			    (rt_status == TM_STATUS_OK))
				msize += sizeof(struct tmnode) * size;
			peerm = m_getm2(NULL, msize, M_NOWAIT, MT_DATA, 0);
			peerm->m_len = msize;

			/* 
			 * Extract hdrs from allocated mbuf
			 */
			peeridx = 0;
			roff = mtod(peerm, char *);
			tmthp = (struct tmhdr *)roff;
			tmvp = (struct tmver *)(roff + sizeof(struct tmhdr));
			if (SOISPRIMARY(hso) && rt_status == TM_STATUS_OK) 
				tmpeer = (struct tmnode *)(roff + 
				    sizeof(struct tmhdr) +
				    sizeof(struct tmver));
			else
				goto node_done;
			
			/* 
			 * Add node info for this new replica 
			 * (at idx = 0)
			 */
#ifdef SMCP
			peer = new_smcp->so_mig_pentry;
#else
			peer = so->so_mig_pentry;
#endif
			tcpmig_spetotn(peer, tmpeer, 0);
			tmpeer++;
			peeridx++;
			/* 
			 * Prepare replica info for new replica
			 */
			TAILQ_FOREACH(peer, &hso->so_mig_peer, list) {
#ifdef SMCP
				if ((peer->id != new_smcp->id) &&
				    SOISPRIMARY(hso) && 
				    peer->state == SOMIG_SO_CONNECTED) {
#else
				if ((peer->id != so->so_mig_id) &&
				    SOISPRIMARY(hso) && 
				    peer->state == SOMIG_SO_CONNECTED) {
#endif
					KASSERT(peeridx < size, 
					    ("%s[%d]: Too many peers\n", 
					     __func__, __LINE__)); 
					tcpmig_spetotn(peer, tmpeer, 0);
					if (peeridx < size) {
						tmpeer++;
						peeridx++;
					} else {
						tmpeer -= size;
					}
				}
			}
			
			KASSERT(peeridx == size, 
			    ("%s[%d]: inconsistent peer num.",
			    __func__, __LINE__));

node_done:
			//SOCK_UNLOCK(hso);

			/* 
			 * Adjust status in header
			 */
			tmthp->magic = TM_MAGIC;
			tmthp->cmd = TM_CMD_HANDSHAKE;
			tmthp->status = rt_status;
#ifdef SMCP
			tmthp->addr = new_smcp->r_addr;
			tmthp->port = new_smcp->r_port;
			/* 
			 * During HS replica does NOT know ID before receiving
			 * response.
			 */
			if (hso->so_mig_role == SOMIG_PRIMARY)
				tmthp->id = smcp->id;	/* Should always be 0 */
			else
				tmthp->id = new_smcp->id;
#endif
			tmthp->exlen = sizeof(struct tmver);
			if (SOISPRIMARY(hso) && rt_status == TM_STATUS_OK)
				tmthp->exlen += sizeof(struct tmnode)*size;
			tmthp->len = sizeof(struct tmhdr) + tmthp->exlen;

			/* 
			 * Sendback to new replica
			 */
			if (rt_status == TM_STATUS_OK) {
#ifdef SMCP
				error = tcpmig_send(peerm, new_smcp);
#else
				error = tcpmig_send(peerm, sototcpcb(so));
#endif
				if (error) {
					/* TODO: find a proper handling */
					panic("%s[%d]: Cannot send message. Err %d", 
					    __func__, __LINE__, error);
				}	
				/*
				 * Update current CtlSo states
				 */
#ifdef SMCP
				new_smcp->so_mig_pentry->state = SOMIG_SO_CONNECTED;
				new_smcp->state = SMCP_NORMAL;
				hso->so_mig_gack_full |= (1<<new_smcp->id);
#else
				so->so_mig_pentry->state = SOMIG_SO_CONNECTED;
				hso->so_mig_gack_full |= (1<<so->so_mig_id);
#endif
				//SOCK_LOCK(hso);
				hso->so_mig_peer_size++;
				//SOCK_UNLOCK(hso);
//TODO
				printf("Replica joined so %p\n", hso); 

				/* Wait for next 3HS-ACK rexmt */
				if (hso->so_mig_peer_size == hso->so_mig_head_peer_size) {
					hso->so_mig_state = SMGS_CONNECTED;
					/* Compose an ACK to finalize the TCPHS */
					ack_m = tcpmig_compose_tcp_ack(hso);
					tcpmig_direct_ip_input(ack_m, sototcpcb(hso));

					CTR2(KTR_SPARE5, "%s:%d All joined.",
					    __func__, __LINE__);
				}
				//wakeup(&hso->so_mig_peer_size);
			} else {
#ifdef SMCP
				tcpmig_senddrop(peerm, new_smcp);
#else
				tcpmig_senddrop(peerm, sototcpcb(so));
#endif
			}

#ifdef SMCP
			new_smcp = NULL;
#endif
			goto consume_all;
			break;
		case TM_CMD_PACKET:
			/*
			if (chkpr->state != SOMIG_SO_CONNECTED) {
				panic("TM_CMD_PACKET wrong SO type");
				return;
			}
			*/
			switch (hso->so_mig_role) {
			case SOMIG_REPLICA:
#ifdef SMCP
				tcpmig_ctlinput_packet(smcp, m, status, tmth->len);
#else
				tcpmig_ctlinput_packet(so, m, status, tmth->len);
#endif
				if (next_m) 
					goto process_next;
				else
					goto done;
				break;
			case SOMIG_PRIMARY:
				htp = sototcpcb(hso);
				if (htp != NULL && htp->rolechange != 0) {
					/*
					 * For now just ignore it
					 */
					//printf("PRIMARY received a broadcasted packet. rolechange %d\n", htp->rolechange);
				}
				break;
			default:
				panic("Shouldn't receive this packet.\n");
			}
			break;
		case TM_CMD_MIGRATE:
			/* 
			 * Let cmd receiver takeover the connection
			 *	    ^ which is the current HSO. 
			 */
			htp = sototcpcb(hso);
			htp->rolechange = 1;

			KASSERT(hso->so_mig_role == SOMIG_REPLICA, 
			    ("Calling MIG on PRIMARY"));
			KASSERT(smcp->so_mig_pentry->role == SOMIG_PRIMARY,
			    ("Received MIG from REPLICA"));

			tmmig = (struct tmmigration *)(off + sizeof(struct tmhdr));
			
			SMGTPRT(hso, "Received MIG msg flag %u", tmmig->flag);
			if (tmmig->flag & TM_MIGRATION_FLAG_FAIL) {
#ifdef SMCP
				smcp->so_mig_pentry->state = SOMIG_SO_FREEING;
				somig_close(smcp->so_mig_pentry);
				smcp->state = SMCP_FREE;
#else
				somig_close(so->so_mig_pentry);
#endif
			}

			/*
			 * TODO:
			 *  If orig node fails, sending LB only will not notify
			 *  other nodes. Either add more info in pkt or
			 *  implement the heartbeat check in sys.
			 */
			if (tcpmig_get_livepeer_count(hso)) {
				tcpmig_compose_migration_packet(peerm, TM_MIGRATION_FLAG_LB);
				error = tcpmig_bcast(peerm, sototcpcb(hso));
			}
			SMGTPRT(hso, "Broadcasted promotion msg.");

			tcpmig_updatecb(hso);

			htp->unack_flush = 1;
#ifdef SOMIG_MIG_BRKDN
			SMGTPRT(hso, "Flushing all buffered unsent packet to client.");
#endif

#ifdef SMCP
			tcpmig_flushpkt_migration(hso->smcpcb, 1);
			tcpmig_updaterole(hso, NULL, NULL, TM_PROMOTE);
			TAILQ_FOREACH(peer, &hso->so_mig_peer, list) {
				peer->role = SOMIG_REPLICA;
			}
#else
			tcpmig_flushpkt_migration(so, 1);
			tcpmig_updaterole(hso, so->so_mig_pentry, NULL, TM_PROMOTE);
#endif

			hso->so_mig_unack = sbavail(&hso->so_snd);
			if (hso->so_mig_unack) {
				error = htp->t_fb->tfb_tcp_output(htp);
			}

			op = 0;
			/*
			 * Find ifaddr for our RSO and promote it!
			 */
#ifdef SOMIG_MIG_BRKDN
			SMGTPRT(hso, "Promoting corresponding ifaddr.");
#endif
			CK_STAILQ_FOREACH(ia, &V_in_ifaddrhead, ia_link) {
				sa = (struct sockaddr_in *)ia->ia_ifa.ifa_addr;
				if (sa->sin_addr.s_addr != sotoinpcb(hso)->inp_laddr.s_addr) 
					continue;
#ifndef SOMIG_FASTMIG
				tcpmig_carp_promote(&ia->ia_ifa, TCPMIG_CARP_ADJ);
#else
				/* 
				 * TODO: for now use this quick hack, which
				 * compares the masked IP, need to be
				 * fixed. 
				 */
				tcpmig_if_promote(ia->ia_ifp, &ia->ia_ifa); 
#endif
				op++;
				break;
			}
			
			if (op == 0) {
				printf("Wrong ifa for CARP promotion.\n");
			}

			if (TAILQ_EMPTY(&hso->so_mig_pkt) && SEQ_GEQ(htp->snd_max, htp->ack_max)) {
				//INP_WLOCK(htp->t_inpcb);
				tcpmig_rolechange_done(hso);
				//INP_WUNLOCK(htp->t_inpcb);
				SOMIG_TIME_TEST_LOG = 1;
			} else {
				//printf("Have pkt buffered. Continuing.. size %u\n", hso->so_mig_pkt_buffered);
			}
			break;
		case TM_CMD_LEAVE:
			break;
		case TM_CMD_SYNC:
			if (chkpr->state != SOMIG_SO_CONNECTED) {
				panic("TM_CMD_HANDSHAKE wrong pkt type");
				return;
			}
			switch (hso->so_mig_role) {
			case SOMIG_PRIMARY:
				/* 
				 * Prepare mbuf for packet
				 */
				msize = sizeof(struct tmhdr) + sizeof(struct tmstate);
				peerm = m_getm2(NULL, msize, M_NOWAIT, MT_DATA, 0);
				peerm->m_len = msize;
				roff = mtod(peerm, char *);
				tmthp = (struct tmhdr *)roff;
				tms = (struct tmstate *)(roff + sizeof(struct tmhdr));

				tmthp->magic = TM_MAGIC;
				tmthp->cmd = TM_CMD_SYNC;
				tmthp->status = TM_STATUS_OK;
				tmthp->exlen = sizeof(struct tmstate);
				tmthp->len = sizeof(struct tmhdr) + 
				    sizeof(struct tmstate);
#ifdef SMCP
				tmthp->addr = smcp->r_addr;
				tmthp->port = smcp->r_port;
				tmthp->id = smcp->id;
#endif
				INP_WLOCK(sotoinpcb(hso));
				SOCK_LOCK(hso);

				tcpmig_getstates(hso, tms);
				
				SOCK_UNLOCK(hso);
				INP_WUNLOCK(sotoinpcb(hso));
				/* 
				 * Sendback to new replica 
				 */
#ifdef SMCP
				error = tcpmig_send(peerm, smcp);
#else
				error = tcpmig_send(peerm, sototcpcb(so));
#endif
				if (error) {
					/* TODO: find a proper handling */
					panic("%s[%d]: Cannot send message. Err %d", 
					    __func__, __LINE__, error);
				}			
				break;	
			default:
				panic("SYNC msg delivered to NON-PRIMARY");
				break;
			}
			break;
		case TM_CMD_JOIN:
			if (chkpr->state != SOMIG_SO_CONNECTED) {
				panic("TM_CMD_JOIN wrong pkt type");
				return;
			}
			KASSERT(hso->so_mig_role == SOMIG_REPLICA, 
			    ("sotype: %d shouldn't receive HS.\n", 
			     hso->so_mig_role));
			KASSERT((exlen == sizeof(struct tmnode)), 
			    ("Invalid JOIN packet size"));

			tmn = (struct tmnode *)(off + sizeof(struct tmhdr));
			/*
			 * Add this pending connect info to JOIN queue 
			 */
			peer = (struct somig_peer_entry *)malloc(
			    sizeof(struct somig_peer_entry), M_TEMP, 
			    M_NOWAIT | M_ZERO);
			peer->id = tmn->id;
			peer->role = tmn->role;
			peer->ip = tmn->ip;
#ifdef SMCP
			peer->p_addr = tmn->p_addr;
			peer->p_port = tmn->p_port;
#else
			peer->port = tmn->port;
#endif

			SOMIG_LOCK(hso);
			TAILQ_INSERT_TAIL(&hso->so_mig_join, peer, list);
			SOMIG_UNLOCK(hso);

#ifdef SMCP
			CTR3(KTR_SPARE5, "Join[id:%u|role:%d|ip:%u]\n", 
			    peer->id, peer->role, peer->ip);
#else
			CTR4(KTR_SPARE5, "Join[id:%u|role:%d|ip:%u|port:%u]\n", 
			    peer->id, peer->role, peer->ip, peer->port);
#endif

			//wakeup(&hso->so_mig_join);
			//printf("Joining primary..\n");

			SOLISTEN_LOCK(hso);
			incomp_so = TAILQ_FIRST(&hso->sol_incomp);
			CTR4(KTR_SPARE5, "%s:%d hso%p incmpl_so%p", __func__, __LINE__, hso, incomp_so);
			if (!incomp_so) {
				SOLISTEN_UNLOCK(hso);
				break;
			}

			error = tcpmig_sojoin(hso, incomp_so, SOMIG_REPLICA);
			if (error) {
				printf("Join error %d\n", error);
				panic("Join error see errno above");
			}
			incomp_so->so_mig_state = SMGS_CONNECTED;
#ifndef SMCP
			soisconnected(incomp_so);
#endif
			SOLISTEN_UNLOCK(hso);

			/* Reply */
			//tcpmig_sendreply(so, TM_CMD_JOIN, TM_STATUS_OK);
			break;
		default:
			/* No cmd set. Status packet. */
			break;
		}
		break;
	case TM_STATUS_OK:
		switch (flags) {
		case TM_CMD_HANDSHAKE:
			switch (hso->so_mig_role) {
			case SOMIG_REPLICA:

				/* get replica group size */
				size = (exlen - sizeof(struct tmver)) / 
				    sizeof(struct tmnode);
				if (size < 0 || size > SOMIG_MAXNODE) {
					panic("Invalid group size %d", size);
				}

				/*
				 * At this point we can change the state in 
				 * peer list to its corresponding one
				 */
#ifndef SMCP
				so->so_mig_pentry->state = SOMIG_SO_CONNECTED;
				hso->so_mig_gack_full |= (1<<so->so_mig_id);
#endif
				hso->so_mig_peer_size++;

				/*
				 * If returned message has node list then
				 * that means we are connecting to primary
				 * and we need to connect to all returned 
				 * replicas in order to compose the group net
				 */
				if (size > 0) {
					/* 
					 * offset to first tmnode 
					 */
					roff = off + sizeof(struct tmhdr) + 
					    sizeof(struct tmver);

					SOCK_LOCK(hso);
					for (peeridx=0;peeridx<size;peeridx++) {
						tmpeer = (struct tmnode *)(roff +
						    peeridx * sizeof(struct tmnode));
						
						/* 
						 * idx 0 contains our own info 
						 */
						if (peeridx == 0) {
							hso->so_mig_id = tmpeer->id;
#ifdef SMCP
							smcp->so_mig_pentry->state = SOMIG_SO_CONNECTED;
							hso->so_mig_gack_full |= (1<<tmpeer->id);
							smcp_set_id((void*)smcp, tmpeer->id);
#endif
							continue;
						}

#ifdef SMCP
						tcpmig_nodeconnect(
						    hso, tmpeer,
						    smcp->r_addr,
						    smcp->r_port,
						    smcp->l_addr);
#else
						tcpmig_nodeconnect(hso, tmpeer);
#endif
					}
					SOCK_UNLOCK(hso);
				}

#ifdef SMCP
				SOCK_LOCK(hso);
				smcp->state = SMCP_NORMAL;
				SOCK_UNLOCK(hso);
				wakeup(&smcp->so_mig_pentry->state);

				/* Compose an ACK to finalize the TCPHS */
				ack_m = tcpmig_compose_tcp_ack(hso);
				tcpmig_direct_ip_input(ack_m, sototcpcb(hso));

#else
				wakeup(&so->so_mig_pentry->state);
#endif
				break;
			default:
				panic("Only replica can send HS cmd.");
			}
			break;
		case TM_CMD_PACKET:
#ifdef SMCP
			tcpmig_ctlinput_packet(smcp, m, status, tmth->len);
#else
			tcpmig_ctlinput_packet(so, m, status, tmth->len);
#endif
			break;
		case TM_CMD_SYNC:
			/* 
			 * Apply states to hso
			 */
			tms = (struct tmstate *)(off + sizeof(struct tmhdr));
			INP_WLOCK(sotoinpcb(hso));
#ifdef SMCP
			tcpmig_setstates(hso, (void *)smcp, tms, ~ISSOCONNECTED(hso));
#else
			tcpmig_setstates(hso, so, tms, ~ISSOCONNECTED(hso));
#endif
			INP_WUNLOCK(sotoinpcb(hso));

			if (hso->so_mig_role == SOMIG_REPLICA) 
				wakeup(&hso->so_options);
			break;
		case TM_CMD_MIGRATE:
			/*
			 * If TM_CMD_MIGRATE+TM_STATUS_OK was received, 
			 * means the sending was promoted.
			 */
			htp = sototcpcb(hso);
//printf("I received CMD_MIG_OK msg, role %d tprc %d\n", hso->so_mig_role, htp->rolechange);
			if (htp->rolechange != 0) {
				htp->rolechange = 0;
#ifdef SMCP
				tcpmig_updaterole(hso, smcp->so_mig_pentry, NULL, 
				    TM_DEMOTE);
#else
				tcpmig_updaterole(hso, so->so_mig_pentry, NULL, 
				    TM_DEMOTE);
#endif

				panic("jajajajajajajaja\n");
			} else {
				/*
				 * Find the current PRIMARY
				 */
				TAILQ_FOREACH(peer, &hso->so_mig_peer, list) {
					if (peer->role == SOMIG_PRIMARY) {
#ifdef SMCP
						tcpmig_updaterole(hso, 
						    smcp->so_mig_pentry, peer,
						    TM_UPDATE);
#else
						KASSERT(peer->so != so, 
						    ("Swapping the role for the same So"));
						tcpmig_updaterole(hso, 
						    so->so_mig_pentry, peer, 
						    TM_UPDATE);
#endif
						//printf("Swapped role..\n");
						break;
					}
				}

			}

			break;
		case TM_CMD_JOIN:
			/* Ignore for now */
			break;
		default:
			break;
		}
		break;
	case TM_STATUS_FULL:
		break;
	default:
		/* Consume packet? */
		goto consume_all;
	}

consume_all:
	/*
	 * If this is the packet we delivered into TCPStack(REPLCIA case) then
	 * don't free it.
	 */
	if (!(hso->so_mig_role == SOMIG_REPLICA && 
		    status == TM_STATUS_NULL && flags == TM_CMD_PACKET)) {
		m_freem(m);
	}

process_next:
	hso->so_mig_pending_m = NULL;
	hso->so_mig_pending_tlen = 0;

	if (next_m) {
#ifdef SMCP
		tcpmig_ctlinput(next_m, smcp, drop_hdrlen, remainder);
#else
		tcpmig_ctlinput(next_m, tp, inp, drop_hdrlen, remainder);
#endif
		//goto done;
	}

done:
	return;
}

/*
 * tcpmig_pktinput
 * Duplicate user packet and broadcast to all replicas
 */
void 
tcpmig_pktinput(struct mbuf *m, struct socket *so, int *offp, uint32_t seq, 
    int thflags, int drop_hdrlen, int tlen, struct somig_pkt_data_syn *syndata, 
    uint32_t flag, uint16_t port)  
{
	int error, send = 0;
	struct timeval	tn;
	struct somig_pkt_entry *pkt = NULL, *tmp = NULL;
	uint32_t total_hdrsize, m1_size;
	uint32_t m2_saddr, m2_daddr;
	uint16_t m2_sport, m2_dport;
	uint32_t m2_seq, m2_ack;
	uint16_t m2_thwin;
	uint8_t m2_thflag, m2_thurp;
	struct ifnet *m2_ifn;
	struct mbuf *m1, *m2; /* F87 is good */
	struct tcphdr *th;
#ifdef INET6
	int		isipv6;
	struct ip6_hdr	*ip6;
#endif
	struct ip	*ip;

	/* Check if so is closing */
	if (so->so_state & SS_ISDISCONNECTING || so->so_state & SS_ISDISCONNECTED)
		goto bad;

	so->so_mig_pkt_counter += 1;

	/* 
	 * Check if the size of payload plus our SOMIG+IP hdr wont exceed uint16
	 * max (which is the max that an IP packet could take). 
	 */
	total_hdrsize = max_linkhdr + sizeof(struct ipovly) + 
	    sizeof(struct tmhdr) + sizeof(struct ppshdr); 
	
	/* If we don't have enough space in mbuf, do the fragmentation */
	if (m->m_pkthdr.len > (0xffff - total_hdrsize)) {
		/*
		 * The stragety here is we cut the packet into two pieces.
		 *
		 * For the first piece, we trim off the last 1000bytes of data
		 * in order to make it fit our headers(somig+ip).
		 * For the second piece, we use the 1000bytes of data trim'd
		 * from the first piece to compose a new tcp packet.
		 */
		m1 = m;
		m1_size = m->m_pkthdr.len - 1000;
		m2 = m_split(m, m->m_pkthdr.len - 1000, M_NOWAIT); 
		if (m2 == NULL) {
			CTR2(KTR_SPARE5, "%d: failed to split the mbuf len %u",
			    __LINE__, m->m_pkthdr.len);
			goto bad;
		}

		/*
		 * Do the first piece
		 * Trim off 1/2 of the data, then update the existing header
		 */
#ifdef INET6
		isipv6 = (((struct ip*)mtod(m1, caddr_t))->ip_v == 6) ? 1 : 0;
		if (isipv6) {
			ip6 = mtod(m1, struct ip6_hdr *);
			th = (struct tcphdr *)(mtod(m1, caddr_t) + sizeof(struct ip6_hdr));
			panic("ipv6 support: Incomplete code path\n");
		} else
#endif
		{
			ip = (struct ip *)(mtod(m1, caddr_t));
			th = (struct tcphdr *)(mtod(m1, caddr_t) + sizeof(struct ip));
		}

		/* Save necessary tcp/ip info for m2 */
		m2_saddr = ip->ip_src.s_addr;
		m2_daddr = ip->ip_dst.s_addr;

		m2_sport = th->th_sport;
		m2_dport = th->th_dport;
		m2_seq = th->th_seq;
		m2_ack = th->th_ack;
		m2_thflag = th->th_flags;
		m2_thwin = th->th_win;
		m2_thurp = th->th_urp;
		m2_ifn = m->m_pkthdr.rcvif;

		/* Update size in tcpip headers */
		ip->ip_len = htons(ntohs(ip->ip_len) - 1000);

		/* Redo pkt input for m1 */
		tcpmig_pktinput(m1, so, offp, seq, thflags, drop_hdrlen, 
		    tlen - 1000, syndata, flag | TM_PKTIN_SPLIT_M1, port);

		/* 
		 * Do the second piece
		 * Reconstruct the full tcp/ip header 
		 */
		m2_seq = htonl(ntohl(m2_seq) + (tlen - 1000));
		m2 = tcpmig_compose_tcpip_pkt(m2_saddr, m2_daddr, 
		    m2_sport, m2_dport, m2_thflag, m2_seq, m2_ack, m2_thwin,
		    m2, 1000, m2_ifn, so, 0); 
		
		/* Redo pkt input for m2 */
		/* drop_hdrlen - 12: our homemade packet doesn't have TCP timestamp option */
		tcpmig_pktinput(m2, so, offp, ntohl(m2_seq), thflags, drop_hdrlen - 12,
		    1000, syndata, flag | TM_PKTIN_SPLIT_M2, port);
		return;
	} 

	if (flag & TM_PKTIN_BUFFER) {
		pkt = uma_zalloc(somig_pkt_zone, M_NOWAIT | M_ZERO);
		SOMIG_PKT_ENTRY_INIT(pkt, m, *offp, so->so_mig_gack_full, seq, thflags, 
		    drop_hdrlen, tlen, sototcpcb(so), syndata, port);

		if (flag & TM_PKTIN_SPLIT_M1) 
			pkt->flag |= SOMIG_PKT_FLAG_SPLIT_M1;
		else if (flag & TM_PKTIN_SPLIT_M2)
			pkt->flag |= SOMIG_PKT_FLAG_SPLIT_M2;
	
		if (flag & TM_PKTIN_TS) {
			microtime(&tn);
			pkt->snd_ts = (uint32_t)(tn.tv_sec % 10000) * 1000000;
			pkt->snd_ts += tn.tv_usec;
		}
//CTR2(KTR_SPARE4, "%d: tlen %u", __LINE__, tlen);
		
		SOMIG_PKT_LOCK(so);
		TAILQ_INSERT_TAIL(&so->so_mig_pkt, pkt, list);
		so->so_mig_pkt_buffered += pkt->tlen;
//CTR6(KTR_SPARE5, "%d: buf'd%u seq%u tlen%u buf'd%u m%p", __LINE__, so->so_mig_pkt_buffered, 
   // pkt->seq, pkt->tlen, so->so_mig_pkt_buffered, m);
		SOMIG_PKT_UNLOCK(so);
	}

	if (flag & TM_PKTIN_NO_BCAST)
		return;

	if (flag & TM_PKTIN_BCAST_IF_FULLSO) {
		if (so->so_qstate != SQ_NONE)
			return;
	}

	if (!(flag & TM_PKTIN_BUFFER) || (so->so_mig_pkt_unsnd == NULL)) {
		error = tcpmig_pktinput_internal(m, pkt, sotoinpcb(so), drop_hdrlen, tlen, flag);
		if (error) {
			printf("Bad sent at %p, err %d\n", pkt, error);
			if (pkt) so->so_mig_pkt_unsnd = pkt;
		} else {
			if (pkt) pkt->sent = 1;
		}
		return;
	}

	/*
	 * SMCP is built on top of IP layer. One case that causes the delivery
	 * failure is the NIC rejects the packet when the buffer is full/etc., 
	 * and the IP layer will return an error. To avoid the retransmission, 
	 * we save the last unsent packet and always start the sending 
	 * from the last unsent packet. 
	 */
	if (so->so_mig_pkt_unsnd) {
		TAILQ_FOREACH_SAFE(pkt, &so->so_mig_pkt, list, tmp) {
			if (pkt != so->so_mig_pkt_unsnd && !send)
				continue;

			if (pkt == so->so_mig_pkt_unsnd) {
				send = 1;
				so->so_mig_pkt_unsnd = NULL;
			}

			KASSERT(pkt->sent == 0, ("pkt->sent == 1 in a unsent packet"));

			m = pkt->m;
			drop_hdrlen = pkt->drop_hdrlen;
			tlen = pkt->tlen;

			error = tcpmig_pktinput_internal(m, pkt, sotoinpcb(so), drop_hdrlen, tlen, flag);
			if (error) {
				printf("Bad sent at %p, err %d\n", pkt, error);
				so->so_mig_pkt_unsnd = pkt;
				return;
			} else {
				pkt->sent = 1;
			}
		}
	} 

	return;
bad:
	/* TODO: notify caller */
	m_freem(m);
	return;
}

static int
tcpmig_pktinput_internal(struct mbuf *m, struct somig_pkt_entry *smpe,
    struct inpcb *inp, int drop_hdrlen, int tlen, int flag)
{
	char *off;
	struct mbuf *bm;
	struct tcpcb *tp; 
	struct tmhdr *tmh;
	struct ppshdr *ppsh;
	struct socket *so;
	int pld_size, hdr_size;
	int error = 0;
#ifdef SOMIG_TIMING_DIAG
	struct timeval tn;
	uint32_t pri_time;
#endif
#if defined(SMCP) && defined(SOMIG_OPTI_COPYPKT)
	int upd_smpe = 0;
#endif
#ifdef SOMIG_TASKQUEUE
	struct somig_task_entry *te;
#endif
#ifdef SMCP
	struct smcpcb *smcp;
	struct somig_peer_entry *spe;
#endif
	//int size, chunk, MTU, offset, left, sent;

	so = inp->inp_socket;
	KASSERT(so != NULL, ("%s: so == NULL", __func__));

	if (so->so_mig_peer_size == 0)
		return (0);
	tp = sototcpcb(so);
	
	KASSERT(m != NULL, ("Null mbuf"));

	// Allocate space for tmhdr 
	hdr_size = sizeof(struct tmhdr) + sizeof(struct ppshdr);
	pld_size = tlen + drop_hdrlen;
#ifdef SMCP
	/* Duplicate current mbufs */
#if defined(SOMIG_OPTI_COPYPKT)
	if (flag & TM_PKTIN_BUFFER) {
		/* 
		 * Check if ip_fragment will be called. If so, we set the somig
		 * flag in mbuf so that our optimized ip_fragment will be
		 * called without breaking the original mbuf chain.
		 */
		/* Here we choose the largest MTU */
		if (sizeof(struct ipovly) + hdr_size + pld_size <= TM_FRAG_OPTIMIZATION_THRESH)
			bm = m_copypacket(m, M_NOWAIT);
		else {
			bm = m;
			upd_smpe = 1;
		}
	} else {
		bm = m_copypacket(m, M_NOWAIT);
	}
#else
	//bm = m_copypacket(m, M_NOWAIT);
	bm = m_dup(m, M_NOWAIT);
#endif //SOMIG_OPTI_COPYPKT

	M_PREPEND(bm, max_linkhdr + sizeof(struct ipovly) + hdr_size, M_NOWAIT);
#if defined(SOMIG_OPTI_COPYPKT)
	if (upd_smpe) {
		bm->m_flags |= M_SOMIG_PKT;
		//smpe->m = tcpmig_mbuf_somigize(bm, m);
	}
#endif //SOMIG_OPTI_COPYPKT

	bm->m_type = MT_HEADER;
	bm->m_data += (max_linkhdr + sizeof(struct ipovly));
	bm->m_len = hdr_size;
	bm->m_pkthdr.len = hdr_size + pld_size;
#else
#if defined(SOMIG_OPTI_COPYPKT)
	bm = m_copypacket(m, M_NOWAIT);
	if (sizeof(struct ipovly) + hdr_size + pld_size > TM_FRAG_OPTIMIZATION_THRESH)
		bm->m_flags |= M_SOMIG_PKT;
#else
	bm = m_dup(m, M_NOWAIT);
#endif //SOMIG_OPTI_COPYPKT
	bm->m_type = MT_HEADER;
	M_PREPEND(bm, hdr_size, M_NOWAIT);
#endif // SMCP
	if (bm == NULL) {
		panic("M_PREPEND Error");
	}

	bm->m_flags |= M_PKTHDR;
	m->m_flags |= M_PKTHDR;
	
	/* Set tmhdr */ 
	off = mtod(bm, char *);
	tmh = (struct tmhdr *)off;
	tmh->magic = TM_MAGIC;
	tmh->cmd = TM_CMD_PACKET;
	tmh->status = TM_STATUS_NULL;
	tmh->exlen = pld_size;
	tmh->len = hdr_size + pld_size;

#ifdef SMCP
if (smpe) {
    tmh->debug_seq = (uint32_t)((uint64_t)so & 0xFFFFFFFFUL);
    tmh->padding = so->so_mig_pkt_counter % 256;
    //CTR6(KTR_SPARE5, "Bcasting so %p len %u seq%u hdr_size%u pldsize%u padding%u", so, tmh->len, smpe->seq, hdr_size, pld_size, tmh->padding&0xff);
}
	/* TODO: fix this for multi peer setup !!!!!!!!!!!!!!!!!!!!!! */
	spe = TAILQ_FIRST(&so->so_mig_peer);

	smcp = spe->smcpcb;
	tmh->addr = smcp->r_addr;
	tmh->port = smcp->r_port;
	tmh->id = smcp->id;
#endif
	
	/* Set ppshdr */
	ppsh = (struct ppshdr *)(off + sizeof(struct tmhdr));
	if (tp->t_state == TCPS_ESTABLISHED) {
		ppsh->rwnd = (sbspace(&so->so_rcv) + sbused(&so->so_rcv));
	}
	ppsh->snd_off = tp->t_snd_off_local;
	ppsh->flag = 0;
	ppsh->snd_cwnd = tp->snd_cwnd;
	ppsh->ts_recent = tp->ts_recent;
	ppsh->ts_recent_age = tp->ts_recent_age;

	ppsh->pri_ts = tcp_ts_getticks(); 

#ifdef SOMIG_TIMING_DIAG
	microtime(&tn);
	pri_time = (uint32_t)(tn.tv_sec % 10000) * 1000000 + tn.tv_usec;
	tmh->stime = pri_time;
	tmh->padding = 1;
#endif

#ifdef SOMIG_OPTI_DONT_BUFFER_ACK
	if (flag | TM_PKTIN_DONT_ACK) 
		ppsh->flag |= TM_FLAG_DONTACK;
		
#endif

	/* Create the context for taskqueue and store it */
	/* TODO: use uma zone to handle the allocation */
	if (so->so_mig_role == SOMIG_PRIMARY && 
	    tp->t_state == TCPS_ESTABLISHED
#ifdef SOMIG_TASKQUEUE
	    && so->so_mig_task_thread
#endif
	    ) {
#ifdef SOMIG_TASKQUEUE
		te = (struct somig_task_entry *)malloc(sizeof(struct somig_task_entry),
			M_TEMP, M_NOWAIT | M_ZERO);
		te->ctl_blk = tp;
		te->m = bm;
		te->so = so;
		te->spe = smpe;
		te->flag = 0;
		SOMIG_TASK_LOCK(so);
		TAILQ_INSERT_TAIL(&so->so_mig_tasks, te, list);
		SOMIG_TASK_UNLOCK(so);
#else
		error = tcpmig_bcast(bm, tp);
#endif
	} else {
		error = tcpmig_bcast(bm, tp);
	}

	/* Label the packet unsent and resend later */
	if (error) {
		//panic("Add the error packet resend timer..");
	}

	return (error);
}

static int
#ifdef SMCP
tcpmig_ctlinput_packet(struct smcpcb *smcp, struct mbuf *m0, int status, int tlen)
#else
tcpmig_ctlinput_packet(struct socket *so, struct mbuf *m0, int status, int tlen)
#endif
{
	int error = 0, msize = 0, thflags, synpkt = 0, dontbuf = 0;
	int ccount = 0, rcount = 0, throttle = 0; 
	int conti_flag;
	uint32_t seq_off = 0, seq, seq_throttle;
	uint32_t orig_rn;
	char *off;
	struct socket *hso;
	struct mbuf *m;
	struct tmhdr *tmth;
	struct ppshdr *ppsh;
	struct tcphdr *th;
	struct inpcb *hinp;
	struct tcpcb *htp;
#ifndef SMCP
	struct inpcb *inp;
	struct tcpcb *tp;
#endif
	struct somig_pkt_entry *pkt = NULL, *temp = NULL;
#ifdef SOMIG_TIMING_DIAG
	struct timeval tn;
	uint32_t time_now;
	static int timing_diag_counter;
	static uint64_t timing_diag_sum;
#endif
	
	//m = m0;
	m = tcpmig_m_rearrange(m0, tlen);

#ifdef SMCP
	KASSERT(smcp->inp != NULL, ("smcp inp is NULL"));
	hso = (struct socket *)(smcp->inp->inp_socket);
#else
	hso = so->so_mig_hostso;
	tp = sototcpcb(so);
	inp = sotoinpcb(so);
#endif
	htp = sototcpcb(hso);

	if (m->m_len < sizeof(struct tmhdr) + sizeof(struct ppshdr)) {
		m = m_pullup(m, 
		    sizeof(struct tmhdr) + sizeof(struct ppshdr));
	}

	off = mtod(m, char *);
	tmth = (struct tmhdr *)(off);
	ppsh = (struct ppshdr *)(off + sizeof(struct tmhdr));

#ifdef SMCP
	/* Cancel the activated timer */
	if (tcp_timer_active(htp, TT_SOMIG)) {
		tcp_timer_activate(htp, TT_SOMIG, 0);
	}
#else
	/* Cancel the activated timer */
	if (tcp_timer_active(tp, TT_SOMIG)) {
		tcp_timer_activate(tp, TT_SOMIG, 0);
	}
#endif

	if (status == TM_STATUS_NULL) {
		int pld_len = 0;
		struct ppshdr ppshd;

		msize = sizeof(struct tmhdr) + sizeof(struct ppshdr);
		ppshd = *ppsh;

#ifdef SOMIG_TIMING_DIAG
		if (tmth->padding)
			stime_from_mso = tmth->stime;
		else 
			stime_from_mso = 0;
#endif

		/*
		 * per packet TCP state update
		 */
		tcpmig_updatestate(htp, hso, &ppshd);

		/* 
		 * Remove current SOMIG header 
		 */
		m_adj(m, msize);
#ifdef SMCP
		th = tcpmig_updatehdr_addr(m, smcp, hso, tlen - msize, &pld_len);
#else
		th = tcpmig_updatehdr_addr(m, hso, so, tlen - msize, &pld_len);
#endif
		//th = tcpmig_updatehdr_tcp(m, hso, 0);
		th = tcpmig_updatehdr_tcp(m, hso, pld_len);
		thflags = th->th_flags;
		//CTR5(KTR_SPARE5, "seq %u ack %utlen %u pldlen %d flg %d",
		//    ntohl(th->th_seq), ntohl(th->th_ack), tlen, pld_len, thflags);
		synpkt = PKTSYN(thflags);
//printf("%d: ad%u sb rcv%ld snd%ld\n", __LINE__, hso->so_mig_primary_addr, sbspace(&hso->so_rcv), sbspace(&hso->so_snd)); 

		seq = th->th_seq;
		
		/* 
		 * Set current input socket (will be used in tcp_output)
		 */
#ifdef SMCP
		hso->so_mig_inputpeer = smcp->so_mig_pentry;
#else
		hso->so_mig_inputpeer = so->so_mig_pentry;
#endif
		/*
		 * Skip the ACK for TCPHS - 3(ACK) pkt
		 */
		if (sototcpcb(hso)->t_state != TCPS_ESTABLISHED && 
		    !(thflags & TH_SYN)) {
			CTR2(KTR_SPARE5, "%s:%d 3HS ACK received\n", __func__, __LINE__);
			ip_input(m);
			hso->so_mig_pkt_consumption = 0;
			return (error);
		}

		/*
		 * Buffer this packet. (Don't buffer any packet belongs to 3HS)
		 */
		if (!synpkt) {
			/* Just return if this is a pure ACK */
#ifdef SOMIG_OPTI_REPLICA_IGNORE_ACK
			if (pld_len == 0 && th->th_flags == TH_ACK) {
				dontbuf = 1;
				m_freem(m);
#ifdef SOMIG_OPTI_DONT_BUFFER_ACK
				goto timer_reset;
#else
				goto sendack;
#endif
			}
#endif

			TAILQ_FOREACH_SAFE(pkt, &hso->so_mig_pkt, list, temp) {
				if (pkt->seq == ntohl(seq) && 
				    pkt->tlen == tlen - msize) {
				    CTR2(KTR_SPARE5, "%d - pkt %u freed", __LINE__, pkt->seq);
					dontbuf = 1;
					m_freem(m);
					goto sendack;
				}
			}
			
			pkt = uma_zalloc(somig_pkt_zone, M_NOWAIT | M_ZERO);
			pkt->m = m;
			pkt->seq = ntohl(seq);
			pkt->ack = ntohl(th->th_ack);
			pkt->tlen = pld_len;
			pkt->thflags = th->th_flags;
			pkt->sent = 0;
			pkt->rexmt = 0;
			pkt->flag = 0;
			pkt->snd_off = ppshd.snd_off;
			pkt->th = th;

			//SOMIG_PKT_LOCK(hso);
#ifdef SMCP
			SOMIG_DELIVERY_LOCK(hso);
#endif

			TAILQ_INSERT_TAIL(&hso->so_mig_pkt, pkt, list);
			if (TCPMIG_INC_PACKET > 2000) {
				printf("WARN Check LEAK: PACKETS Buffered %d\n", 
				    TCPMIG_INC_PACKET);
			}

			if (hso->so_mig_pkt_buffered < 0)
				hso->so_mig_pkt_buffered = 0;
			hso->so_mig_pkt_buffered += pkt->tlen;

#ifdef SMCP
			SOMIG_DELIVERY_UNLOCK(hso);
#endif

			if (hso->so_mig_role == SOMIG_PRIMARY && hso->so_mig_virgin == 0)
				panic("New pkt after flush");

			if (sototcpcb(hso)->rcv_nxt == pkt->seq) {
				sototcpcb(hso)->seq_nxt = pkt->seq;
				sototcpcb(hso)->ack_nxt = pkt->ack;
			}  

			//SOMIG_PKT_UNLOCK(hso);

						
			if (throttle) {
				seq_throttle = seq;
				goto deliver;
			}
		} else {
			if (sototcpcb(hso)->t_snd_off != ppshd.snd_off) {
				sototcpcb(hso)->t_snd_off = ppshd.snd_off;
				sototcpcb(hso)->t_snd_off_local += ppshd.snd_off - sototcpcb(hso)->t_snd_off;
			}
			ip_input(m);
			hso->so_mig_pkt_consumption = 0;
		}

sendack:
		//if (synpkt || dontbuf || (throttle == 0)) {
		if (synpkt || dontbuf || (throttle == 0)) {
#ifdef SMCP
			tcpmig_replica_send_ack(smcp, hso, 0, ntohl(seq), ppshd.pri_ts); 
#else
			tcpmig_replica_send_ack(so, hso, 0, ntohl(seq), ppshd.pri_ts); 
#endif
			if (synpkt || dontbuf) {
				goto timer_reset;
			}
		}

deliver:
		/*
		 * Do the quick check to see if the packet buffer has any can 
		 * be delivered to TCPStack.
		 * If so deliver the mbuf into replica's ip_input path.
		 */
		do {
			ccount = 0;
			rcount = 0;
#ifdef SMCP
			tcpmig_flushpkt_internal(smcp, &ccount, &rcount, 0); 
#else
			tcpmig_flushpkt_internal(so, &ccount, &rcount, 0); 
#endif
		} while (ccount && rcount);

/*
CTR2(KTR_SPARE5, "Acc %d Rej %d", ccount, rcount); 
		if (ccount + rcount == 0) {
			CTR2(KTR_SPARE5, "%d rcvnumsack %u", __LINE__, htp->rcv_numsacks);
			for (int i=0;i<htp->rcv_numsacks;i++) {
				CTR3(KTR_SPARE5, "%d:s%u e%u", __LINE__,
				    htp->sackblks[i].start,
				    htp->sackblks[i].end);
			}
		}
*/
		//throttle = (rcount >= 5);
		//CTR2(KTR_SPARE5, "acc%d rej%d", ccount, rcount);
		//if (rcount > 10 && hso->so_mig_pkt_buffered > 80000)
			//panic("check");

		if (throttle || 
		    (ccount + rcount == 0 && sbspace(&hso->so_rcv) <= 0) ||
		    (sbspace(&hso->so_snd) > htp->t_maxseg)) {
#ifdef SMCP
			tcpmig_replica_send_ack(smcp, hso, TM_FLAG_THROTTLE, ntohl(seq_throttle), ppshd.pri_ts);  
#else
			tcpmig_replica_send_ack(so, hso, TM_FLAG_THROTTLE, ntohl(seq_throttle), ppshd.pri_ts);  
#endif
			sorwakeup(hso);
			//tcpmig_replica_send_ack(so, hso, 0, ntohl(seq_throttle));  
		}

timer_reset:
		/* if we have pending packets, start the timer for later
		 * delivery */
#ifdef SMCP
		if (!tcp_timer_active(htp, TT_SOMIG)) {
			if (TAILQ_EMPTY(&hso->so_mig_pkt))  
				tcp_timer_activate(htp, TT_SOMIG, TCPMIG_SLOWTIMO);
			else 
				tcp_timer_activate(htp, TT_SOMIG, TCPMIG_TIMO);
		}
#else
		if (!tcp_timer_active(tp, TT_SOMIG)) {
			if (TAILQ_EMPTY(&hso->so_mig_pkt)) 
				tcp_timer_activate(tp, TT_SOMIG, TCPMIG_SLOWTIMO);
			else
				tcp_timer_activate(tp, TT_SOMIG, TCPMIG_TIMO);
		}
#endif

		if (tcpmig_need_tcp_ack(hso)) {
			struct mbuf *ack_m;
			ack_m = tcpmig_compose_tcp_ack(hso);
			tcpmig_direct_ip_input(ack_m, sototcpcb(hso));
		}

	} else if (status == TM_STATUS_OK) {
		hinp = sotoinpcb(hso);
		hso->so_mig_smg_cpu = curcpu;
#ifndef SMCP
		/* Update CtlSo's bufsize in hso(use t_currctlso) */
		if (tp->t_currctlso == so->so_mig_pentry->id) {
			hso->so_mig_pkt_buffered_cso = ppsh->buf_size;
		}
#endif

#ifdef SOMIG_TIMING_DIAG
		if (tmth->stime != 0 && tmth->padding && hso->so_mig_timing_diag) {
			microtime(&tn);
			time_now = (uint32_t)(tn.tv_sec % 10000) * 1000000 + tn.tv_usec;
			// remove outliers
			if (time_now - tmth->stime > 1000000) {
				goto skip_timing;
			}
			//somig_timing_bucket_add(hso, time_now - tmth->stime);
			timing_diag_sum += time_now - tmth->stime;
			if (timing_diag_counter++ > 200000) {
				//CTR0(KTR_SPARE5, "========MSO========");
				printf("========MSO[%p - avg: %luus]========\n", 
				    hso,
				    timing_diag_sum / timing_diag_counter);
				/*
				for (int i=0;i<SOMIG_TIMING_BUCKET_COUNT;i++) {
					printf("DIAG[%d-%d]: %u\n", 
					    SOMIG_TIMING_BUCKET_INTERVAL * i,
					    SOMIG_TIMING_BUCKET_INTERVAL * (i+1),
					    timing_bucket[i]);
					timing_bucket[i] = 0;
				}
				*/
				timing_diag_sum = 0;
				timing_diag_counter = 0;
			}
		}
skip_timing:
#endif

		/* Filter the heartbeat packet */
		if (ppsh->flag & TM_FLAG_HEARTBEAT) {
CTR5(KTR_SPARE5, "[HTBT]rcvn %u ppsh %u sndm %u ppsh %u pkt empty?%d", htp->rcv_nxt, ppsh->rcv_nxt,
    htp->snd_max, ppsh->snd_max, TAILQ_EMPTY(&hso->so_mig_pkt));
			if (tcpmig_need_throttle(ppsh, htp)) {
CTR1(KTR_SPARE5, "[HTBT %d] throttle flag set", __LINE__);
				htp->t_throttle = 1;
			} else {
				htp->t_throttle = 0;
			}

			if (htp->t_throttle == 1) {
				if (ppsh->rcv_nxt > htp->rcv_nxt ||
				    ppsh->snd_max > htp->snd_max)
					htp->t_throttle = 0;
			}

			//goto done;
		}

#ifdef SMCP
		/* Update SMCP channel RTT */
		if (ppsh->pri_ts) {
			uint32_t t = tcp_ts_getticks() - ppsh->pri_ts;
			smcp_update_rtt(smcp, TCP_TS_TO_TICKS(t));
			/*
			CTR4(KTR_SPARE5, "%d: rtt %u pri_ts %u delta %u", __LINE__, 
			    ((u_int64_t)smcp_get_rtt(smcp) * tick) >> TCP_RTT_SHIFT,
			    ppsh->pri_ts, t);
			*/
		}
#endif

		/*
		 * Find the corresponding pkt in queue.
		 * Most cases the first pkt is the one we want, theoretically.
		 */
		TAILQ_FOREACH_SAFE(pkt, &hso->so_mig_pkt, list, temp) {
			ccount++;
			if (pkt->sent != 1) {
				rcount++;
				continue;
			}

			/* HS ACK = CLIENT SEQ + 1 during TCPHS */
			seq_off = PKTSYN(pkt->thflags);
			
			if ((ppsh->seq == pkt->seq) || 
			    SEQ_GEQ(ppsh->rcv_nxt, (pkt->seq+pkt->tlen)) ||
			    (pkt->gack == 0)) {
				
				if (hso->so_state & SS_ISDISCONNECTING ||
				    hso->so_state & SS_ISDISCONNECTED) {
					CTR2(KTR_SPARE5, 
					    "(%d): disconnected. freeing seq %u\n",
					    __LINE__, pkt->seq);
					break;
				}
			//if (th->th_ack >= pkt->seq + seq_off) {
				/* 
				 * Update gack in pkt and see if all replied.
				 * If so, we remove this pkt from queue and 
				 * deliver this packet to stack again.
				 */
#ifdef SMCP
				pkt->gack &= (((1<<SOMIG_MAXNODE)-1) - 
				    (1<<smcp->id));
#else
				pkt->gack &= (((1<<SOMIG_MAXNODE)-1) - 
				    (1<<so->so_mig_id));
#endif
				/*
				 * Check if we need to throttle the current one.
				 */
#ifdef SMCP
				if (smcp->state & SMCP_NORMAL) {
#else
				if (tp->t_state == TCPS_ESTABLISHED) {
#endif
					if (tcpmig_need_throttle(ppsh, htp)) {
CTR1(KTR_SPARE5, "%d: throttle flag set", __LINE__);
CTR5(KTR_SPARE5, "%d: ppshsm%u sm%u diff %u gt?%d", __LINE__, ppsh->snd_max,
    htp->snd_max, htp->snd_max-ppsh->snd_max, SEQ_GT(htp->snd_max, ppsh->snd_max));
						htp->t_throttle = 1;
					} else {
						htp->t_throttle = 0;
					}
				}

				if ((ppsh->flag & TM_FLAG_THROTTLE)) {
					//continue;
					if (hso->so_throttle == 0)
						hso->so_throttle = 1;//SOMIG_THROTTLE_COUNT;
				}
				
				if (pkt->gack == 0) {
					conti_flag = 0;
					/* 
					 * If seq is greater than rcv_nxt, then
					 * means we got a hole in between.
					 * To avoid SACK rexmt, we try to
					 * continue to see if we got any 
					 * reordered packet that can be delivered
					 * to fix this.
					 */
					//if (SEQ_GT(pkt->seq, htp->rcv_nxt) &&
					//    htp->t_state == TCPS_ESTABLISHED) {
					//	continue;
					//}
//CTR6(KTR_SPARE5,"%d: pri buf'd %u rso buf'd %u seq %u m%p mflg%u", __LINE__, hso->so_mig_pkt_buffered,
//	ppsh->buf_size, pkt->seq, pkt->m, pkt->m->m_flags);

					SOMIG_PKT_LOCK(hso);
					TAILQ_REMOVE(&hso->so_mig_pkt, pkt, list);
					SOMIG_PKT_UNLOCK(hso);

					/* 
					 * Deliver to stack again and pkt will 
					 * be consumed.
					 */
					//uint32_t orig_rcvn = htp->rcv_nxt;
					//uint32_t orig_tlen = pkt->tlen;

					orig_rn = htp->rcv_nxt;
					pkt->m->m_flags |= M_PKTHDR;
					//htp->ts_recent = 0;
					tcpmig_input_with_port(&pkt->m, &pkt->offp, 0, 
					    pkt->port, TM_PKT_SENDNOW, pkt);
		    
					if (pkt->flag & SOMIG_PKT_FLAG_SPLIT_M1) {
						conti_flag = 1;
					}

					/*
					if ((pkt->flag & SOMIG_PKT_FLAG_SPLIT_M1) ||
					    (pkt->flag & SOMIG_PKT_FLAG_SPLIT_M2)) {
						printf("--->tlen%u orn%u rn%u seq%u sbsp%ld\n", orig_tlen, orig_rcvn, htp->rcv_nxt, pkt->seq, sbspace(&hso->so_rcv)); 
					}
					*/


//if (htp->rcv_nxt - orig_rcvn < orig_tlen - 100 && orig_tlen > 100) {
//	printf("tlen%u orn%u rn%u seq%u sbsp%ld\n", orig_tlen, orig_rcvn, htp->rcv_nxt, pkt->seq, sbspace(&hso->so_rcv)); 
//}
//CTR6(KTR_SPARE5,"%d: pri buf'd %u rso buf'd %u seq %u c%u tl%u", __LINE__, hso->so_mig_pkt_buffered,
//	ppsh->buf_size, pkt->seq, htp->rcv_nxt - orig_rcvn, orig_tlen);
					uma_zfree(somig_pkt_zone, pkt);

					if (conti_flag)
						continue;
				}
				break;
			} 
		}

	}

//done:
	return (error);
}

static void	
#ifdef SMCP
tcpmig_replica_send_ack(struct smcpcb *smcp, struct socket *hso, uint32_t flag, 
    uint32_t seq, uint32_t pri_ts)
#else
tcpmig_replica_send_ack(struct socket *so, struct socket *hso, uint32_t flag, 
    uint32_t seq, uint32_t pri_ts)
#endif
{
	struct mbuf *m;
	struct ppshdr *ppsh;
	struct tcpcb *htp;

	htp = sototcpcb(hso);

	m = m_getm2(NULL, sizeof(struct ppshdr), M_NOWAIT, MT_DATA, 0);
	m->m_len = sizeof(struct ppshdr);
	ppsh = (struct ppshdr *)mtod(m, char *);
	/* host byte order */
	ppsh->seq = seq;
	ppsh->flag = flag;
	ppsh->rcv_nxt = htp->rcv_nxt;
	ppsh->snd_max = htp->snd_una;
	if (SEQ_GT(htp->rcv_nxt, seq)) {
		ppsh->snd_max = 0;
	}
	ppsh->buf_size = hso->so_mig_pkt_buffered;
	ppsh->pri_ts = pri_ts;
#ifdef SOMIG_TIMING_DIAG
	/* Invalidate timing diag info */
	//stime_from_mso = 0;
#endif

#ifdef SMCP
	tcpmig_sendreply_m((void *)smcp, TM_CMD_PACKET, TM_STATUS_OK, m);
#else
	tcpmig_sendreply_m(so, TM_CMD_PACKET, TM_STATUS_OK, m);
#endif
}


static void	
tcpmig_compose_migration_packet(struct mbuf *m, int flag)
{
	char			*roff;
	int			msize;
	struct tmhdr		*tmth;
	struct tmmigration	*tmmig;

	msize = sizeof(struct tmhdr) + sizeof(struct tmmigration);
	m = m_getm2(NULL, msize, M_NOWAIT, MT_DATA, 0);
	m->m_len = msize;

	roff = mtod(m, char *);
	tmth = (struct tmhdr *)roff;
	tmth->magic = TM_MAGIC;
	tmth->cmd = TM_CMD_MIGRATE;
	tmth->status = TM_STATUS_OK;
	tmth->exlen = sizeof(struct tmmigration);
	tmth->len = sizeof(struct tmhdr) + sizeof(struct tmmigration);

	roff = (char *)tmth + sizeof(struct tmmigration);
	tmmig = (struct tmmigration *)roff;

	tmmig->flag = flag;
}

/*
 * Connect to a new node on TCPMIG layer (HBO)
 */
int
#ifdef SMCP
tcpmig_nodeconnect(struct socket *hso, struct tmnode *node, 
    uint32_t p_addr, uint16_t p_port, uint32_t l_addr)
#else
tcpmig_nodeconnect(struct socket *hso, struct tmnode *node)
#endif
{
	int error = 0;
#ifdef SMCP
	struct smcpcb *smcp;
#else
	struct socket *ctlso;
#endif
	struct somig_peer_entry *peer;

	/* 
	 * Create SO and connect in TCP
	 */
#ifdef SMCP
	tcpmig_newsmcpcb((void **)&smcp, hso);
	smcp->f_addr = ntohl(node->ip);
	CURVNET_SET(smcp->inp->inp_socket->so_vnet);
	smcp_bind((void *)smcp, p_addr, p_port, l_addr, 0);
	CURVNET_RESTORE();
#else
	somig_create(&ctlso, hso);
	ctlso->so_mig_role = SOMIG_CTL;
	ctlso->so_mig_hostso = hso;
	somig_connect_tuple(ctlso, hso, node->ip, node->port);
#endif

	peer = (struct somig_peer_entry *)malloc(
	    sizeof(struct somig_peer_entry), M_TEMP, M_NOWAIT | M_ZERO);
	peer->id = node->id;
	peer->role = node->role;
	peer->state = SOMIG_SO_PENDING;
	peer->ip = node->ip;
#ifdef SMCP
	peer->smcpcb = smcp;
	peer->hso = hso;
	smcp->id = node->id;
	smcp->so_mig_pentry = peer;
#else
	peer->port = node->port;
	peer->so = ctlso;
	ctlso->so_mig_id = node->id;
	ctlso->so_mig_pentry = peer;
#endif
	if (!somig_add_peer_to_hostso(hso, peer, 0)) {
		free(peer, M_TEMP);
		printf("Cannot add so to peer list\n");
	}

	/* 
	 * HS in tcpmig layer
	 */
#ifdef SMCP
	tcpmig_soconnect(smcp, SOMIG_V_MAJOR, SOMIG_V_MINOR, SOMIG_V_FEATURE);
#else
	tcpmig_soconnect(ctlso, SOMIG_V_MAJOR, SOMIG_V_MINOR, SOMIG_V_FEATURE);
#endif

	return (error);
}

/*
 * Convert(Copy) from somig_peer_entry to tmnode
 */
void 
tcpmig_spetotn(struct somig_peer_entry *peer, struct tmnode *node, int self)
{
	KASSERT(node != NULL || peer != NULL, ("%s: NULL input.", __func__));
#ifndef SMCP
	if (self)
		KASSERT(peer->so->so_mig_hostso != NULL, 
		    ("Insert peer to list first."));
#endif
	node->role = peer->role;

	if (self) {
#ifdef SMCP
		node->id = peer->id;
		node->ip = htonl(((struct smcpcb *)peer->smcpcb)->l_addr); 
		node->p_addr = peer->p_addr;
		node->p_port = peer->p_port;
#else
		struct inpcb *inp;

		node->id = peer->so->so_mig_hostso->so_mig_id;
		inp = sotoinpcb(peer->so->so_mig_hostso->so_mig_ctl);
		KASSERT(inp != NULL, ("%s:%d Null inp", __func__, __LINE__));
		node->port = inp->inp_lport; 
		node->ip = inp->inp_laddr.s_addr;
		if (node->ip == 0) {
			/* If INADDR_ANY is used, we just use the ip of curr CtlSo */
		        inp = sotoinpcb(peer->so);
			node->ip = inp->inp_laddr.s_addr;
		}
#endif
	} else {
		node->role = peer->role;
		node->id = peer->id;
		node->ip = peer->ip;
#ifdef SMCP
		node->p_addr = peer->p_addr;
		node->p_port = peer->p_port;
#else
		node->port = peer->port;
#endif
	}
}

/*
 * Copy essential states from socket into tmstate
 */
void
tcpmig_getstates(struct socket *so, struct tmstate *tms)
{
	struct inpcb *inp;
	struct tcpcb *tp;

	inp = sotoinpcb(so);
	tp = sototcpcb(so);

	INP_WLOCK_ASSERT(inp);
	KASSERT(tms != NULL, ("NULL tms"));


	/*
	 * If this socket is connected, we grab the local addr from its route. 
	 * On FreeBSD 13 and newer, the old rtentry is replaced by the new 
	 * nhop_object struct. 
	 */
	if (inp && inp->inp_route.ro_nh && inp->inp_route.ro_nh->nh_ifa) {
		tms->laddr = IA_SIN(ifatoia(inp->inp_route.ro_nh->nh_ifa))->sin_addr.s_addr;
	} else
		tms->laddr = inp->inp_laddr.s_addr;
	tms->faddr = inp->inp_faddr.s_addr;
	tms->lport = inp->inp_lport;
	tms->fport = inp->inp_fport;

	tms->ts_offset = tp->ts_offset;
	tms->ts = tp->ts_recent_age;
	tms->ts_ecr = tp->ts_recent;

	tms->snd_una = tp->snd_una;
	tms->snd_max = tp->snd_max;
	tms->snd_nxt = tp->snd_nxt;
	tms->snd_up = tp->snd_up;
	tms->last_ack_sent = tp->last_ack_sent;
	tms->rcv_up = tp->rcv_up;
	tms->rcv_nxt = tp->rcv_nxt;
	tms->rcv_adv = tp->rcv_adv;
	tms->request_r_scale = tp->request_r_scale;
	tms->snd_wl1 = tp->snd_wl1;
	tms->snd_wl2 = tp->snd_wl2;
	tms->irs = tp->irs;
	tms->iss = tp->iss;
	tms->rcv_wnd = tp->rcv_wnd;
	tms->snd_wnd = tp->snd_wnd;
	tms->snd_cwnd = tp->snd_cwnd;
	tms->t_state = tp->t_state;
}

/*
 * Apply tmstate struct into a socket
 * Turn a non-connected replica socket into connected or lisstening state 
 * by using tmstate struct sent from primary
 */
void 
#ifdef SMCP
tcpmig_setstates(struct socket *so, void *smcp, 
    struct tmstate *tms, int init)
#else
tcpmig_setstates(struct socket *so, struct socket *ctl_so, 
    struct tmstate *tms, int init)
#endif
{
	struct inpcb *inp, *oinp;
	struct tcpcb *tp;
	struct sockaddr nam;
	u_short lport, fport;
	uint32_t laddr, faddr;
	int error, backlog = 1;

	inp = sotoinpcb(so);
	tp = sototcpcb(so);

	INP_WLOCK_ASSERT(inp);
	KASSERT(tms != NULL, ("NULL tms"));

	/* Compose fake sockaddr struct for client to send in */
	/* We need to reverse the value as the data was from 
	 * peer inp, which uses NBO to store IP & PORT
	 */
	laddr = ntohl(tms->laddr);
	lport = ntohs(tms->lport);
	faddr = ntohl(tms->faddr);
	fport = ntohs(tms->fport);

	so->so_mig_primary_addr = htonl(laddr);

	nam.sa_len = sizeof(struct sockaddr_in);
	nam.sa_family = AF_INET;
	/* local Port */
	nam.sa_data[0] = (lport>>8) & 0xff;
	nam.sa_data[1] = lport & 0xff;
	/* local IP */
	/* Don't use any loopback type IP, ip_input will drop per RFC1122 */
	if (tms->t_state == TCPS_ESTABLISHED) {
		nam.sa_data[2] = 0;
		nam.sa_data[3] = 0;
		nam.sa_data[4] = 0;
		nam.sa_data[5] = 0;
		bzero(&nam.sa_data[6], 8);
	} else if (tms->t_state == TCPS_LISTEN) {
		uint32_t addr;

#ifdef SMCP
		//addr = htonl(laddr);
		addr = htonl(((struct smcpcb *)so->smcpcb)->l_addr);
#else
		KASSERT(so->so_mig_ctl != NULL, ("Null CtlSO"));
		addr = ((struct inpcb *)sotoinpcb(ctl_so))->inp_laddr.s_addr;
#endif
		addr = ntohl(addr);
		nam.sa_data[2] = (addr>>24) & 0xff;
		nam.sa_data[3] = (addr>>16) & 0xff;
		nam.sa_data[4] = (addr>>8) & 0xff;
		nam.sa_data[5] = addr & 0xff;

		bzero(&nam.sa_data[6], 8);
	} else
		panic("Unknown TCP state in SYNC message.");

	INP_HASH_WLOCK(&V_tcbinfo);
	error = in_pcbbind(inp, &nam, so->so_cred);
	if (error) {
		printf("%s: in_pcbbind error %d\n", __func__, error);
	}
	
	/* foreign Port*/
	nam.sa_data[0] = (fport>>8) & 0xff;
	nam.sa_data[1] = fport & 0xff;
	/* foreign IP */
	nam.sa_data[2] = (faddr>>24) & 0xff;
	nam.sa_data[3] = (faddr>>16) & 0xff;
	nam.sa_data[4] = (faddr>>8) & 0xff;
	nam.sa_data[5] = faddr & 0xff;

	laddr = inp->inp_laddr.s_addr;
	lport = inp->inp_lport;

	if (tms->t_state == TCPS_ESTABLISHED) {
		error = in_pcbconnect_setup(inp, &nam, &laddr, &lport,
		 &inp->inp_faddr.s_addr, &inp->inp_fport, &oinp, so->so_cred);
		if (error) {
			printf("in_pcbconnect_setup error: %d\n", error);
			panic("Cannot proceed.");
		}
		in_pcbrehash(inp);

		inp->inp_laddr.s_addr = laddr;
	}
	
	INP_HASH_WUNLOCK(&V_tcbinfo);

	so->so_options &= ~SO_NEEDSYNC;

	if (init) {
		if (tms->t_state == TCPS_ESTABLISHED) {
			/* init socket object */
			soisconnected(so);
			so->so_options &= ~SO_ACCEPTCONN;
			tcp_state_change(tp, TCPS_ESTABLISHED);

			/* To sync the local time with PRIMARY, we use such
			 * formula to estimate:
			 *
			 * local_ts = tick + ts_offset
			 * ts_offset = (remote_tick + 1/2 * (tick - ts_ecr)) - tick 
			 *	     = (remote_tick - 1/2 * tick - 1/2 * ts_ecr
			 *
			 * */
			tp->ts_offset = tms->ts - (tcp_ts_getticks()<<1) - (tms->ts_ecr<<1);
			//tp->ts_offset = tms->ts_offset;

			tp->snd_una = tms->snd_una;
			tp->snd_max = tms->snd_max;
			
			tp->ack_max = tms->snd_una;
			tp->snd_nxt = tms->snd_nxt;
			tp->snd_up = tms->snd_up;
			tp->last_ack_sent = tms->last_ack_sent;
			tp->rcv_up = tms->rcv_up;
			tp->rcv_nxt = tms->rcv_nxt;
			tp->rcv_adv = tms->rcv_adv;
			tp->request_r_scale = tms->request_r_scale;
			tp->snd_wl1 = tms->snd_wl1;
			tp->snd_wl2 = tms->snd_wl2;

			tp->rcv_wnd = tms->rcv_wnd;
			tp->snd_wnd = tms->snd_wnd;
			tp->snd_cwnd = tms->snd_cwnd;
		} else if (tms->t_state == TCPS_LISTEN) {
			tcp_state_change(tp, TCPS_LISTEN);
			SOCK_LOCK(so);
			solisten_proto(so, backlog); 
#ifdef TCP_OFFLOAD
			if ((so->so_options & SO_NO_OFFLOAD) == 0)
				tcp_offload_listen_start(tp);
#endif
			so->sol_qlimit = SOMIG_LISTEN_BACKLOG;
			SOCK_UNLOCK(so);

			if (IS_FASTOPEN(tp->t_flags))
				tp->t_tfo_pending = tcp_fastopen_alloc_counter();
		} else 
			panic("Not impl'd");
	}
	
	/* Make snd_wnd large */
	//tp->snd_wnd = 4194240;
	//tp->snd_cwnd = 4194240;
	tp->irs = tms->irs;
	tp->iss = tms->iss;
}

/*
 * Calculate checksums for ip/tcp header
 */
void
tcpmig_cksum(struct mbuf *m, struct ip *ip, struct tcphdr *th)
{
	int		len, optlen;
	struct ipovly	*ipov;
	char		ih_x1[9];
	u_short		ih_len;

	KASSERT(mtod(m, caddr_t) == (caddr_t)ip, ("IP hdr is not in mbuf"));
	
	/* 
	 * must set to 0 before calculating cksum since the cksum is
	 * the complement of the orig ip hdr, which could zero out 
	 * at the validation stage.
	*/
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum(m, sizeof(struct ip));
 
	goto test;
	ipov = (struct ipovly *)ip;

	/* user payload len */
	optlen = (th->th_off << 2) - sizeof(struct tcphdr);
	len = m->m_pkthdr.len - sizeof(struct tcpiphdr) - optlen;
			
	KASSERT(sizeof(ipov->ih_x1) == 9, ("ipov->ph+x1 size has been changed"));
	bcopy(ipov->ih_x1, ih_x1, sizeof(ipov->ih_x1));
	bzero(ipov->ih_x1, sizeof(ipov->ih_x1));
	ih_len = ipov->ih_len;
	ipov->ih_len = htons(len + optlen + sizeof(struct tcphdr));

	th->th_sum = 0;
	th->th_sum = in_cksum(m, optlen + len + sizeof(struct tcpiphdr));

	bcopy(ih_x1, ipov->ih_x1, sizeof(ipov->ih_x1));
	ipov->ih_len = ih_len;

	m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
	m->m_pkthdr.csum_flags = 0;

	/*
	 * TEST
	 */
test:
	m->m_pkthdr.csum_flags |= CSUM_DATA_VALID;
	m->m_pkthdr.csum_flags |= CSUM_PSEUDO_HDR;
	m->m_pkthdr.csum_data = 0xffff;

}

/*
 * Remove payloads from packet. Mainly used to split PUSH+ACK packet in HS
 */
void
tcpmig_strippld(struct mbuf *m, int pld_size)
{
	struct ip *ip;
	struct tcphdr *th;

	KASSERT(m != NULL, ("NULL mbuf"));
	
	ip = mtod(m, struct ip *);
	th = (struct tcphdr *)((caddr_t)ip + sizeof(struct ip));

	ip->ip_len = ntohs(ip->ip_len);
	ip->ip_len -= pld_size;
	ip->ip_len = htons(ip->ip_len);

	m_adj(m, (-1) * pld_size);

	tcpmig_cksum(m, ip, th);
}

/*
 * Flush all buffered pkts to replicas
 */
void
tcpmig_flushpkt(struct socket *so)
{
	struct somig_pkt_entry *pkt;
	struct epoch_tracker et;

	NET_EPOCH_ENTER(et);
	TAILQ_FOREACH(pkt, &so->so_mig_pkt, list) {
		if (pkt->sent)
			continue;
		/*tcpmig_pktinput(pkt->m, pkt, sotoinpcb(so), pkt->drop_hdrlen, pkt->tlen);*/
		tcpmig_pktinput(pkt->m, so, &pkt->offp, pkt->seq, pkt->thflags, 
		    pkt->drop_hdrlen, pkt->tlen, NULL, 0, pkt->port);
		pkt->sent = 1;
	}
	NET_EPOCH_EXIT(et);
}

/*
 * Called in tcp_output. Helps to keep flushing packets continuously when
 * conditions are met.
 */
void
tcpmig_flushpkt_continuous(struct socket *so, int output_len)
{
	int acc, rej;

	if (output_len <= 1) {
		return;
	}
	
#ifdef SMCP
	tcpmig_flushpkt_internal(so->smcpcb, &acc, &rej, 1);
#else
	tcpmig_flushpkt_internal(so, &acc, &rej, 1);
#endif
}

/*
 * When migration, all buffered packets need to be flushed into the socket to
 * catch up the TCP state
 */
void
#ifdef SMCP
tcpmig_flushpkt_migration(void *smcp, int migration)
#else
tcpmig_flushpkt_migration(struct socket *so, int migration)
#endif
{
	struct socket *hso;
	int sobuf_avail = 0;
#ifndef SMCP
	struct tcpcb *tp;
#endif
	struct tcpcb *htp;
	struct inpcb *hinp;
	//struct mbuf *ack_m = NULL;

#ifdef SMCP
	if (!smcp) return;
	hso = (struct socket *)(((struct smcpcb *)smcp)->inp->inp_socket);
#else
	hso = so->so_mig_hostso;
	tp = sototcpcb(so);
#endif
	htp = sototcpcb(hso);
	hinp = sotoinpcb(hso);

	if (sototcpcb(hso)->rolechange == 0) 
		return;

	if (migration && TAILQ_EMPTY(&hso->so_mig_pkt))
		return;

#ifdef SMCP

CTR5(KTR_SPARE5, "%d: pkt buf empty ? %d rn%u sm%u am%u", __LINE__, 
    TAILQ_EMPTY(&hso->so_mig_pkt), htp->rcv_nxt, htp->snd_max, htp->ack_max);
	if (tcp_timer_active(htp, TT_SOMIG)) {
		tcp_timer_activate(htp, TT_SOMIG, 0);
	}

#ifdef SOMIG_MIG_BRKDN
	//SMGTPRT("Flush: Calling flushpkt func.");
#endif

	tcpmig_flushpkt_internal(smcp, NULL, NULL, 0);
#else
	if (tcp_timer_active(tp, TT_SOMIG)) {
		tcp_timer_activate(tp, TT_SOMIG, 0);
	}
	tcpmig_flushpkt_internal(so, NULL, NULL, 0);
#endif

#ifdef SOMIG_MIG_BRKDN
	//SMGTPRT("Flush: Flushing sndbuf leftovers.");
#endif
	sobuf_avail = sbavail(&hso->so_snd);
	if (sobuf_avail) {
		//printf("b4: so %p sbavail%d su%u sm%u am%u\n", hso, sobuf_avail,
		//    htp->snd_una, htp->snd_max, htp->ack_max);
		INP_WLOCK(hinp);
		(void)htp->t_fb->tfb_tcp_output(htp);
		INP_WUNLOCK(hinp);
		//printf("Af: so %p sbavail%d su%u sm%u am%u\n", hso, sobuf_avail,
		//    htp->snd_una, htp->snd_max, htp->ack_max);
	}

	if (htp->t_state == TCPS_ESTABLISHED) {
		//ack_m = tcpmig_compose_tcp_ack(hso);
		//tcpmig_direct_ip_input(ack_m, htp);
	}

	/* Restart the timer if pkt queue is not empty */
	//if (SEQ_LT(htp->snd_max, htp->ack_max)) { 
	if (!TAILQ_EMPTY(&hso->so_mig_pkt) && SEQ_LT(htp->snd_max, htp->ack_max)) {
#ifdef SMCP
		tcp_timer_activate(htp, TT_SOMIG, TCPMIG_TIMO);
#else
		tcp_timer_activate(tp, TT_SOMIG, TCPMIG_TIMO);
#endif
	} else {
		//INP_WLOCK(hinp);
		tcpmig_rolechange_done(hso);
		//INP_WUNLOCK(hinp);
	}
}

static void
#ifdef SMCP
tcpmig_flushpkt_internal(struct smcpcb *smcp, int *acc, int *rej, int skip_sent)
#else
tcpmig_flushpkt_internal(struct socket *so, int *acc, int *rej, int skip_sent)
#endif
{
	struct somig_pkt_entry *pkt, *tmp;
	struct socket *hso;
	struct tcpcb *htp;
	struct inpcb *inp;
	uint32_t off;
	//struct mbuf *ack_m = NULL;
	//int lowat;
	uint32_t orcvn;

	if (acc) *acc = 0;
	if (rej) *rej = 0;

#ifdef SMCP
	if (!smcp || !smcp->inp)
		return;
	hso = (struct socket *)smcp->inp->inp_socket;
	htp = sototcpcb(hso);
	inp = sotoinpcb(hso);

	if (FLUSH_PACKET(htp)) {
		return;
	}
	FLUSH_PACKET_BEGIN(htp);

	KASSERT(hso->so_mig_role != SOMIG_PRIMARY || htp->rolechange == 1, ("PRIMARY in flushpkt"));

	SOMIG_DELIVERY_LOCK(hso);
	if (!(hso && sototcpcb(hso) && (hso->so_state & SS_ISCONNECTED))) {
		FLUSH_PACKET_END(htp);
		SOMIG_DELIVERY_UNLOCK(hso);
		return;
	}
#else
	hso = so->so_mig_hostso;
	if (!hso)
	    return;
	htp = sototcpcb(hso);
	inp = sotoinpcb(hso);

	if (FLUSH_PACKET(htp)) {
		return;
	}


if (0 && sototcpcb(hso)->rolechange == 1) {
	CTR2(KTR_SPARE4, "%d: deliv ts %u", __LINE__, tcp_ts_getticks()); 
}

	FLUSH_PACKET_BEGIN(htp);
#endif

	TAILQ_FOREACH_SAFE(pkt, &hso->so_mig_pkt, list, tmp) {
		if (hso->so_state & SS_ISDISCONNECTING ||
		    hso->so_state & SS_ISDISCONNECTED ||
		    pkt->m == NULL) {
			TAILQ_REMOVE(&hso->so_mig_pkt, pkt, list);
			hso->so_mig_pkt_buffered -= pkt->tlen;
			if (pkt->m != NULL) {
				m_freem(pkt->m);
				pkt->m = NULL;
			}
			uma_zfree(somig_pkt_zone, pkt);
			continue;
		}

		if (skip_sent && pkt->sent) {
			continue;
		}

		/* Remove obsolete packet */
		if (SEQ_GEQ(sototcpcb(hso)->rcv_nxt, (pkt->seq + pkt->tlen)) &&
		    SEQ_GEQ(sototcpcb(hso)->snd_una, pkt->ack)) {
			TAILQ_REMOVE(&hso->so_mig_pkt, pkt, list);
			hso->so_mig_pkt_buffered -= pkt->tlen;
			if (pkt->m) {
				m_freem(pkt->m);
				pkt->m = NULL;
			}
			uma_zfree(somig_pkt_zone, pkt);
			continue;
		}

		tcpmig_updatehdr_tcp_off(pkt, sototcpcb(hso));
		/* Perform number-based TCP state check */
		if (tcpmig_pktstate_check(pkt, sototcpcb(hso))) {
			CTR6(KTR_SPARE5, "REJ->s%u a%u rn %u sm%u bufd %u sba%u", 
			    pkt->seq, 
			    pkt->ack,
			    sototcpcb(hso)->rcv_nxt,
			    sototcpcb(hso)->snd_max,
			    hso->so_mig_pkt_buffered,
			    sbavail(&hso->so_snd));

			if (sototcpcb(hso)->rcv_nxt == pkt->seq) {
				sototcpcb(hso)->seq_nxt = pkt->seq;
				sototcpcb(hso)->ack_nxt = pkt->ack;
				if (SEQ_LT(sototcpcb(hso)->snd_max, pkt->ack)) {
					sorwakeup(hso);
					break;
				}
			} 

			if (rej) {
				(*rej)++;
			}
			continue;
		}

		/* 
		 * If rcvbuf doesn't have enough space for incoming pkt, pause
		 * curthr and let userspace app consumes from rcvbuf
		 */
		if (sbspace(&hso->so_rcv) <= pkt->tlen) {
			/* Rely on timer to wake us up again */
			CTR1(KTR_SPARE5, "sbspace %d, skip delivery", sbspace(&hso->so_rcv));
			//pause("bcastth", hz / 100);
			goto send_ack;
		}

		if (pkt->m == NULL) {
CTR1(KTR_SPARE5, "%d: m got consumed bc composed ack", __LINE__);
			printf("%d composed ack acked some data\n", __LINE__);
			panic("aaa");
			TAILQ_REMOVE(&hso->so_mig_pkt, pkt, list);
			hso->so_mig_pkt_buffered -= pkt->tlen;
			if (pkt->m != NULL)
				m_freem(pkt->m);
			uma_zfree(somig_pkt_zone, pkt);
			continue;
		}

		/* Update ack based on t_snd_off */
		tcpmig_updatehdr_tcp_off(pkt, sototcpcb(hso));

		tcpmig_updatehdr_tcp(pkt->m, hso, pkt->tlen);

		orcvn = sototcpcb(hso)->rcv_nxt;
		sototcpcb(hso)->t_packet_ctlso = 1;
		tcpmig_ipinput(pkt, hso);
		sototcpcb(hso)->t_packet_ctlso = 0;
		sorwakeup(hso);

		/*
		 * Current packet was rejected by RSO.
		 */
		if (pkt->m != NULL) {
			pkt->rej_count++;
			/*
			 * Experimental: 
			 *  IF, rej_count is greater than REJ_THRES(2)
			 * AND, theres no missing holes,
			 *THEN, we remove this packet from queue.
			 */
			if (0 && pkt->rej_count > 2 &&
			    sototcpcb(hso)->rcv_numsacks == 0) {
				TAILQ_REMOVE(&hso->so_mig_pkt, pkt, list);
				hso->so_mig_pkt_buffered -= pkt->tlen;
				CTR3(KTR_SPARE5, "%d: rm'd seq%u rn%u",
				    __LINE__, pkt->seq, sototcpcb(hso)->rcv_nxt);
				if (pkt->m != NULL)
					m_freem(pkt->m);
				uma_zfree(somig_pkt_zone, pkt);
				continue;
			}

			if (rej && (sototcpcb(hso)->rcv_nxt == orcvn))
				(*rej)++;
			continue;
		}
		
		/*
		 * If got properly delivered(based on tcp states) remove from
		 * queue.
		 */
		if (SEQ_GEQ(sototcpcb(hso)->rcv_nxt, pkt->seq + pkt->tlen)) {
			if (acc)
				(*acc)++;

if (0 && sototcpcb(hso)->rolechange == 1) {
    CTR6(KTR_SPARE4, "ACC: ts%u su%u sn%u sm%u am%u rn%u",
	tcp_ts_getticks(), sototcpcb(hso)->snd_una, sototcpcb(hso)->snd_nxt,
	sototcpcb(hso)->snd_max, sototcpcb(hso)->ack_max, sototcpcb(hso)->rcv_nxt);
    CTR4(KTR_SPARE4, "sw%u cw%u sba%u pkt%u", 
	sototcpcb(hso)->snd_wnd, sototcpcb(hso)->snd_cwnd,
	sbavail(&hso->so_snd), hso->so_mig_pkt_buffered);
}
			
			/* Update snd_off_pri */
			if (sototcpcb(hso)->t_snd_off != pkt->snd_off) {
				off = pkt->snd_off - sototcpcb(hso)->t_snd_off;
				sototcpcb(hso)->t_snd_off = pkt->snd_off;
				sototcpcb(hso)->t_snd_off_local += off;
				//sototcpcb(hso)->snd_max += off;
			}

			TAILQ_REMOVE(&hso->so_mig_pkt, pkt, list);
			hso->so_mig_pkt_buffered -= pkt->tlen;
			uma_zfree(somig_pkt_zone, pkt);
		}
	}

	/* 
	 * As a part of ACKCompression, always feed an ACK to tcp stack after
	 * delivery.
	 */
send_ack:
	if (tcpmig_need_tcp_ack(hso)) {
		struct mbuf *ack_m;
		ack_m = tcpmig_compose_tcp_ack(hso);
		tcpmig_direct_ip_input(ack_m, sototcpcb(hso));
	}

	FLUSH_PACKET_END(htp);
#ifdef SMCP
	SOMIG_DELIVERY_UNLOCK(hso);
#endif

	if (htp->rolechange == 1) {
		if (TAILQ_EMPTY(&hso->so_mig_pkt) && SEQ_GEQ(htp->snd_max, htp->ack_max)) { 
			//INP_WLOCK(sotoinpcb(hso));
			tcpmig_rolechange_done(hso);
			//INP_WUNLOCK(sotoinpcb(hso));
		}
	}
}

void
tcpmig_flushpkt_timo(struct socket *so)
{
#ifdef SMCP
	struct somig_peer_entry *peer;
#endif
	struct epoch_tracker et;
	struct tcpcb *tp;
	struct tcpcb *htp;
	struct socket *hso;
	//struct mbuf *ack_m = NULL;
	int acc = 0, rej = 0;
	int snd_avail = 0;
	
#ifdef SMCP
	hso = so;
	tp = sototcpcb(hso);
#else
	tp = sototcpcb(so);
	hso = so->so_mig_hostso;
#endif
	htp = sototcpcb(hso);

	if (hso->so_state & SS_ISDISCONNECTING ||
	    hso->so_state & SS_ISDISCONNECTED) {
		tcp_timer_activate(tp, TT_SOMIG, 0);
		return;
	}

	/* Cancel the activated timer */
	if (tcp_timer_active(tp, TT_SOMIG)) {
		tcp_timer_activate(tp, TT_SOMIG, 0);
		if (hso->so_mig_role != SOMIG_REPLICA && hso->so_mig_virgin == 0 && tp->rolechange == 0) {
			/* Stop the timer after promotion */
			return;
		}
	}

	if (hso->so_mig_role == SOMIG_REPLICA) {
		/* Flush the packet */
		NET_EPOCH_ENTER(et);
#ifdef SMCP
		tcpmig_flushpkt_internal(hso->smcpcb, &acc, &rej, 0);
#else
		tcpmig_flushpkt_internal(so, &acc, &rej, 0);
#endif
		snd_avail = sbavail(&hso->so_snd);
		if (snd_avail && SEQ_GT(htp->ack_max, htp->snd_una) &&
		    SEQ_GT(htp->snd_max, htp->snd_una)) {
			struct mbuf *ack_m;
			ack_m = tcpmig_compose_tcp_ack(hso);
			tcpmig_direct_ip_input(ack_m, sototcpcb(hso));
		}

		NET_EPOCH_EXIT(et);

		if (htp->t_state == TCPS_ESTABLISHED) {
			//ack_m = tcpmig_compose_tcp_ack(hso);
			//tcpmig_direct_ip_input(ack_m, sototcpcb(hso));
		}

		/* Send back an ACK to primary in case it stuck in throttling mode */
#ifdef SMCP
		TAILQ_FOREACH(peer, &hso->so_mig_peer, list) {
			if (peer->role == SOMIG_PRIMARY) {
				tcpmig_replica_send_ack(peer->smcpcb, hso, TM_FLAG_HEARTBEAT, 0, 0); 
				break;
			}
		}
#else
		tcpmig_replica_send_ack(so, hso, TM_FLAG_HEARTBEAT, 0, 0);
#endif
		/* Start the timer if theres buffer packet */
		if (TAILQ_EMPTY(&hso->so_mig_pkt))
			tcp_timer_activate(tp, TT_SOMIG, TCPMIG_SLOWTIMO);
		else
			tcp_timer_activate(tp, TT_SOMIG, TCPMIG_TIMO);
	} else if (hso->so_mig_role == SOMIG_PRIMARY) {
		/* Send an ACK to client if necessary for rexmt */
		return;

		if (!tcp_timer_active(tp, TT_SOMIG)) {
			tcp_timer_activate(tp, TT_SOMIG, TCPMIG_SLOWTIMO);
		}
	} else {
		// do nothing
	}
}

/*
 * Send a message to a node
 *
 * Notes for inp lock:
 *  If send function was called from an ctlso input routine, then inp was locked
 *  before thus the caller does NOT need to lock it seperately.
 *  However, if the caller was local (for sending to message to remote node),
 *  then most likely the inpm->m_pkthdr.csum_data need to be locked seperately. 
 */
static int
#ifdef SMCP
tcpmig_send(struct mbuf *m, struct smcpcb *smcp)
#else
tcpmig_send(struct mbuf *m, struct tcpcb *tp)
#endif
{
#ifdef SMCP
	return (tcpmig_send_internal(m, smcp, 0));
#else
	return (tcpmig_send_internal(m, tp, 0));
#endif
}

static int
#ifdef SMCP
tcpmig_send_internal(struct mbuf *m, struct smcpcb *smcp, int flag)
#else
tcpmig_send_internal(struct mbuf *m, struct tcpcb *tp, int flag)
#endif
{
	int error;
#ifdef SMCP
	int sid = 0, pid = 0;
	if (smcp->inp->inp_socket) {
		sid = smcp->inp->inp_socket->so_mig_sid;
		pid = smcp->inp->inp_socket->so_mig_pid;
	}
	error = smcp->smcp_output(smcp, m, flag, pid, sid);
	return (error);
#else
	struct inpcb *inp;
	struct socket *so;

	KASSERT(tp != NULL, ("%s: NULL tp.", __func__));
	inp = tp->t_inpcb;
	KASSERT(inp != NULL, ("%s: NULL inp.", __func__));
	so = inp->inp_socket;
	KASSERT(so != NULL, ("%s: NULL so.", __func__));
	//KASSERT(!INP_WLOCKED(inp), ("inp lock owned by curthr"));
	//if (!INP_WLOCKED(inp)) {
	//	INP_WLOCK(inp);
	//	locked = 1;
	//}
	if (m != NULL) {
		//sbflush(&so->so_snd);
		sbappendstream(&so->so_snd, m, 0);
	}
	CURVNET_SET(so->so_vnet);
	error = tp->t_fb->tfb_tcp_output(tp);
	CURVNET_RESTORE();
	//if (locked)
	//	INP_WUNLOCK(inp);
#endif
	return error;
}


/*
 * Broadcast a message to all [replicas].
 */
static int
tcpmig_bcast(struct mbuf *m, struct tcpcb *tp)
{
	return (tcpmig_bcast_internal(m, tp, 0));
}

static int	
tcpmig_bcast_internal(struct mbuf *m, struct tcpcb *tp, int flag)
{
	struct socket *so;
	struct somig_peer_entry *peer;
	struct mbuf *bm;
	int error, idx = 0, extr = 1;

	so = tp->t_inpcb->inp_socket;
	KASSERT(so != NULL, ("%s: NULL so.", __func__));
	KASSERT(so->so_mig_role != SOMIG_NONE, ("%s: Non-SOMIG so.", __func__));

	if (so->so_state & SS_ISDISCONNECTING || so->so_state & SS_ISDISCONNECTED)
		return (0);

	//SOCK_LOCK(so);
	TAILQ_FOREACH(peer, &so->so_mig_peer, list) {
		if (peer == NULL) {
			//SOCK_UNLOCK(so);
			return (0);
		}
		if (peer->state != SOMIG_SO_CONNECTED) {
			CTR1(KTR_SPARE5, "%u peer is not connected.\n", tcp_ts_getticks());
			continue;
		}
		if (idx < so->so_mig_peer_size - 1) {
			bm = m_dup(m, M_NOWAIT);
			//bm = m_copym(m, 0, M_COPYALL, M_NOWAIT);
		} else {
			bm = m;
			extr = 0;
		}
		KASSERT(bm != NULL, ("Null MBUF"));
#ifdef SMCP
		error = tcpmig_send_internal(bm, peer->smcpcb, flag);
#else
		KASSERT(!INP_WLOCKED(sotoinpcb(peer->so)), 
		    ("Potential deadlk: INP locked."));
		INP_WLOCK(sotoinpcb(peer->so));
		error = tcpmig_send(bm, sototcpcb(peer->so)); 
		INP_WUNLOCK(sotoinpcb(peer->so));
#endif
		if (error) {
			break;
		}
		idx++;
	}
	//SOCK_UNLOCK(so);

	if (extr) {
		m_freem(m);
	}
	return (error);
}

/*
 * Send message and then drop this peer.
 */ 
static void
#ifdef SMCP
tcpmig_senddrop(struct mbuf *m, struct smcpcb *smcp)
#else
tcpmig_senddrop(struct mbuf *m, struct tcpcb *tp)
#endif
{
#ifdef SMCP
	tcpmig_send(m, smcp);
#else
	tcpmig_send(m, tp);
#endif
	
	/* drop */
	panic("drop connection");
}


/*
 * Connected to a node over [TCPMIG] layer
 */
static int
#ifdef SMCP
tcpmig_soconnect(void *smcp, uint16_t v_major, uint16_t v_minor, 
    uint32_t v_feature)
#else
tcpmig_soconnect(struct socket *so, uint16_t v_major, uint16_t v_minor, 
    uint32_t v_feature)
#endif
{
	int error;
#ifdef SMCP
	error = tcpmig_sendcmd((struct smcpcb *)smcp, TM_SEND_SINGLE, TM_CMD_HANDSHAKE, 
		    (unsigned int)v_major, (unsigned int)v_minor,
		    (unsigned int)v_feature);
#else
	error = tcpmig_sendcmd(so, TM_SEND_SINGLE, TM_CMD_HANDSHAKE, 
		    (unsigned int)v_major, (unsigned int)v_minor,
		    (unsigned int)v_feature);
#endif
	return (error);
}

/*
 * Query states from Primary and apply to local HostSo from CtlSo
 */
static int
#ifdef SMCP
tcpmig_sosync(void *smcp)
#else
tcpmig_sosync(struct socket *so)
#endif
{
	int error;
#ifdef SMCP
	error = tcpmig_sendcmd(smcp, TM_SEND_SINGLE, TM_CMD_SYNC);
#else
	error = tcpmig_sendcmd(so, TM_SEND_SINGLE, TM_CMD_SYNC);
#endif
	return (error);
}

/*
 * Let new connection just dequeued from HostSo to connect
 */
static int	
tcpmig_sojoin(struct socket *head, struct socket *so, int role)
{
	int error = 0;
	
	if (role == SOMIG_PRIMARY) {
		struct inpcb *inp;
#ifdef SMCP
		inp = sotoinpcb(so);
		tcpmig_sendcmd(head->smcpcb, TM_SEND_BCAST, TM_CMD_JOIN,
		    so->so_mig_id, so->so_mig_role, 
		    head->so_mig_local_ctl_addr, inp->inp_faddr.s_addr, 
		    inp->inp_fport);
#else
		inp = sotoinpcb(so->so_mig_ctl);
		tcpmig_sendcmd(head, TM_SEND_BCAST, TM_CMD_JOIN, 
		    so->so_mig_id, so->so_mig_role, 
		    head->so_mig_local_ctl_addr, inp->inp_lport);
#endif
	} else if (role == SOMIG_REPLICA) {
		struct tmnode tmn;
		struct somig_peer_entry *node;

		CTR4(KTR_SPARE5, "%s:%d head%p so%p", __func__, __LINE__, head, so);
		KASSERT(so->so_mig_state == SMGS_SYNC, ("SO is not in SYNC mode"));

		node = TAILQ_FIRST(&head->so_mig_join);
		tcpmig_spetotn(node, &tmn, 0);
#ifdef SMCP
		tcpmig_nodeconnect(so, &tmn,
		    ntohl(node->p_addr), ntohs(node->p_port), ntohl(so->so_mig_local_ctl_addr));
#else
		tcpmig_nodeconnect(so, &tmn);
#endif

		/* Let's set the init ack_max here. It's not elegant but hey
		 * this is the only good place to grab all necessary info to
		 * make it work. */
		sototcpcb(so)->ack_max = sototcpcb(head)->ack_max;

#ifdef SOMIG_FASTMIG
		struct in_ifaddr *ia;
		struct sockaddr_in *sa;
		CK_STAILQ_FOREACH(ia, &V_in_ifaddrhead, ia_link) {
			sa = (struct sockaddr_in *)ia->ia_ifa.ifa_addr;
			if ((sa->sin_addr.s_addr & 0xffffff) != 
			    (so->so_mig_primary_addr & 0xffffff))
				continue;
			tcpmig_add_ifa(ia->ia_ifp, so->so_mig_primary_addr); 
			break;
		}
#endif

		TAILQ_REMOVE(&head->so_mig_join, node, list);
		free(node, M_TEMP);
	} else {
		error = EINVAL;
	}
	return (error);
}

/*
 * Carp callback if there's a demotion happening
 */
void
tcpmig_carp_master_down_callback(struct ifaddr **ifas, int ifasiz, int stage)
{
	struct inpcb *inp, *inp_tmp, *hinp;
	struct tcpcb *tp;
	struct socket *so, *hso;
	struct inpcbinfo *pcbinfo = &V_tcbinfo;
	struct mbuf *m = NULL;
	//struct somig_pkt_entry *pkt, *tmp;
	int op = 0, error, found_ifa;
	uint32_t ifa_addr_u32, pri_addr_u32;
#ifdef SMCP
	struct somig_peer_entry *spe = NULL, *peer;
#endif

	KASSERT(ifas != NULL, ("NULL ifas from carp"));
	/*
	 * This function will be called directly from CARP(ip layer), however
	 * since the ctlblk object we are looking for is on TCP layer, 
	 * therefore we cannot use the standard way(4 tuple HT lookup) to find
	 * the corresponding object. 
	 * So here the solution is to iterate all INPs directly from pcbinfo.
	 * It might be slow but since this is not happening frequectly, we can
	 * live with that perfectly.
	 */
	INP_INFO_WLOCK(pcbinfo);
	CK_LIST_FOREACH_SAFE(inp, pcbinfo->ipi_listhead, inp_list, inp_tmp) {
		found_ifa = 0;

		if (inp == NULL)
			continue;
		
		so = inp->inp_socket;
		if (so == NULL)
			continue;
//printf("%d: checking so %p role %u\n", __LINE__, so, (so != NULL) ? so->so_mig_role: 0xffff);
#ifdef SMCP
		hso = so;
#else
		if (so->so_mig_role != SOMIG_CTL)
			continue;
		
		hso = so->so_mig_hostso;
#endif
		if (hso == NULL)
			continue;

		/* find the current replica host_so */
		if (hso->so_mig_role != SOMIG_REPLICA)
			continue;

		hinp = sotoinpcb(hso);
		if (hinp == NULL)
			continue;

		tp = intotcpcb(hinp);
		if (tp == NULL)
			continue;

		if (tp->t_state != TCPS_ESTABLISHED) {
			continue;
		}

//printf("%d: promoting so %p\n", __LINE__, so);
		if (stage == CARP_CHANGING_IN_PROGRESS) {
			SMGTPRT(hso, "Carp master down event detected");
			for (int i=0;i<ifasiz;i++) {
				ifa_addr_u32 = ((struct sockaddr_in *)ifas[i]->ifa_addr)->sin_addr.s_addr;
				pri_addr_u32 = hso->so_mig_primary_addr; 
				CTR2(KTR_SPARE5, "ifaaddr:%u inpaddr:%u", ifa_addr_u32,
				    hinp->inp_laddr.s_addr);
				//if (ifa_addr_u32 == hinp->inp_laddr.s_addr) {
				if (ifa_addr_u32 == pri_addr_u32) {
					found_ifa = 1;
					break;
				}
			}
			if (!found_ifa)
				continue;

			/* If we are in a migration process */
			if (tp->rolechange != 0) {
				op++;
				continue;
			}

			CTR2(KTR_SPARE5, "%d: so %p in rolechange mode.", __LINE__, hso);
			tp->rolechange = 1;

			/* 
			 * At this point we can assume that our old king is dead,
			 * close the CTL connection to avoid long timout.
			 */
#ifdef SMCP
			spe = NULL;
			TAILQ_FOREACH(peer, &hso->so_mig_peer, list) {
				if (peer->role == SOMIG_PRIMARY) {
					spe = peer;
					break;
				}
			}

			KASSERT(spe != NULL, ("Cannot find SMCP channel to PRIMARY"));
			somig_close(spe);
#else
			somig_close(so->so_mig_pentry);
#endif

			if (tcpmig_get_livepeer_count(hso)) {
				tcpmig_compose_migration_packet(m, 
				    TM_MIGRATION_FLAG_LB + TM_MIGRATION_FLAG_OLD_KINGS_DEAD);
				error = tcpmig_bcast(m, sototcpcb(hso));
				if (error) {
					panic("tcpmig_carp_master_down_callback Failed to bcast msg..");
				}
			}
			SMGTPRT(hso, "Broadcasted promotion msg.");
		}

		if (stage == CARP_CHANGING_DONE) {
		    	if (tp->rolechange != 1) {
				continue;
			}

			/* 
			 * Update local peer 
			 */
			CTR2(KTR_SPARE5, "%d: PROMOTING so %p", __LINE__, hso);
			tp->unack_flush = 1;
#ifdef SMCP
			tcpmig_updaterole(hso, NULL, NULL, TM_PROMOTE);
			TAILQ_FOREACH(peer, &hso->so_mig_peer, list) {
				peer->role = SOMIG_REPLICA;
			}
#else
			tcpmig_updaterole(hso, so->so_mig_pentry, NULL, TM_PROMOTE);
#endif
			tcpmig_updatecb(hso);

			SMGTPRT(hso, "Flushing all buffered unsent packet to client.");
#ifdef SMCP
			tcpmig_flushpkt_migration(hso->smcpcb, 0);
#else
			tcpmig_flushpkt_migration(so, 0);
#endif

			hso->so_mig_unack = sbavail(&hso->so_snd);
			if (hso->so_mig_unack) {
				INP_WLOCK(hinp);
				//printf("%d: so %p sbavail %d\n", __LINE__, hso, hso->so_mig_unack);
				error = tp->t_fb->tfb_tcp_output(tp);
				INP_WUNLOCK(hinp);
			}

			//tp->rolechange = 0;

			CTR4(KTR_SPARE5, "snd_max %u snd_una %u rcv_nxt %u ack_max %u",
			    tp->snd_max, tp->snd_una, tp->rcv_nxt, tp->ack_max);
			//SMGTPRT("Role change done, now I'm the new PRIMARY");
			SOMIG_TIME_TEST_LOG = 1;
		}

		op++;
	}
	INP_INFO_WUNLOCK(pcbinfo);

	/* Didn't do anything */
	if (!op) {
		printf("Nothing happened during MASTER down event?? Need inspection if this event was triggered by SOMIG.\n");
	}
}

/*
 * Promote dest node + demote self: TM_CMD_MIGRATE + TM_STATUS_NULL
 * Promoted + broadcast to others: TM_CMD_MIGRATE + TM_STATUS_OK
 */
static int
#ifdef SMCP
tcpmig_somigrate(void *smcpcb, uint32_t flag, uint32_t who)
#else
tcpmig_somigrate(struct socket *so, uint32_t flag, uint32_t who)
#endif
{
	int error, op = 0;
	uint32_t tm_flag = 0;
	struct socket *hso;
	struct tcpcb *tp;
	struct sockaddr_in *sa;
	struct in_ifaddr *ia;

#ifdef SMCP
	hso = ((struct smcpcb *)smcpcb)->inp->inp_socket;
#else
	hso = so->so_mig_hostso;
#endif
	KASSERT(hso != NULL, ("Null HostSo"));
	tp = sototcpcb(hso);
	tp->rolechange = 1;

	tm_flag |= (flag & SOMIG_MIGRATION_FLAG_LB ? TM_MIGRATION_FLAG_LB: 0);
	tm_flag |= (flag & SOMIG_MIGRATION_FLAG_FAIL ? TM_MIGRATION_FLAG_FAIL: 0);

	SMGTPRT(hso, "Sending MIG msg to peer id %u with flag %u.", who, tm_flag);
#ifdef SMCP
	error = tcpmig_sendcmd(smcpcb, TM_SEND_SINGLE, TM_CMD_MIGRATE, tm_flag, who);
#else
	error = tcpmig_sendcmd(so, TM_SEND_SINGLE, TM_CMD_MIGRATE, tm_flag, who);
#endif


	/* TODO: ipv6 support */
	if (flag & SOMIG_MIGRATION_FLAG_CARP_DEMOTION) {
		CK_STAILQ_FOREACH(ia, &V_in_ifaddrhead, ia_link) {
			sa = (struct sockaddr_in *)ia->ia_ifa.ifa_addr;
			if (sa->sin_addr.s_addr == sotoinpcb(hso)->inp_laddr.s_addr) {
				tcpmig_carp_demote(&ia->ia_ifa, TCPMIG_CARP_ADJ);
				op++;
				break;
			}
		}

		if (op == 0) {
			SMGTPRT(hso, "Failed to do migration.");
			return (0);
		}
	}

	return (error);
}

static void
tcpmig_updaterole(struct socket *hso, struct somig_peer_entry *new, 
    struct somig_peer_entry *old, int op)
{
	int t;

#ifndef SMCP
	KASSERT(new != NULL, ("Null changed peer"));
#endif
	SOCK_LOCK(hso);

	switch (op) {
	case TM_PROMOTE:
		KASSERT(hso->so_mig_role == SOMIG_REPLICA,
		    ("Cannot promote non REPLICA"));
		
		hso->so_mig_role = SOMIG_PRIMARY;
		hso->so_mig_virgin = 0;

		if (new) {
			KASSERT(new->role == SOMIG_PRIMARY, 
			    ("The peer will be demoted is not PRIMARY"));
			new->role = SOMIG_REPLICA;
		}
		//printf("so %p got promoted to PRIMARY\n", hso);
		break;
	case TM_DEMOTE:
		KASSERT(hso->so_mig_role == SOMIG_PRIMARY, 
		    ("Cannot demote non PRIMARY"));
		KASSERT(new->role == SOMIG_REPLICA, 
		    ("The peer will be promoted is not REPLICA"));
		hso->so_mig_role = SOMIG_REPLICA;
		hso->so_mig_virgin = 0;
		new->role = SOMIG_PRIMARY;
		break;
	case TM_UPDATE:
		KASSERT(old != NULL, ("Null changed peer 2"));
		KASSERT(new->role != old->role, ("Swapping the same role"));
		t = old->role;
		old->role = new->role;
		new->role = t;
		break;
	default:
		break;
	}

	SOCK_UNLOCK(hso);
}

/*
 * After promotion, we need to update info in tcpcb, inpcb, etc.
 * For example, we need to update inp hash in order to let regular routine work.
 */
static void
tcpmig_updatecb(struct socket *hso)
{
	int error;
	struct tcpcb *tp;
	struct inpcb *inp;
	struct in_ifaddr	*ia;
	struct sockaddr_in	*sa;
	
	KASSERT(hso != NULL, ("Null HostSo"));

	tp = sototcpcb(hso);
	inp = sotoinpcb(hso);

#ifdef SOMIG_MIG_BRKDN
	SMGTPRT(hso, "UpdateCB: Dropping old inp from global pool.");
#endif
	INP_WLOCK(inp);

	/* 
	 * As the comment for in_pcbrehash states it cannot handle lport changing situation
	 * Thus here we need to manually remove this inp and later reinsert it.
	 */
	in_pcbdrop(inp);

	//TODO: change to real app addr
	inp->inp_laddr.s_addr = hso->so_mig_primary_addr;

	if (0 && inp->inp_route.ro_nh == NULL) {
		inp->inp_route.ro_nh = fib4_lookup(0, inp->inp_faddr, 0, 
		    NHR_REF, inp->inp_flowid);

		KASSERT(inp->inp_route.ro_nh != NULL, ("NULL ro_nh"));
	}

	if (0 && inp->inp_route.ro_nh->nh_ifa) {
		CK_STAILQ_FOREACH(ia, &V_in_ifaddrhead, ia_link) {
			sa = (struct sockaddr_in *)ia->ia_ifa.ifa_addr;
			if (sa->sin_addr.s_addr != inp->inp_laddr.s_addr) 
				continue;

			inp->inp_route.ro_nh->nh_ifa = &ia->ia_ifa;
			break;
		}
	}
	/**
	 * Problem: If we don't change ro_dst, all messages will be dumped to lookback.
	 *	    and packet is then lost.
	 *     Why: When Replica receives migration msg from Main, it will use carp to 
	 *	    take over Main's position(IP address). While Carp is doing the job,
	 *	    it adds a routing rule to loopback previously Main's IP address 
	 *	    since now Replica is using Main's IP address. As we are reusing 
	 *	    inpcb for communicating between Main and Replica, the original 
	 *	    destination was Main's IP and now is replica itself. 
	 *	    Thus, all packets will be dumped to our loopback.
	 *Solution: Changed ro_dst to client.
	 *
	 */
	((struct sockaddr_in *)&(inp->inp_route.ro_dst))->sin_port = inp->inp_fport;
	((struct sockaddr_in *)&(inp->inp_route.ro_dst))->sin_addr = inp->inp_faddr;
	/* TODO: clear old mem after NULLed */
	/* Invalidate both bpf and linklayer routing in case to 
	 * trigger ARP to query unknown cli MAC 
	 */
	inp->inp_route.ro_prepend = NULL;
	inp->inp_route.ro_lle = NULL;

	inp->inp_flags &= ~(INP_DROPPED);
	/*
	 * As we have updated inp, reinsert to hash list here.
	 */
#ifdef SOMIG_MIG_BRKDN
	SMGTPRT(hso, "UpdateCB: Rehashing inp.");
#endif
	INP_HASH_WLOCK(&V_tcbinfo);
	error = in_pcbinshash(inp);
	if (error != 0) {
		panic("Failed to reinsert pcb");
	}

	INP_HASH_WUNLOCK(&V_tcbinfo);
	INP_WUNLOCK(inp);
#ifdef SOMIG_MIG_BRKDN
	SMGTPRT(hso, "UpdateCB: Done");
#endif
}

/*
 * Adjust wnd size on Replica.
 */
static void
tcpmig_updatestate(struct tcpcb *tp, struct socket *so, struct ppshdr *ppsh)
{
	int error;

	if (tp->t_state == TCPS_ESTABLISHED) {
		if (ppsh->rwnd > tp->rcv_wnd) {
			SOCKBUF_LOCK(&so->so_rcv);
			error = sbreserve_locked(&so->so_rcv, ppsh->rwnd, so, NULL);
			SOCKBUF_UNLOCK(&so->so_rcv);
		}

		tp->last_snd_cwnd = ppsh->snd_cwnd;
	}
}

/*
 * Update timestamp in TCPHDR 
 * This is used for fixing the PAWS problem if there is a delay on RSO.
 * In other words, if the ts_recent value on RSO is greater than MSO, then we
 * might suffer from the PAWS check. By using this, we manually bump up the ts
 * if needed.
 */
static void
tcpmig_updatets(struct tcpcb *tp, u_char *cp, int cnt, struct ppshdr *ppsh)
{
	int opt, optlen, offset;
	uint32_t val, tsval, tsecr;

	if (tp == NULL)
		return;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2)
				break;
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt)
				break;
		}
		switch (opt) {
		case TCPOPT_TIMESTAMP:
			if (optlen != TCPOLEN_TIMESTAMP)
				continue;
			bcopy((char *)cp + 2, (char *)&tsval, sizeof(uint32_t));
			bcopy((char *)cp + 6, (char *)&tsecr, sizeof(uint32_t));
			tsval = ntohl(tsval);
			tsecr = ntohl(tsecr);
		
			//tp->ts_recent = ppsh->ts_recent;

			offset = tsval - ppsh->ts_recent;
			val = htonl((offset > 0? offset: 0) + tp->ts_recent);
			bcopy((char *)&val, (char *)cp + 2, sizeof(val));
			
			//val = htonl(tp->ts_recent_age);
			//bcopy((char *)&val, (char *)cp + 6, sizeof(val));
			break;
		default:
			continue;
		}
	}
}

/*
 * Adjust the remote packet ip hdr in order to be accepted by REPLICA So
 * The mbuf after adjusted by this function will be sent to ip_input,
 * tcp stack will use the 4-tuple hdr info to find the proper pcb.
 * Therefore we need to update this 4-tuple to let it match the pcb.
 */
static struct tcphdr *
#ifdef SMCP
tcpmig_updatehdr_addr(struct mbuf *m0, struct smcpcb *smcp, struct socket *so, 
    int len, int *tlen)
#else
tcpmig_updatehdr_addr(struct mbuf *m0, struct socket *so, struct socket *ctlso,
    int len, int *tlen)
#endif
{
#ifdef INET6
	int		isipv6;
	struct ip6_hdr	*ip6;
#endif
	struct inpcb	*inp;
#ifndef SMCP
	struct inpcb	*ctl_inp;
#endif
	struct tcpcb	*tp;
	struct ip	*ip;
	struct tcphdr	*th;
	int		thflags;
	uint32_t	laddr, faddr, oladdr, ctl_laddr;
	uint16_t	lport, fport;
	int		optlen;
	struct mbuf	*m;

	m = m0;

	KASSERT(so != NULL, ("Null So"));
	KASSERT(m != NULL, ("Null mbuf"));

	inp = sotoinpcb(so);
	tp = sototcpcb(so);
#ifdef SMCP
	ctl_laddr = htonl(smcp->l_addr);
#else
	ctl_inp = sotoinpcb(ctlso);
	ctl_laddr = inp->inp_laddr.s_addr;
#endif

	laddr =	inp->inp_laddr.s_addr;
	faddr = inp->inp_faddr.s_addr;
	lport = inp->inp_lport;
	fport = inp->inp_fport;

	if (m->m_len < (sizeof(struct ip) + sizeof(struct tcphdr)))
		m = m_pullup(m, sizeof(struct ip) + sizeof(struct tcphdr));
	
	if (!(m->m_flags & M_PKTHDR))
		m = tcpmig_m_fixhdr(m, so, len);

#ifdef INET6
	isipv6 = (((struct ip*)mtod(m, caddr_t))->ip_v == 6) ? 1 : 0;
	if (isipv6) {
		ip6 = mtod(m, struct ip6_hdr *);
		th = (struct tcphdr *)(mtod(m, caddr_t) + sizeof(struct ip6_hdr));
		panic("ipv6 support: Incomplete code path\n");
	} else
#endif
	{
		ip = (struct ip *)(mtod(m, caddr_t));

		/* TODO: may need to handle IP OPTIONS */
		th = (struct tcphdr *)(mtod(m, caddr_t) + sizeof(struct ip));
	}

/*
printf("inp la %u fa %u ip src %u ip dst %u ctlla %u\n", laddr, faddr, ip->ip_src.s_addr,
    ip->ip_dst.s_addr, ctl_laddr);
    */
	// orig local addr (primary addr)
	oladdr = ip->ip_dst.s_addr;
	if (!SOLISTENING(so))
		so->so_mig_primary_addr = oladdr;

	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_tos = inp->inp_ip_tos;
	ip->ip_len = htons(len);

CTR3(KTR_SPARE5, "%d: upd tcp hdr old dst %u, new dst%u", __LINE__, oladdr, laddr);
	//TODO: handle IPV6 here
	thflags = th->th_flags;
	if (((thflags & TH_SYN) == 0) && (!SOLISTENING(so))) { /* Regular traffic */
		ip->ip_src.s_addr = faddr;
		ip->ip_dst.s_addr = laddr;
	} else {	/* HS traffic */
		ip->ip_dst.s_addr = ctl_laddr;
	}

	if (((thflags & TH_SYN) == 0) && (!SOLISTENING(so))) {
		th->th_sport = fport;
	}
	th->th_dport = lport;

	/* calculate actual user payload length */
	optlen = (th->th_off << 2) - sizeof(struct tcphdr);
	*tlen = len - sizeof(struct ip) - sizeof(struct tcphdr) - optlen;

	/*
	 * Update ip/tcp hdr checksum.
	 */
	tcpmig_cksum(m, ip, th);
	return (th);
}

static struct tcphdr *
tcpmig_updatehdr_tcp(struct mbuf *m0, struct socket *so, int tlen)
{
#ifdef INET6
	int		isipv6;
	struct ip6_hdr	*ip6;
#endif
	struct tcpcb	*tp;
	struct ip	*ip;
	struct tcphdr	*th;
	int		thflags;
	struct mbuf	*m;
	uint32_t	seq, ack, rcvn, sndm;
	uint32_t	laddr;
	struct inpcb	*inp;

	m = m0;

	KASSERT(so != NULL, ("Null So"));
	KASSERT(m != NULL, ("Null mbuf"));

	tp = sototcpcb(so);

#ifdef INET6
	isipv6 = (((struct ip*)mtod(m, caddr_t))->ip_v == 6) ? 1 : 0;
	if (isipv6) {
		ip6 = mtod(m, struct ip6_hdr *);
		th = (struct tcphdr *)(mtod(m, caddr_t) + sizeof(struct ip6_hdr));
		panic("ipv6 support: Incomplete code path\n");
	} else
#endif
	{
		ip = (struct ip *)(mtod(m, caddr_t));

		/* TODO: may need to handle IP OPTIONS */
		th = (struct tcphdr *)(mtod(m, caddr_t) + sizeof(struct ip));
	}

	/* Change the IP address if we are in rolechange mode */
	inp = sotoinpcb(so);
	if (inp && so->so_mig_role == SOMIG_PRIMARY && so->so_mig_virgin == 0 && tp->rolechange == 1) {
		laddr = inp->inp_laddr.s_addr;
		ip->ip_dst.s_addr = laddr;
	}

	seq = ntohl(th->th_seq);
	ack = ntohl(th->th_ack);
	rcvn = tp->rcv_nxt;
	sndm = tp->snd_max;

	th->th_win = htons(65535);

	thflags = th->th_flags;

	/*
	 * Necessity check
	 *  SEQ>RCVN, ACK>SNDM: Update ACKM
	 *  SEQ>RCVN, ACK=SNDM: Pass
	 *  SEQ>RCVN, ACK<SNDM: Pass
	 *  SEQ=RCVN, ACK>SNDM: Update ACKM
	 *  SEQ=RCVN, ACK=SNDM: Pass
	 *  SEQ=RCVN, ACK<SNDM: Update ACKM(when ACK>SNDA) or ASSERT
	 *  SEQ<RCVN, ACK>SNDM: Update ACKM
	 *  SEQ<RCVN, ACK=SNDM: Pass
	 *  SEQ<RCVN, ACK<SNDM: Pass
	 *
	 * However if the packet is not a pure ACK, we bypass this check.
	 */
	if (!((th->th_flags & TH_ACK) && (tlen == 0))) 
		if ((seq>rcvn && ack<=sndm) || (seq==rcvn && ack==sndm) || 
		    (seq<rcvn && ack<=sndm))
		    goto done;
	
	/*
	 * update ack_max 
	 */
	if (tp->t_state != TCPS_ESTABLISHED && !(thflags & TH_SYN)) {
			tp->ack_max = ack;
			goto done;
	}

	if ((thflags & TH_ACK) && ((thflags & TH_SYN) == 0) && (!SOLISTENING(so))) {
		//KASSERT(!(seq == rcvn && ack < sndm && ack <= tp->snd_una), 
		 //   ("seq=rcvn && ack<=snd_una"));

		if (SEQ_GT(ack, tp->ack_max)) {
/*
CTR4(KTR_SPARE5, "%d: updated ack_max%u su%u sm%u", __LINE__, tp->ack_max,
    tp->snd_una, tp->snd_max);
    */
			tp->ack_max = ack;
		}

		/*
		 * initial case when establishing the connection, set ack_max
		 * to the very first ack number.
		 */
		if (tp->ack_max == 0) {
			tp->ack_max = ack;
		}

		/*
		 * replace th_ack with maximum acceptable ack 
		 * (we only update this for pure ACK)
		 */
		if (tlen == 0) {
CTR6(KTR_SPARE5, "%d: calling find ack seq%u ack%u sm%u rn%u tl%u", __LINE__,
	seq, ack, sndm, rcvn, tlen);
			th->th_ack = htonl(tcpmig_find_next_ack(so, ack));
			/*
			th->th_ack = htonl(ack);
			ack = tp->ack_max;
			if (SEQ_GT(ack, tp->snd_max)) {
				ack = tp->snd_max;
				th->th_ack = htonl(ack);
			}
			*/
			//th->th_ack = ntohl(tp->snd_max);
		}
	}
	//KASSERT(ack <= tp->snd_una, ("ack is greater than local snd_una"));

	/*
	 * Update ip/tcp hdr checksum.
	 */
	//tcpmig_cksum(m, ip, th);
done:
	if (inp && so->so_mig_role == SOMIG_PRIMARY && so->so_mig_virgin == 0 && tp->rolechange == 1) {
		tcpmig_cksum(m, ip, th);
	}
	return (th);
}

static void
tcpmig_updatehdr_tcp_off(struct somig_pkt_entry *pkt, struct tcpcb *tp)
{
	struct tcphdr *th;

	th = pkt->th;
	KASSERT(th != NULL, ("NULL th in pkt entry"));
	/*
CTR5(KTR_SPARE5, "%d: ack old %u off %u su%u sm%u", __LINE__, ntohl(th->th_ack),
    tp->t_snd_off, tp->snd_una, tp->snd_max);
    */

	if (SEQ_GEQ(tp->snd_una, ntohl(th->th_ack)) &&
	    ntohl(th->th_ack) - tp->snd_una <= tp->t_snd_off) {
		th->th_ack = htonl(ntohl(th->th_ack) + tp->t_snd_off);
	}

	if (SEQ_GT(ntohl(th->th_ack), tp->snd_max)) {
		if (ntohl(th->th_ack) - tp->snd_max <= tp->t_snd_off_local) {
			th->th_ack = htonl(tp->snd_max);
		}
	}

}

/*
 * m point to the first mbuf in the chain.
 * m0 point to the first mbuf contains ext data in the chain
 *
 * somigize function sets the M_SOMIG_PKT header for all mbufs in the chain
 *
 * somigize function also helps to EXT-ize the mbuf in the chain, which doesn't
 * have a M_EXT flag (No refcnt)
 *
 * This function returns the first EXT-DATA mbuf in chain, which is the original
 * mbuf before calling M_PREPEND but without non-data packets.
 *
 * NB: call this function after M_PREPEND
 *
 */
static struct mbuf *
tcpmig_mbuf_somigize(struct mbuf *m, struct mbuf *m0)
{
	volatile u_int *refcnt;
	int fm_set = 0;
	struct mbuf *lm = m0, *fm = m0, *nm;
	
	if (!m)
		return (NULL);

	CTR1(KTR_SPARE5, "somigized mbuf %p", m);
	while (m) {
		m->m_flags |= M_SOMIG_PKT;
		lm = m;
		m = m->m_next;
		if (m == m0) {
			break;
		}
	}

	while (m0) {
		/* EXTize if M_EXT is not set */
		if (!(m0->m_flags & M_EXT)) {
			nm = m0->m_next;
			m0 = tcpmig_m_extize(m0);
			m0->m_next = nm;
			lm->m_next = m0;
		}

		m0->m_flags |= M_SOMIG_PKT;
		/* See if this is the mbuf that holds the embedded refcount. */
		if (m0->m_ext.ext_flags & EXT_FLAG_EMBREF) {
			refcnt = &m0->m_ext.ext_count;
		} else {
			panic("check");
			KASSERT(m0->m_ext.ext_cnt != NULL,
			    ("%s: no refcounting pointer on %p", __func__, m0));
			refcnt = m0->m_ext.ext_cnt;
		}

		if (*refcnt == 1)
			*refcnt += 1;
		else
			atomic_add_int(refcnt, 1);

		if (!fm_set) {
			fm_set = 1;
			fm = m0;
		}
		lm = m0;
		m0 = m0->m_next;
	}

	return (fm);
}

static void
tcpmig_mbuf_desomig(struct mbuf *m)
{
	//volatile u_int *refcnt;
	if (!m)
		return;

	while (m) {
		/* See if this is the mbuf that holds the embedded refcount. */
		/*
		if (m->m_ext.ext_flags & EXT_FLAG_EMBREF) {
			refcnt = &m->m_ext.ext_count;
		} else {
			KASSERT(m->m_ext.ext_cnt != NULL,
			    ("%s: no refcounting pointer on %p", __func__, m));
			refcnt = m->m_ext.ext_cnt;
		}

		atomic_fetchadd_int(refcnt, -1);
		*/

		m->m_flags &= ~M_SOMIG_PKT;
		m->m_nextpkt = NULL;
		m = m->m_next;
	}
}

/*
 * Set tp states to disconnect without sending any pkts out (For REPLICA)
 */
static int
tcpmig_sodisconnect(struct socket *so)
{
	int error = 0;
	struct tcpcb *tp;
	struct inpcb *inp;

	tp = sototcpcb(so);
	inp = sotoinpcb(so);
	INP_WLOCK(inp);
	INP_INFO_WLOCK(&V_tcbinfo);
	/* 
	 * Based on design, tp at this place could only be TCPS_ESTABLISHED
	 * state.
	 */
	tcp_state_change(tp, TCPS_CLOSED);
	tp = tcp_close(tp);
	/*
	 * tcp_close() should never return NULL here as the socket is
	 * still open.
	 */
	KASSERT(tp != NULL,
	    ("tcp_usrclosed: tcp_close() returned NULL"));
	
	INP_INFO_WUNLOCK(&V_tcbinfo);
	INP_WUNLOCK(inp);
	return (error);
}

/*
 * Update so_options into inp (Expand this func as needed)
 */
static int	
tcpmig_soupdateoptions(struct socket *so)
{
#ifdef SMCP
	return (0);
#endif
	int error = 0;
	struct inpcb *inp;
	struct tcpcb *tp;

	if (so == NULL) {
		error = EINVAL;
		return (error);
	}

	inp = sotoinpcb(so);
	if (inp == NULL) {
		error = ENOTCONN;
		return (error);
	}

	INP_WLOCK(inp);
	if ((so->so_options & SO_REUSEADDR) != 0)
		inp->inp_flags2 |= INP_REUSEADDR;
	else
		inp->inp_flags2 &= ~INP_REUSEADDR;

	if ((so->so_options & SO_REUSEPORT) != 0)
		inp->inp_flags2 |= INP_REUSEPORT;
	else
		inp->inp_flags2 &= ~INP_REUSEPORT;
	INP_WUNLOCK(inp);

	tp = sototcpcb(so);
	tp->t_flags |= TCP_NODELAY;

	return (error);
}

/*
 * Get addr tuple from a socket
 */
static int	
tcpmig_getaddrtuple(struct socket *so, struct sockaddr *sa, int which)
{
	int error = 0;
	struct inpcb *inp;
	uint32_t addr;
	uint16_t port;

	if (so == NULL || sa == NULL) {
		error = EINVAL;
		return (error);
	}

	inp = sotoinpcb(so);
	if (inp == NULL) {
		error = ENOTCONN;
		return (error);
	}
    
	if (which == SOMIG_ADDR_TUPLE_LOCAL) {
		addr = ntohl(inp->inp_laddr.s_addr);
		port = ntohs(inp->inp_lport);
	} else {
		addr = ntohl(inp->inp_faddr.s_addr);
		port = ntohs(inp->inp_fport);
	}

	/* foreign Port*/
	sa->sa_data[0] = (port>>8) & 0xff;
	sa->sa_data[1] = port & 0xff;
	/* foreign IP */
	sa->sa_data[2] = (addr>>24) & 0xff;
	sa->sa_data[3] = (addr>>16) & 0xff;
	sa->sa_data[4] = (addr>>8) & 0xff;
	sa->sa_data[5] = addr & 0xff;

	return (error);
}

void
tcpmig_syncache_respond(struct somig_pkt_data_syn *data) 
{
	struct syncache *sc;
	struct syncache_head *sch;
	struct mbuf *m;
	uint16_t fsc;
	int syncookies, syncookies_only;

	m = data->t_scm;
	syncookies = data->t_syncookies;
	syncookies_only = data->t_syncookiesonly;
	sc = (struct syncache *)(data->t_sc);
	sch = (struct syncache_head *)(data->t_sch);
	fsc = data->t_fsc;

	KASSERT(sc != NULL, ("Null syncache"));
	KASSERT(sch != NULL, ("Null syncache_head"));

	if (syncache_respond(sc, m, TH_SYN|TH_ACK) == 0) {
		if (syncookies && syncookies_only && fsc) 
			syncache_free(sc);
		else if (fsc) 
			syncache_insert(sc, sch);   /* locks and unlocks sch */
		TCPSTAT_INC(tcps_sndacks);
		TCPSTAT_INC(tcps_sndtotal);
	} else {
		if (fsc)
			syncache_free(sc);
		TCPSTAT_INC(tcps_sc_dropped);
	}
	if (m) {
		m_freem(m);
	}
}

/*
 * Perform the quick check for pkt buffered in RSO.
 * Return 1 if failed the test, otherwise return 0.
 */
int 
tcpmig_pktstate_check(struct somig_pkt_entry *pkt, struct tcpcb *tp)
{
    	struct tcphdr *th;
	th = pkt->th;

	tp->t_flags |= TF_NODELAY;
	/*
	 * Check 1: snd_max >= th_ack. tcp_input:2889 
	 */
	if (pkt->thflags & (TH_RST | TH_FIN)) {
		return (0);
	}

	if ((!SEQ_GEQ(tp->snd_max, ntohl(th->th_ack)))) {
		return (1);
	}

	if (tp->rcv_nxt != ntohl(th->th_seq) && SEQ_LEQ(ntohl(th->th_seq) + pkt->tlen, tp->rcv_nxt)) {
		return (1);
	}

	if (SEQ_GT(ntohl(th->th_seq), tp->rcv_nxt)) {
		return (1);
	}

	if (tp->rcv_nxt == pkt->seq && SEQ_GT(tp->snd_una, pkt->ack) &&
		tp->snd_una - pkt->ack > 10) {
printf("%d: check seq%u rn%u ack %u sm%u su%u flag%u len%u sndoff%u lsndoff%u\n", __LINE__, pkt->seq, tp->rcv_nxt,
    pkt->ack, tp->snd_max, tp->snd_una, pkt->thflags, pkt->tlen, tp->t_snd_off, tp->t_snd_off_local);
MBUFPRINT(pkt->m);
		panic("check..... snd_una > ack");
	}
	/*
	 * Check 2: tcp_input: 2744
	 */
	return (0);
	if ((int)((pkt->seq + pkt->tlen) - (tp->rcv_nxt + tp->rcv_wnd)) > 0) {
		LOGPRINT(SMGLOG_CURR, "Failed, seq %u, tlen %u rcvn %u rcvw %u\n",
		    pkt->seq, pkt->tlen, tp->rcv_nxt, tp->rcv_wnd);
		return (1);
	}

	return (0);
}

static int
#ifdef SMCP
tcpmig_sendcmd(struct smcpcb *smcp, int mode, int type, ...)
#else
tcpmig_sendcmd(struct socket *so, int mode, int type, ...)
#endif
{
	/* ap follows the prototype func order */
	va_list ap;
	int size, error = 0, who;
	char *off;
	struct mbuf *m;
	struct tmver *tmv;
	struct tmhdr *tmth;
	struct tmnode *tmn;
#ifdef SMCP
	struct epoch_tracker et;
#else
	struct inpcb *inp;
#endif
	struct tmmigration *tmmig;

	size = sizeof(struct tmhdr);
	switch (type) {
	case TM_CMD_HANDSHAKE:
		size += (sizeof(struct tmver) + sizeof(struct tmnode));
		break;
	case TM_CMD_JOIN:
		size += (sizeof(struct tmnode));
		break;
	case TM_CMD_MIGRATE:
		size += (sizeof(struct tmmigration));
	}
	m = m_getm2(NULL, size, M_NOWAIT, MT_DATA, 0);
	m->m_len = size;
	m->m_pkthdr.len = size;
	
	off = mtod(m, char *);
	tmth = (struct tmhdr *)off;
	tmth->magic = TM_MAGIC;
	tmth->status = TM_STATUS_NULL;
	tmth->len = size;
#ifdef SMCP
	tmth->addr = smcp->r_addr;
	tmth->port = smcp->r_port;
	tmth->id = smcp->id;
#else
	inp = sotoinpcb(so);
#endif
	
	switch (type) {
	case TM_CMD_HANDSHAKE:
		tmv = (struct tmver *)((char *)tmth + sizeof(struct tmhdr));
		tmn = (struct tmnode *)((char *)tmth + sizeof(struct tmhdr) + 
		    sizeof(struct tmver));

		tmth->cmd = TM_CMD_HANDSHAKE;
		tmth->exlen = sizeof(struct tmver) + sizeof(struct tmnode);

		va_start(ap, type);
		tmv->major = va_arg(ap, unsigned int);
		tmv->minor = va_arg(ap, unsigned int);
		tmv->feature = va_arg(ap, unsigned int);
		va_end(ap);

#ifdef SMCP
		tcpmig_spetotn(((struct smcpcb *)smcp)->so_mig_pentry, tmn, 1);
#else
		tcpmig_spetotn(so->so_mig_pentry, tmn, 1);
#endif
		break;
	case TM_CMD_SYNC:
		tmth->cmd = TM_CMD_SYNC;
		tmth->exlen = 0;
		break;
	case TM_CMD_MIGRATE:
		tmth->cmd = TM_CMD_MIGRATE;
		tmth->exlen = sizeof(struct tmmigration);
		tmmig = (struct tmmigration *)((char *)tmth + sizeof(struct tmhdr));

		va_start(ap, type);
		tmmig->flag = va_arg(ap, unsigned int);
		who = va_arg(ap, unsigned int);
		va_end(ap);
		break;
	case TM_CMD_JOIN:
		tmth->cmd = TM_CMD_JOIN;
		tmth->exlen = sizeof(struct tmnode);

		tmn = (struct tmnode *)((char *)tmth + sizeof(struct tmhdr));
		va_start(ap, type);
		tmn->id = va_arg(ap, unsigned int);
		tmn->role = va_arg(ap, unsigned int);
		tmn->ip = va_arg(ap, unsigned int);
#ifdef SMCP
		tmn->p_addr = va_arg(ap, unsigned int);
		tmn->p_port = va_arg(ap, unsigned int);
#else
		tmn->port = va_arg(ap, unsigned int);
#endif
		va_end(ap);
	default:
		break;
	}
	
	if (mode == TM_SEND_BCAST)
#ifdef SMCP
	{
		//TODO: FIX IT WITH REAL BCAST !!!!!!!!!!!!!!!!!!!!!!!!
		tmth->id = 1;
		NET_EPOCH_ENTER(et);
		error = tcpmig_bcast(m, sototcpcb(smcp->inp->inp_socket));
		NET_EPOCH_EXIT(et);
	}
#else
		error = tcpmig_bcast(m, sototcpcb(so));
#endif
	else {
#ifdef SMCP
		NET_EPOCH_ENTER(et);
		error = tcpmig_send(m, smcp);
		NET_EPOCH_EXIT(et);
#else
		INP_WLOCK(inp);	
		error = tcpmig_send(m, sototcpcb(so));
		INP_WUNLOCK(inp);	
#endif
	}

	return (error);
}

/*
 * tcpmig wrapped version ip_input. 
 * This version will deliver the duplicated mbuf into stack. In case the packet
 * got dropped, we won't lose it. The main user of this function is RSO.
 */
void
tcpmig_ipinput(struct somig_pkt_entry *pkt, struct socket *hso) 
{
	//struct mbuf *m;
	struct tcpcb *tp;
	uint32_t rcv_nxt;

    	KASSERT(pkt->m != NULL, ("TCPOUTPUT NULL mbuf"));
	
	/*
	 * TODO:
	 * Curr: Always reset ts_recent to 0 to bypass PAWS.
	 * Ideal: Fix tsval if necessary (how to detect dupack?)
	 * Note: If ts_recent = 0 only affects WND thing, then we probably can
	 *	keep it since we will add dummy CC.
	 */
	tp = sototcpcb(hso);
	tp->ts_recent = 0;

	/*
	 * Keep the congestion wnd on REP giant.
	 */
	tp->snd_cwnd = tp->snd_wnd << tp->snd_scale;

	rcv_nxt = tp->rcv_nxt;
	hso->so_mig_pkt_consumption = pkt->tlen;
	pkt->sent = 1;
	//m = m_dup(pkt->m, M_NOWAIT);
	//m = m_copypacket(pkt->m, M_NOWAIT);
	//tcpmig_updatehdr_tcp(m, hso, pkt->tlen);
//CTR5(KTR_SPARE5, "seq%u ack%u rn%u ua%u ml%u", pkt->seq, pkt->ack, tp->rcv_nxt, tp->snd_una, pkt->m->m_pkthdr.len);
	ip_input(pkt->m);
//CTR2(KTR_SPARE5, "after rn%u ua%u", tp->rcv_nxt, tp->snd_una);

	if (hso->so_mig_pkt_consumption < pkt->tlen)  {
if (pkt->m)
    CTR3(KTR_SPARE5, "consm'd%u mlen%u pkttlen%u", hso->so_mig_pkt_consumption, pkt->m->m_pkthdr.len, pkt->tlen);
CTR6(KTR_SPARE5, "ipinput: REJ->s%u a%u su%u sm%u bufd %u sba%u", 
			    pkt->seq, 
			    pkt->ack,
			    sototcpcb(hso)->snd_una,
			    sototcpcb(hso)->snd_max,
			    hso->so_mig_pkt_buffered,
			    sbavail(&hso->so_snd));

		pkt->sent = 0;
		pkt->rexmt++;
	} else {
		//m_freem(pkt->m);
		pkt->m = NULL;
	}
	hso->so_mig_pkt_consumption = 0;
}

/*
 * Send reply with payload m.
 * The main user for this function other than regular tcpmig_sendreply wrapper 
 * is tcp_output as we need to send REPLICA's ack message to PRIMARY.
 */
int 
#ifdef SMCP
tcpmig_sendreply_m(void *smcp, int type, int status, struct mbuf *mp)
#else
tcpmig_sendreply_m(struct socket *so, int type, int status, struct mbuf *mp)
#endif
{
	int size, error, psize = 0;
	char *off;
	struct mbuf *m;
	struct tmhdr *tmth;
	struct epoch_tracker et;

	size = sizeof(struct tmhdr);
	m = m_getm2(NULL, size, M_NOWAIT, MT_DATA, 0);
	m->m_len = size;

	if (mp) {
		psize = m_length(mp, NULL);
		size += psize;
		m_cat(m, mp);
	}
	m->m_len = size;
	m_fixhdr(m);

	off = mtod(m, char *);
	tmth = (struct tmhdr *)off;
	
	tmth->magic = TM_MAGIC;
	tmth->status = status;
	tmth->len = size;
#ifdef SMCP
	tmth->addr = ((struct smcpcb *)smcp)->r_addr;
	tmth->port = ((struct smcpcb *)smcp)->r_port;
	tmth->id = ((struct smcpcb *)smcp)->id;
#endif
#ifdef SOMIG_TIMING_DIAG
	if (type == TM_CMD_PACKET && status == TM_STATUS_OK && stime_from_mso != 0) {
		tmth->padding = 1;
		tmth->stime = stime_from_mso;
	}
#endif
	switch (type) {
	case TM_CMD_PACKET:
		tmth->cmd = TM_CMD_PACKET;
		tmth->exlen = psize;
		break;
	default:
		printf("sendreply doesn't have routine for this type\n");
		return 0;
	}
	
	NET_EPOCH_ENTER(et);
#ifdef SMCP
	error = tcpmig_send(m, (struct smcpcb *)(smcp));
#else
	error = tcpmig_send(m, sototcpcb(so));
#endif
	NET_EPOCH_EXIT(et);

	return (error);
}

/*
 * 
 */
#ifndef SMCP
static int
tcpmig_sendreply(struct socket *so, int type, int status)
{
	return (tcpmig_sendreply_m(so, type, status, NULL));
}
#endif

void
tcpmig_rolechange_done(struct socket *so)
{
	struct tcpcb *htp = sototcpcb(so);

	SMGTPRT(so, "Last bit of role change.");

	if (SEQ_LT(htp->snd_una, htp->ack_max)) {
		INSTANT_ACK_BEGIN(htp);
		tcpmig_direct_ip_input(tcpmig_compose_tcp_ack(so), htp);
		INSTANT_ACK_END(htp);
	}

	htp->snd_cwnd = htp->last_snd_cwnd;
	if (htp->snd_cwnd == 0) {
		htp->snd_cwnd = htp->t_maxseg;
	}
	htp->t_flags &= ~TF_NODELAY;
	
	if (SEQ_GEQ(htp->snd_nxt, htp->ack_max) && htp->ack_max != 0) {
		htp->snd_nxt = htp->ack_max;
		htp->snd_recover = htp->snd_max;
	}
	htp->rolechange = 0;

	SMGTPRT(so, "Role change done, now I'm the new PRIMARY");

	//(void)htp->t_fb->tfb_tcp_output(htp);
}

/*
 * If the packet we got misses PKTHDR (mainly from tcp_reass), we fix it.
 * Need IPV6 support.
 */
static struct mbuf *	
tcpmig_m_fixhdr(struct mbuf *m, struct socket *so, int len)
{	
	struct inpcb *inp;

	inp = sotoinpcb(so);

	m->m_flags |= M_PKTHDR;
	m->m_pkthdr.len = len;
	m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
	// check ipv6 , CSUM_TCP_IPV6
	m->m_pkthdr.csum_flags = CSUM_TCP;
	m->m_pkthdr.snd_tag = inp->inp_snd_tag;
	SLIST_INIT(&m->m_pkthdr.tags);

	return m;
}

/*
 * Modified version of m_catpkt.
 * The main reason to create this is due to the orig m_catpkt requires both
 * m_buf contains pkthdr section. However, due to our way to split/merge mbuf,
 * in some cases the mbuf are missing the pkthdr part. 
 * This modified version will all mbufs as long as one of it has pkthdrs.
 */
static void
tcpmig_m_catpkt(struct mbuf **m, struct mbuf *n, struct socket *so)
{
	int len;
	/*
	 * We got two good candidates, call orig m_catpkt.
	 */
	if (((*m)->m_flags & M_PKTHDR) && (n->m_flags & M_PKTHDR)) {
		m_catpkt((*m), n);
		return;
	}

	/*
	 * If n has pkthdr, great, we move that hdr to m and do m_cat.
	 */
	if (n->m_flags & M_PKTHDR) {
		len = m_length(n, NULL);
//CTR3(KTR_SPARE5, "%s type 1, n len %d, m len %d\n", __func__, len, m_length(*m, NULL));
if (len == 0 || m_length(*m, NULL) == 0) panic("m_catpkt 0 length");
	
		*m = tcpmig_m_fixhdr(*m, so, m_length(*m, NULL));
		*m = tcpmig_m_rearrange(*m, m_length(*m, NULL));
		//m_move_pkthdr(*m, n);
		m_cat(*m, n);
		(*m)->m_pkthdr.len += len;
		return;
	}

	/*
	 * If m has pkthdr, excellent, we just call m_cat and update pkthdr len
	 * manually. Or if not, we fix m first.
	 */
	if (!((*m)->m_flags & M_PKTHDR)) {
//CTR1(KTR_SPARE5, "%s type pre2\n", __func__);
		*m = tcpmig_m_fixhdr(*m, so, m_length(*m, NULL));
	}
//CTR1(KTR_SPARE5, "%s type 2\n", __func__);
	len = m_length(n, NULL);
	m_cat(*m, n);
	(*m)->m_pkthdr.len += len;
	return;
}

/*
 * Extract ACK packet from a packet with payload
 */
static struct mbuf *	tcpmig_m_extract_ack(struct mbuf *m, int pld_len, 
    int fix_cksum, int update_th, uint32_t new_seq, uint32_t new_ack) 
{
#ifdef INET6
	int		isipv6;
	struct ip6_hdr	*ip6;
#endif
	struct ip	*ip;
	struct tcphdr	*th;
	struct mbuf	*ack_m = NULL;

	ack_m = m_dup(m, M_NOWAIT);

#ifdef INET6
	isipv6 = (((struct ip*)mtod(ack_m, caddr_t))->ip_v == 6) ? 1 : 0;
	if (isipv6) {
		ip6 = mtod(ack_m, struct ip6_hdr *);
		th = (struct tcphdr *)(mtod(ack_m, struct ip6_hdr *) + 1);
		panic("ipv6 support: Incomplete code path\n");
	} else
#endif
	{
		ip = (struct ip *)(mtod(ack_m, caddr_t));
		th = (struct tcphdr *)(mtod(ack_m, struct ip *) + 1);
	}

	th->th_flags = TH_ACK;
	tcpmig_strippld(ack_m, pld_len);

	if (update_th) {
		th->th_seq = htonl(new_seq);
		th->th_ack = htonl(new_ack);
	}

	/*
	 * Update ip/tcp hdr checksum.
	 */
	if (fix_cksum)
		tcpmig_cksum(ack_m, ip, th);
	return (ack_m);
}

#ifdef SOMIG_TASKQUEUE
static void
tcpmig_tcp_bcast_task(void *s)
{
	int error;
	struct somig_task_entry *te, *tmp;
	struct socket *so;

	so = (struct socket *)s;
	while (so && !so->so_mig_task_done) {
		TAILQ_FOREACH_SAFE(te, &so->so_mig_tasks, list, tmp) {
			if (so->so_mig_task_done == 1) {
				break;
			}
			if (te->spe) { 
				CTR2(KTR_SPARE5, "SMCP send seq%u sz%u",
				    te->spe->seq, te->spe->tlen);
			}
			if (sototcpcb(so)->t_throttle) {
				// sleep 10ms after each send
				//pause("bcastth", hz / 100);
			}
			error = tcpmig_bcast_internal(te->m, te->ctl_blk, te->flag);
			if (error) {
				/* sleep and retry */
				te->flag |= SOMIG_SEND_FLAG_REXMT;
				pause("bcastrt", hz / 10);
				break;
			}
			SOMIG_TASK_LOCK(so);
			TAILQ_REMOVE(&so->so_mig_tasks, te, list);
			SOMIG_TASK_UNLOCK(so);
			free(te, M_TEMP);
			CTR1(KTR_SPARE5, "SMCP send seq%u free unlocked", te->spe->seq);
		}
	}

	CTR0(KTR_SPARE5, "kthread exit");
	kthread_exit();
}
#endif

int	
tcpmig_need_tcp_ack(struct socket *so)
{
	struct tcpcb *tp;
	uint32_t sendwin, pending;

	if (!so) return (0);
	tp = sototcpcb(so);
	if (!tp) return (0);

	sendwin = min(tp->snd_wnd, tp->snd_cwnd);
	pending = tp->snd_nxt - tp->snd_una;
//CTR5(KTR_SPARE5, "%d: sw%u cw%u pending %u mseg%u", __LINE__, tp->snd_wnd, tp->snd_cwnd, tp->snd_nxt - tp->snd_una,
//    sototcpcb(so)->t_maxseg);
	/*
	 * XXX: 100000 is a dirty hack for triggering ack more frequently, remove it
	 */
	if (sototcpcb(so)->t_state == TCPS_ESTABLISHED && 
	    SEQ_GT(sototcpcb(so)->ack_max, sototcpcb(so)->snd_una) &&
	    SEQ_GT(sototcpcb(so)->snd_max, sototcpcb(so)->snd_una) &&
	    (sbspace(&so->so_snd) <= sototcpcb(so)->t_maxseg ||
	    (sbspace(&so->so_snd) <= 16384) || 
	    (sbspace(&so->so_snd) >= SB_MAX) ||
	    (sbavail(&so->so_snd) >= 100000) ||
	    sendwin < sototcpcb(so)->t_maxseg ||
	    sendwin <= (pending + sototcpcb(so)->t_maxseg)
	    )
	   ) 
		return (1);

	return (0);
}

static struct mbuf *
tcpmig_compose_tcpip_pkt(uint32_t ip_src, uint32_t ip_dst, uint16_t port_src,
    uint16_t port_dst, uint8_t th_flag, uint32_t seq, uint32_t ack, uint16_t th_win,
    struct mbuf *pld, int tlen, struct ifnet *ifn, struct socket *so, int cksum)
{
	char *off;
	int m_size;
	struct mbuf *m;
	struct tcpcb *tp;
	struct inpcb *inp;
	struct ip *ip;
	struct tcphdr *th;

	tp = sototcpcb(so);
	inp = sotoinpcb(so);

	m_size = sizeof(struct ipovly) + sizeof(struct tcphdr);

	/* Generate header first */
	m = m_gethdr(M_NOWAIT, MT_DATA);
	m->m_len = m_size;
	m->m_pkthdr.len = m_size;
	//m->m_data += max_linkhdr;
	m->m_pkthdr.rcvif = ifn;

	/* Fill up necessary info */
	off = mtod(m, char *);
	ip = (struct ip *)off;
	th = (struct tcphdr *)(off + sizeof(struct tcphdr));

	INP_WLOCK(inp);
	tcpip_fillheaders(inp, tp->t_port, ip, th);
	INP_WUNLOCK(inp);
	
	ip->ip_len = htons(m_size);
	ip->ip_src.s_addr = ip_src;
	ip->ip_dst.s_addr = ip_dst;

	th->th_sport = port_src;
	th->th_dport = port_dst;

	th->th_seq = seq;
	th->th_ack = ack;
	th->th_flags = th_flag;
	th->th_win = th_win; 

	/* Append to the beginning of the payload */
	if (!pld)
		goto fix_hdr;
	
	ip->ip_len = htons(ntohs(ip->ip_len) + tlen);
	m_size += tlen;

	m_catpkt(m, pld);

fix_hdr:
	m = tcpmig_m_fixhdr(m, so, m_size);

	if (cksum)
		/* Update the checksum */
		tcpmig_cksum(m, ip, th);

	return (m);
}

static inline int
tcpmig_need_throttle(struct ppshdr *ppsh, struct tcpcb *tp)
{
	struct socket *so;
	uint32_t roff, soff;
	uint32_t pri, rep;

	so = tp->t_inpcb->inp_socket; 
	roff = sbavail(&so->so_rcv) + sbspace(&so->so_rcv);
	soff = sbavail(&so->so_snd) + sbspace(&so->so_snd);

	/*
	 * 1. Replica's snd_una should never be greater than primary's
	 * 2. If 1 holds true, then for calculating the absolute distance
	 * between two uints, we can either do the direct substaction or we
	 * pad 0xffffffff to the wrapped one
	 *
	 */
	pri = tp->rcv_nxt;
	rep = ppsh->rcv_nxt;
	if (rep == 0)
		goto check_sm;
	if (!SEQ_GEQ(pri, rep)) {
		goto check_sm;
	}

	if (pri > rep) {
		if (pri - rep > TM_FALLBEHIND_MAXIMUM - roff) {
			return (1);
		}
	}
	if (pri < rep) {
		if (0xffffffff - rep + pri > TM_FALLBEHIND_MAXIMUM - roff) {
			return (1);
		}
	}
	
check_sm:
	pri = tp->snd_max;
	rep = ppsh->snd_max;
	/* Never throttle when 0, this might be a rexmt */
	if (rep == 0)
		return (0);
	if (!SEQ_GEQ(pri, rep)) {
		printf("bad sn%u rsn%u\n", pri, rep);
		return (0);
	}

	if (pri > rep) {
		if (pri - rep > TM_FALLBEHIND_MAXIMUM - soff) {
			return (1);
		}
	}
	if (pri < rep) {
		if (0xffffffff - rep + pri > TM_FALLBEHIND_MAXIMUM - soff) {
			return (1);
		}
	}

	return (0);
}

static uint32_t 
tcpmig_find_next_ack(struct socket *so, uint32_t orig_ack) {
	struct tcpcb *tp;
	struct inpcb *inp;
	uint32_t ack = 0;
	struct somig_pkt_entry *pkt = NULL, *tmp = NULL;

	tp = sototcpcb(so);
	inp = sotoinpcb(so);

	if (tp->t_state == TCPS_SYN_RECEIVED) {
		return (tp->snd_max);
	}

	/* From the composed ack path */
	ack = orig_ack;
	if (ack == 0) {
		if (tp->rolechange == 1) {
			ack = 0;
		} else {
			TAILQ_FOREACH_SAFE(pkt, &so->so_mig_pkt, list, tmp) {
				if (pkt->seq >= tp->rcv_nxt && pkt->sent == 0) {
					ack = pkt->ack;
					break;
				} 
			}
		}
	}

	if (tp->ack_max == 0) {
		return (tp->snd_una);
	}
	if (SEQ_GT(tp->ack_max, tp->snd_max))
		if (ack != 0) {
			if (SEQ_GT(ack, tp->snd_max)) 
				ack = tp->snd_max;
		} else 
			ack = tp->snd_max;
	else {
		if (ack != 0) {
			if (SEQ_GT(ack, tp->ack_max))
				ack = tp->ack_max;
			if (SEQ_GT(tp->snd_una, ack)) {
				CTR6(KTR_SPARE5, "[%d]%d: !!!! su%u sm%u ack%u am%u",
				    0, __LINE__, tp->snd_una, tp->snd_max, ack, tp->ack_max);
				ack = tp->snd_una;
			}
		} else {
			ack = tp->ack_max;
			if (SEQ_GT(tp->snd_una, ack))
				ack = tp->snd_una;
		}
	}
/*
if (ack != tp->ack_max && so->so_mig_pkt_buffered > 50000 && sbavail(&so->so_snd) > 50000 && orig_ack == 0) {
CTR5(KTR_SPARE5, "%d: ack%u su%u sm%u am%u", __LINE__, ack, tp->snd_una, tp->snd_max,
    tp->ack_max);
CTR4(KTR_SPARE5, "sbav%u rn%u bufd%u ogack%u", sbavail(&so->so_snd), tp->rcv_nxt, so->so_mig_pkt_buffered, orig_ack);
}
*/

	return (ack);
}

struct mbuf *
tcpmig_compose_tcp_ack(struct socket *so)
{
	struct tcpcb *tp;
	struct inpcb *inp;
	uint32_t ack, recwin;
	uint16_t th_win;

	//if (so->so_mig_role != SOMIG_REPLICA) {
	//	return (NULL);
	//}

	tp = sototcpcb(so);
	inp = sotoinpcb(so);

	ack = htonl(tcpmig_find_next_ack(so, 0));

	//CTR5(KTR_SPARE5, "%d: ack%u su%u sm%u am%u", __LINE__,
	//    ntohl(ack), tp->snd_una, tp->snd_max, tp->ack_max); 

	recwin = lmin(lmax(sbspace(&so->so_rcv), 0), (long)TCP_MAXWIN << tp->rcv_scale);
	if (recwin < (so->so_rcv.sb_hiwat / 4) && recwin < tp->t_maxseg)
		recwin = 0;
	if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt) && recwin < (tp->rcv_adv - tp->rcv_nxt))
		recwin = (tp->rcv_adv - tp->rcv_nxt);
	th_win = htons((u_short)(recwin >> tp->rcv_scale));

	th_win = htons(65535);

	if (so->so_mig_role == SOMIG_PRIMARY && tp->rolechange == 0) {
		th_win = tp->snd_wnd;
	}

	return (tcpmig_compose_tcpip_pkt(inp->inp_faddr.s_addr, 
	    inp->inp_laddr.s_addr, inp->inp_fport, inp->inp_lport, TH_ACK, 
	    htonl(tp->rcv_nxt), ack, th_win, (struct mbuf *)0, 0, (struct ifnet *)0,
	    so, 1));
}

void
tcpmig_direct_ip_input(struct mbuf *m, struct tcpcb *tp)
{
	if (tp)
		tp->t_packet_ctlso = 1;
	if (m) ip_input(m);
	if (tp)
		tp->t_packet_ctlso = 0;
}

#ifdef SMCP
static int
tcpmig_newsmcpcb(void **smcp, void *hso)
{
	int error;

	error = smcp_newcb(smcp, hso);
	((struct smcpcb *)*smcp)->somig_ctlinput = &tcpmig_ctlinput;
	return (error);
}
#endif

#ifdef SOMIG_TIMING_DIAG
/*
 * time unit: ms
 *  Bucket:
 *	[0-5]
 *	[6-10]
 *	[11-15]
 *	[...]
 */
static void
somig_timing_bucket_add(struct socket *so, uint32_t time)
{
	int n = 0;
	n = (time - (time > 0)) / SOMIG_TIMING_BUCKET_INTERVAL;
	if (n > SOMIG_TIMING_BUCKET_COUNT) 
		n = SOMIG_TIMING_BUCKET_COUNT - 1;
	timing_bucket[n]++;
}
#endif

void
somig_logprint(int type, int subtype, const char *func, int line, 
    struct mbuf *m, ...)
{
	va_list ap;
	char *fmt;

#if !SMGDEBUG 
	return;
#endif

	switch (type) {
	case SMGLOG_INFO:
		goto print_enabled; 
		break;
	case SMGLOG_DEBUG:
#if SMGLOG
		if (subtype < 0 || subtype >= (sizeof(SMGLOG_SW)/sizeof(int))) {
			INFOPRINT("Wrong logging type %d, subtype %d\n", 
			    type, subtype);
			return;
		}
		if (SMGLOG_SW[subtype])
			goto print_enabled;
#endif
		break;
	}
	return; 

print_enabled:
	va_start(ap, m);
	fmt = va_arg(ap, char *);
	printf("[%s:%d] ", func, line);
	vprintf(fmt, ap);
	va_end(ap);
#if SMGMBUFLOG
	if (m)
		MBUFPRINT(m);
#endif
}


static void
tcpmig_getcb(struct socket *so, void *buf, int buf_len, int who, int *len)
{
	struct tcpcb *tp = NULL;
	struct inpcb *inp = NULL;
	struct cc_var *cc = NULL;

	if (buf == NULL || len == NULL)
		return;
	
	tp = sototcpcb(so);
	inp = sotoinpcb(so);
	if (tp)
		cc = tp->ccv;

	switch (who) {
	case SOMIG_CB_TCPCB:
		if (buf_len < sizeof(struct tcpcb)) {
			goto bad;
		}
		if (!tp)
			goto bad;

		memcpy(buf, tp, sizeof(struct tcpcb));
		*len = sizeof(struct tcpcb);
		break;
	case SOMIG_CB_INPCB:
		if (buf_len < sizeof(struct inpcb)) {
			goto bad;
		}
		if (!inp)
			goto bad;

		memcpy(buf, inp, sizeof(struct inpcb));
		*len = sizeof(struct inpcb);
		break;
	case SOMIG_CB_CC:
		if (buf_len < sizeof(struct cc_var)) {
			goto bad;
		}
		if (!cc)
			goto bad;
		
		memcpy(buf, cc, sizeof(struct cc_var));
		*len = sizeof(struct cc_var);
		break;
	default:
		goto bad;
	}

	return;
bad:
	len = 0;
}

static int
tcpmig_get_livepeer_count(struct socket *so)
{
	struct somig_peer_entry *peer;
	int count = 0;

	KASSERT(so != NULL, ("%s: NULL so.", __func__));
	KASSERT(so->so_mig_role != SOMIG_NONE, ("%s: Non-SOMIG so.", __func__));

	if (so->so_state & SS_ISDISCONNECTING || so->so_state & SS_ISDISCONNECTED)
		return (0);

	TAILQ_FOREACH(peer, &so->so_mig_peer, list) {
		if (peer == NULL)
			continue;
		if (peer->state != SOMIG_SO_CONNECTED)
			continue;
		count++;
	}
	return (count);
}

#ifdef SOMIG_FASTMIG
static void 
tcpmig_if_down(struct socket *so)
{
	struct sockaddr_in *sa;
	struct in_ifaddr *ia;
	CK_STAILQ_FOREACH(ia, &V_in_ifaddrhead, ia_link) {
		sa = (struct sockaddr_in *)ia->ia_ifa.ifa_addr;
		if (sa->sin_addr.s_addr == sotoinpcb(so)->inp_laddr.s_addr) {
			ia->ia_ifp->if_flags &= ~IFF_UP;
			if_link_state_change(ia->ia_ifp, LINK_STATE_DOWN);
			//if_down(ia->ia_ifp);
			break;
		}
	}
}

static void
in_socktrim(struct sockaddr_in *ap)
{
	char *cplim = (char *) &ap->sin_addr;
	char *cp = (char *) (&ap->sin_addr + 1);

	ap->sin_len = 0;
	while (--cp >= cplim)
		if (*cp) {
			(ap)->sin_len = cp - (char *) (ap) + 1;
		break;
	}
}

static void
tcpmig_if_promote(struct ifnet *ifp, struct ifaddr *ifa)
{
SMGTPRT(NULL, "Add prefix");
	in_addprefix(ifatoia(ifa));
SMGTPRT(NULL, "Add loopback route");
	ifa_add_loopback_route(ifa,
	    (struct sockaddr *)&ifatoia(ifa)->ia_addr);

SMGTPRT(NULL, "ARP announce");
	arp_announce_ifaddr(ifp, 
	    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ifp->if_hw_addr);
}

void
tcpmig_add_ifa(struct ifnet *ifp, uint32_t addr)
{
	struct ifaddr *ifa;
	struct in_ifaddr *ia;
	struct sockaddr_in sa, mask, broadaddr;

	sa.sin_len = sizeof(sa);
	sa.sin_family = AF_INET; 
	sa.sin_addr.s_addr = addr;
	sa.sin_port = 0;

	/* TODO: change mask and broadcast addr to reflect the actual setup */
	mask.sin_len = sizeof(mask);
	mask.sin_family = AF_INET; 
	mask.sin_addr.s_addr = 0xffffff;
	mask.sin_port = 0;

	broadaddr.sin_len = sizeof(broadaddr);
	broadaddr.sin_family = AF_INET; 
	broadaddr.sin_addr.s_addr = addr | 0xff000000;
	broadaddr.sin_port = 0;

	ifa = ifa_alloc(sizeof(struct in_ifaddr), M_WAITOK);
	ia = (struct in_ifaddr *)ifa;
	ifa->ifa_addr = (struct sockaddr *)&ia->ia_addr;
	ifa->ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
	ifa->ifa_netmask = (struct sockaddr *)&ia->ia_sockmask;
	ia->ia_ifp = ifp;
	ia->ia_addr = sa;
	ia->ia_sockmask = mask;
	ia->ia_subnetmask = ntohl(ia->ia_sockmask.sin_addr.s_addr);
	ia->ia_subnet = ntohl(sa.sin_addr.s_addr) & ia->ia_subnetmask;
	in_socktrim(&ia->ia_sockmask);
	ia->ia_broadaddr = broadaddr;

	/* if_addrhead is already referenced by ifa_alloc() */
	IF_ADDR_WLOCK(ifp);
	CK_STAILQ_INSERT_TAIL(&ifp->if_addrhead, ifa, ifa_link);
	IF_ADDR_WUNLOCK(ifp);

	ifa_ref(ifa);			/* in_ifaddrhead */
	IN_IFADDR_WLOCK();
	CK_STAILQ_INSERT_TAIL(&V_in_ifaddrhead, ia, ia_link);
	LIST_INSERT_HEAD(INADDR_HASH(ia->ia_addr.sin_addr.s_addr), ia, ia_hash);
	IN_IFADDR_WUNLOCK();
}
#endif

/*
 * Wrapper functions
 */
struct somig_func so_mig_func = {
	.so_mig_connect = tcpmig_soconnect,
	.so_mig_sync = tcpmig_sosync,
	.so_mig_join = tcpmig_sojoin,
	.so_mig_migrate = tcpmig_somigrate,
	.so_mig_disconnect = tcpmig_sodisconnect,
	.so_mig_update_sooptions = tcpmig_soupdateoptions,
	.so_mig_get_addrtuple = tcpmig_getaddrtuple,
	.so_mig_flushpkt = tcpmig_flushpkt,
#ifdef SOMIG_TASKQUEUE
	.so_mig_taskqueue_thread = tcpmig_tcp_bcast_task,
#endif
#ifdef SOMIG_FASTMIG
	.so_mig_if_down = tcpmig_if_down,
#endif
	.so_mig_getcb = tcpmig_getcb,
#ifdef SMCP
	.smcp_newcb = tcpmig_newsmcpcb,
	.smcp_freecb = smcp_freecb,
	.smcp_bind = smcp_bind,
	.smcp_listen = smcp_listen,
	.smcp_set_pentry = smcp_set_pentry,
	.smcp_get_state = smcp_get_state,
	.smcp_set_primary = smcp_set_primary,
	.smcp_get_so_laddr = smcp_get_so_laddr,
	.smcp_get_so_lport = smcp_get_so_lport,
	.smcp_get_so_faddr = smcp_get_so_faddr,
	.smcp_get_so_fport = smcp_get_so_fport,
	.smcp_set_laddr = smcp_set_laddr,
	.smcp_set_faddr = smcp_set_faddr,
	.smcp_inherit = smcp_inherit
#endif
};
