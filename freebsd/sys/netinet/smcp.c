/*
 * smcp.c
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
#include <sys/mbuf.h>
#include <sys/kdb.h>

#include <net/vnet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_options.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_migration_var.h>
#include <netinet/smcp.h>

#ifdef SMCP

int smcp_freecb_internal(void **smcp, int locked);
static int smcp_output_internal(struct smcpcb *smcp, struct mbuf *m, int flag, 
    int pid, int sid);
VNET_DEFINE(struct smcp_addr_map, addr_map);
static struct mtx	smcp_lock;

/* 
 * Addr and port are in NBO
 * When adding a mapping, 
 *	the addr and port is the tuple used by hostso
 */
void 
add_addr_map(struct smcpcb *smcp)
{
	struct addr_map_entry *am_entry;

	am_entry = (struct addr_map_entry *)malloc(sizeof(struct addr_map_entry),
	    M_TEMP, M_NOWAIT);
	am_entry->smcp = smcp;

	SLIST_INSERT_HEAD(&V_smcp_addr_map.aml, am_entry, list);
}

void 
del_addr_map(struct smcpcb *smcp)
{
	struct addr_map_entry *am_entry, *tmp;

	SLIST_FOREACH_SAFE(am_entry, &V_smcp_addr_map.aml, list, tmp) {
		if (am_entry->smcp == smcp) {
			SLIST_REMOVE(&V_smcp_addr_map.aml, am_entry, addr_map_entry, list);
		}
	}
}

struct smcpcb * 
find_addr_map(uint32_t addr, uint16_t port, uint8_t id)
{
	struct addr_map_entry *am_entry, *tmp;
	struct smcpcb *smcp;
	
	SLIST_FOREACH_SAFE(am_entry, &V_smcp_addr_map.aml, list, tmp) {
		smcp = am_entry->smcp;
if (!(smcp->inp->inp_socket) && (smcp->r_port == port)) {
	printf("pa %u a %u pp %u p %u pi %u i %u inp%p\n", smcp->r_addr, addr, smcp->r_port, port, smcp->id, id, smcp->inp);
	printf("so%p\n", smcp->inp->inp_socket);
}
		if (smcp->r_addr == addr && smcp->r_port == port && 
		    smcp->id == id && 
		    (smcp->inp->inp_socket->so_mig_role != SOMIG_PRIMARY ? smcp->state != SMCP_WAIT_ONLY: 1)) {
			return (smcp);
		}
	}
	return (NULL);
}

int
smcp_newcb(void **smcp, void *hso)
{
	struct smcpcb *cb;
	cb = (struct smcpcb *)malloc(sizeof(struct smcpcb), M_TEMP, M_NOWAIT);
	if (!cb) {
		return (ENOMEM);
	}

	cb->state = SMCP_INIT;
	cb->inp = sotoinpcb((struct socket *)hso);
	cb->smcp_output = &smcp_output_internal;
	cb->id = 0;
	cb->srtt = 0;
	mtx_init(&cb->s_lock, "smcblk", NULL, MTX_DEF | MTX_NEW);

	*smcp = cb;
	return (0);
}

int 
smcp_freecb(void **smcp) {
	return (smcp_freecb_internal(smcp, 0));
}

int
smcp_freecb_internal(void **smcp, int locked)
{
	struct smcpcb *cb = *((struct smcpcb **)smcp);
	
	if (!cb)
		return (0);

	ADDR_MAP_LOCK(V_smcp_addr_map);
	if (!locked)
		SMCP_LOCK(cb);
	del_addr_map(cb);
	ADDR_MAP_UNLOCK(V_smcp_addr_map);

	cb->state = SMCP_DONE;
	mtx_destroy(&cb->s_lock);
	free(cb, M_TEMP);
	*smcp = NULL;
	return (0);
}

/*
 * The addr and port is the original TCP connection's tuple
 */
int
smcp_bind(void *smcp, uint32_t addr, uint16_t port, uint32_t l_addr, int l_addr_only)
{
	if (((struct smcpcb *)smcp)->state != SMCP_INIT) {
		return (EINVAL);
	}
	
	//printf("bind r_addr %u r_port %u l_addr %u\n", addr, port, l_addr);
	if (!l_addr_only) {
		((struct smcpcb *)smcp)->r_addr = addr;
		((struct smcpcb *)smcp)->r_port = port;
	}
	((struct smcpcb *)smcp)->l_addr = l_addr;

	ADDR_MAP_LOCK(V_smcp_addr_map);
	add_addr_map((struct smcpcb *)smcp); 
	ADDR_MAP_UNLOCK(V_smcp_addr_map);
	return (0);
}

int
smcp_listen(void *smcp)
{
	if (((struct smcpcb *)smcp)->state != SMCP_INIT) {
		return (EINVAL);
	}
	((struct smcpcb *)smcp)->state = SMCP_WAIT_ONLY;

	return (0);
}

void
smcp_set_pentry(void *smcp, struct somig_peer_entry *peer)
{
	((struct smcpcb *)smcp)->so_mig_pentry = peer;
}

int
smcp_get_state(void *smcp)
{
	return (((struct smcpcb *)smcp)->state);
}

int
smcp_get_id(void *smcp)
{
	return (((struct smcpcb *)smcp)->id);
}

void
smcp_set_id(void *smcp, uint8_t id) 
{
	((struct smcpcb *)smcp)->id = id;
	((struct smcpcb *)smcp)->so_mig_pentry->id = id;
}

void 
smcp_set_primary(void *smcp, uint32_t addr, uint16_t port)
{
	((struct smcpcb *)smcp)->r_addr = addr;
	((struct smcpcb *)smcp)->r_port = port;
}

void
smcp_get_primary(void *smcp, uint32_t *addr, uint16_t *port)
{
	struct smcpcb *cb;

	cb = (struct smcpcb *)smcp;
	*addr = cb->r_addr;
	*port = cb->r_port;
}

uint32_t 
smcp_get_so_laddr(void *so)
{
	struct inpcb *inp = NULL;

	inp = sotoinpcb((struct socket *)so);
	if (inp) {
		return ntohl(((struct inpcb *)inp)->inp_laddr.s_addr);
	}
	return (0);
}

uint16_t 
smcp_get_so_lport(void *so)
{
	struct inpcb *inp = NULL;

	inp = sotoinpcb((struct socket *)so);
	if (inp) {
		return ntohs(((struct inpcb *)inp)->inp_lport);
	}
	return (0);
}

uint32_t 
smcp_get_so_faddr(void *so)
{
	struct inpcb *inp = NULL;

	inp = sotoinpcb((struct socket *)so);
	if (inp) {
		return ntohl(((struct inpcb *)inp)->inp_faddr.s_addr);
	}
	return (0);
}

uint16_t
smcp_get_so_fport(void *so)
{
	struct inpcb *inp = NULL;

	inp = sotoinpcb((struct socket *)so);
	if (inp) {
		return ntohs(((struct inpcb *)inp)->inp_fport);
	}
	return (0);
}

void
smcp_set_laddr(void *smcp, uint32_t addr)
{
	((struct smcpcb *)smcp)->l_addr = addr;
}

void
smcp_set_faddr(void *smcp, uint32_t addr)
{
	((struct smcpcb *)smcp)->f_addr = addr;
}

void
smcp_inherit(void *cb_dst, void *cb_src)
{
	struct smcpcb *src, *dst;

	src = (struct smcpcb *)cb_src;
	dst = (struct smcpcb *)cb_dst;

	dst->inp = src->inp;
	dst->l_addr = src->l_addr;
	dst->f_addr = src->f_addr;
	dst->r_addr = src->r_addr;
	dst->r_port = src->r_port;
}

uint32_t
smcp_get_rtt(void *smcp)
{
	KASSERT(smcp, ("NULL smcp"));
	return (((struct smcpcb *)smcp)->srtt);
}

/*
 * Based on TCP srtt calculation: R = aR+(1-a)M, a=0.875(RFC793, tcp_xmit_timer
 * interger hack)
 */
void
smcp_update_rtt(void *smcp, int rtt)
{
	struct smcpcb *cb = smcp;
	int delta;

	KASSERT(cb, ("NULL smcp"));
	KASSERT(rtt >= 0, ("Bad SMCP RTT measurement"));
	if (rtt == 0)
		return;
	if (cb->srtt == 0) {
		cb->srtt = rtt << TCP_RTT_SHIFT;
		return;
	}
	
	delta = ((rtt - 1) << TCP_DELTA_SHIFT) 
		- (cb->srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT));

	if ((cb->srtt + delta) <= 0)
		cb->srtt = 1;
}

void
smcp_init(void)
{
	printf("smcp proto initialized.\n");
	CTR2(KTR_SPARE5, "%d:%s", __LINE__, __func__);
	/* Init addr_map mechanism */
	SLIST_INIT(&V_smcp_addr_map.aml);
	mtx_init(&V_smcp_addr_map.aml_lock, "samlk", NULL, MTX_DEF); 
	mtx_init(&smcp_lock, "smcplk", NULL, MTX_DEF);
}

int
smcp_input(struct mbuf **mp, int *offp, int proto)
{
	struct mbuf *m;
	struct ip *ip;
	struct tmhdr *tmh;
	uint16_t ip_len, t_hdrlen;
	struct smcpcb *smcp;
	int iphlen, drop_hdrlen = 0;

	m = *mp;
	iphlen = *offp;
	*mp = NULL;

	/*
	 * Get IP and SOMIG header, plus the nested ip+tcp
	 */
	t_hdrlen = iphlen + sizeof(struct tmhdr);

	if (m->m_len < t_hdrlen) {
		CTR3(KTR_SPARE5, "smcp %d: pullup %u mlen %u", __LINE__, 
		    t_hdrlen, m->m_len);
		if ((m = m_pullup(m, t_hdrlen)) == NULL) {
			CTR2(KTR_SPARE5, "Couldn't pull up ip+tmhdr worth data from mbuf. m_len %d pkthdrlen %u", (*mp)->m_len, (*mp)->m_pkthdr.len);
			panic("check mbuf");
			goto bad;
		}
	}
	ip = mtod(m, struct ip *);
	ip_len = ntohs(ip->ip_len) - iphlen;
	
	tmh = (struct tmhdr *)((caddr_t)ip + iphlen);

	/*
	 * Strip IP header
	 */
	m_adj(m, iphlen);

	/*
	 * Compare ip len with somig carried len
	 */
	if (ip_len != tmh->len) {
		printf("Wrong payload size %u, where ip hdr size %u ipid%u\n",
		    tmh->len, ip_len, ntohs(ip->ip_id));
		MBUFPRINTN(m, 150);
	struct addr_map_entry *am_entry;
	struct smcpcb *smcp;
	struct inpcb *sinp;
	struct tcpcb *stp;
	SLIST_FOREACH(am_entry, &V_smcp_addr_map.aml, list) {
		smcp = am_entry->smcp;
		if (smcp->inp) {
			sinp = smcp->inp;
			stp = (struct tcpcb *)(sinp)->inp_ppcb;
			printf("host rcvn%u sndm%u\n",
			    stp->rcv_nxt, stp->snd_max);
		}
	}

		//panic("check pldsize");
		goto bad;
	}
	//CTR2(KTR_SPARE5, "SMCP rcv'd %u hdr len %u", tmh->len, m->m_pkthdr.len);

	/*
	 * Find corresponding cb(replica)
	 */
	ADDR_MAP_LOCK(V_smcp_addr_map);
	smcp = find_addr_map(tmh->addr, tmh->port, tmh->id);
	if (smcp == NULL) {
		CTR0(KTR_SPARE5, "No inp found in scmp addr map. ---see MBUF---");
		CTR3(KTR_SPARE5, "->addr %u port %u id %u", tmh->addr, tmh->port, tmh->id & 0xff);
		goto badunlock;
	}

	/* 
	 * Set peer f_addr 
	 */
	if (smcp->state < SMCP_NORMAL) {
		smcp->f_addr = ntohl(ip->ip_src.s_addr);
	}

	/*
	 * Somig input
	 */
	if (smcp->somig_ctlinput) {
		SMCP_LOCK(smcp);
		ADDR_MAP_UNLOCK(V_smcp_addr_map);

		//SOMIG_REPLICA_LOCK(smcp->inp->inp_socket);
		(*smcp->somig_ctlinput)(m, smcp, &drop_hdrlen, ip_len);
		//SOMIG_REPLICA_UNLOCK(smcp->inp->inp_socket);
		if (smcp->state == SMCP_FREE) {
			smcp_freecb_internal((void **)&smcp, 1);
		} else
			SMCP_UNLOCK(smcp);
	} else {
		CTR0(KTR_SPARE5, "No ctlinput found in smcpcb");
		goto bad;
	}

	return (IPPROTO_DONE);

badunlock:
	ADDR_MAP_UNLOCK(V_smcp_addr_map);

bad:
	CTR0(KTR_SPARE5, "SMCP dropped one pkt");
	m_freem(m);
	return (IPPROTO_DONE);
}

int
smcp_output(struct inpcb *inp, struct mbuf *m, int rexmt)
{
	int sid, pid;
	struct smcpcb *smcp;
	smcp = inp->inp_socket->smcpcb;
	sid = inp->inp_socket->so_mig_sid;
	pid = inp->inp_socket->so_mig_pid;
	return (smcp_output_internal(smcp, m, rexmt, pid, sid));
}

static int
smcp_output_internal(struct smcpcb *smcp, struct mbuf *m, int flag, int pid, int sid)
{
	struct ip *ip = NULL;
	struct mbuf *bm;
	int error;
	int len, new_mbuf = 0;
	uint32_t hdrlen = 0;
	uint8_t ipopt_len = 0;
#ifdef SOMIG_OPTI_IPREASS
	char * cp;
	uint32_t ts;
	uint32_t extid;
	
	if (sid) 
		ipopt_len = 12; // 4bytes rounded 
#endif

	len = m_length(m, NULL);

	/* Prepend IP mbufs */
	/* Make sure leave the room for link layer hdr */
	bm = m;
	if (flag & SOMIG_SEND_FLAG_REXMT)
		goto send;

	hdrlen = sizeof(struct ipovly) + ipopt_len + max_linkhdr;
	if (M_LEADINGSPACE(bm) < hdrlen) {
		new_mbuf = 1;
		M_PREPEND(bm, sizeof(struct ipovly) + ipopt_len + max_linkhdr, M_NOWAIT);
	//printf("prepend m_data %p m_len %d pktlen %d\n", bm->m_data, bm->m_len, bm->m_pkthdr.len);
		bm->m_len = sizeof(struct ip) + ipopt_len;
		bm->m_pkthdr.len = len + sizeof(struct ipovly) + ipopt_len;
		bm->m_data += max_linkhdr;
	} else {
		bm->m_len += (sizeof(struct ipovly) + ipopt_len);
		bm->m_pkthdr.len += (sizeof(struct ipovly) + ipopt_len);
		bm->m_data -= (sizeof(struct ipovly) + ipopt_len);
	} 

	if (bm == NULL) {
		panic("M_PREPEND error");
	}
	m_tag_init(bm);

	//printf("total hdr size %lu\n", sizeof(struct ip) + max_linkhdr);
	//bm->m_pkthdr.len += sizeof(struct ipovly);
	bm->m_pkthdr.fibnum = 0;
	bm->m_pkthdr.csum_flags = 0;
	//printf("after m_data %p m_len %d pktlen %u\n", bm->m_data, bm->m_len, bm->m_pkthdr.len);
	/*
	if (new_mbuf) {
		bm->m_len = sizeof(struct ip);
	} else {
		bm->m_len = bm->m_len - (max_linkhdr - 2);
	}
	*/
	bm->m_flags |= M_PKTHDR;
	bm->m_pkthdr.snd_tag = NULL;
	
	/* Fill out IP header */
	ip = mtod(bm, struct ip *);
	ip->ip_v = IPVERSION;
	ip->ip_hl = 5 + (ipopt_len >> 2);
	ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = (uint16_t)htons(bm->m_pkthdr.len);
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = SMCP_IPTTL;
	ip->ip_sum = 0;
	ip->ip_p = IPPROTO_SMCP;
	ip->ip_src.s_addr = htonl(smcp->l_addr);
	ip->ip_dst.s_addr = htonl(smcp->f_addr);
#ifdef SOMIG_OPTI_IPREASS
	if (ipopt_len > 0) {
		ts = tcp_ts_getticks();
		/*
		 * extid = hi 17 bits pid + lo 15 bits fd 
		 */
		extid = ((pid & 0x1FFFF) << 15) | (sid & 0x7fff);
		/*
		 * | type(1B) | len(1B) | data() |
		 * type: copied(1b) + class(2b) + number(5b)
		 * data: 32bits extid + 32bits ts 
		 * 4 bytes padded.
		 */
		cp = (char *)(ip+1);
		cp[0] = (uint8_t)IPOPT_REASS;
		cp[1] = IPOPT_REASS_OLEN;
		/* set extid */
		cp[2] = (extid >> 24) & 0xff;
		cp[3] = (extid >> 16) & 0xff;
		cp[4] = (extid >> 8) & 0xff;
		cp[5] = (extid) & 0xff;
		/* set ts */
		cp[6] = (ts >> 24) & 0xff; 
		cp[7] = (ts >> 16) & 0xff;
		cp[8] = (ts >> 8) & 0xff;
		cp[9] = (ts) & 0xff;
		
		cp[10] = IPOPT_NOP;
		cp[11] = IPOPT_EOL;
	}
#endif

	//CTR3(KTR_SPARE5, "smcp out src%u dst%u len%u", ip->ip_src.s_addr, ip->ip_dst.s_addr, bm->m_pkthdr.len);
send:
	if (smcp->state >= SMCP_KILL) {
		CTR1(KTR_SPARE5, "SMCP state %u", smcp->state);
		m_freem(bm);
		return (0);
	}

	/* Hand to ip layer */
	//mtx_lock(&smcp_lock);
	//SMCP_LOCK(smcp);
	CURVNET_SET(smcp->inp->inp_socket->so_vnet);
//CTR4(KTR_SPARE5, "%d: sending m%p mn%p flg%u", __LINE__, bm, bm->m_next, bm->m_flags);
	error = ip_output(bm, NULL, NULL, 0, NULL, NULL);
	CURVNET_RESTORE();
	//mtx_unlock(&smcp_lock);
	//SMCP_UNLOCK(smcp);
	if (error)
		printf("SMCP out err %d\n", error);

	return (error);
}

void
smcp_ctlinput(int cmd, struct sockaddr *sa, void *vip)
{
}

int
smcp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	return (0);
}

#ifdef INET
//struct pr_usrreqs smcp_usrreqs = {
//};
#endif

#endif //SMCP
