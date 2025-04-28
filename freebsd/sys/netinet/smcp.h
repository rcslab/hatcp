/*
 *
 *
 * smcp.h
 *
 *
 */
#ifndef _SMCP_H_
#define _SMCP_H_

#ifdef _KERNEL

#include <netinet/in_pcb.h>

#define SMCP_INIT		0
#define SMCP_WAITING		1
#define SMCP_NORMAL		2	/* Peer discovered(tcps_established equiv) */
#define SMCP_WAIT_ONLY		252	/* For listening only(so nested cb) */
#define SMCP_KILL		253
#define SMCP_DONE		254
#define SMCP_FREE		255

#define SMCP_IPTTL		60

/*
 * For a listening socket, the replicated ip/port is local ip/port.
 * For a established socket, the replicated ip/port is peer(the other side) ip/port.
 * The reason ^ is, multiple peers could connect to the same listening socket so
 * we couldn't rely on local ip/port to identify the replicated connection.
 */
struct smcpcb { 
	struct inpcb *inp;	/* Point to host so */
	struct somig_peer_entry *so_mig_pentry;
	uint32_t l_addr, f_addr;    /* my ip and peer ip */
	uint32_t r_addr;	    /* replicated ip */
	uint16_t r_port;	    /* replicated port */
	uint8_t id;		    /* so_mig_id */
	uint8_t state;
	struct mtx s_lock;	    /* lock when passing thru the traffic */

	int srtt;		    /* smoothed rtt, only updates for PRIMARY smcpcb */

	void (*somig_ctlinput)(struct mbuf *, void *, int *, int);
	int (*smcp_output)(struct smcpcb *, struct mbuf *, int, int, int);
};

#define SMCP_LOCK(x)	mtx_lock(&x->s_lock)
#define SMCP_UNLOCK(x)	mtx_unlock(&x->s_lock)


/*
 * Note: the addr_map_list design is temporary. Since this list will be queried 
 *  on per packet basis, when connection mapping increases, the performance
 *  degrades significantly. However, on most of the using cases the mapping wont
 *  be high so we can now just go with this. 
 *
 */
struct addr_map_entry {
	struct smcpcb *smcp;
	SLIST_ENTRY(addr_map_entry) list;
};
SLIST_HEAD(addr_map_list, addr_map_entry); 

struct smcp_addr_map {
	struct addr_map_list	aml;
	struct mtx		aml_lock;
};

VNET_DECLARE(struct smcp_addr_map, addr_map);
#define V_smcp_addr_map		VNET(addr_map)
#define ADDR_MAP_LOCK(x)	mtx_lock(&x.aml_lock)
#define ADDR_MAP_UNLOCK(x)	mtx_unlock(&x.aml_lock)

void add_addr_map(struct smcpcb *);
void del_addr_map(struct smcpcb *);
struct smcpcb * find_addr_map(uint32_t, uint16_t, uint8_t);

int smcp_newcb(void **, void *);
int smcp_freecb(void **);
int smcp_bind(void *, uint32_t, uint16_t, uint32_t, int);
int smcp_listen(void *);
void smcp_set_pentry(void *, struct somig_peer_entry *);
int smcp_get_state(void *);
int smcp_get_id(void *);
void smcp_set_id(void *, uint8_t);
void smcp_set_primary(void *, uint32_t, uint16_t);
void smcp_get_primary(void *, uint32_t*, uint16_t*);
uint32_t smcp_get_so_laddr(void *);
uint16_t smcp_get_so_lport(void *);
uint32_t smcp_get_so_faddr(void *);
uint16_t smcp_get_so_fport(void *);
void smcp_set_laddr(void *, uint32_t);
void smcp_set_faddr(void *, uint32_t);
void smcp_inherit(void *, void *);
uint32_t smcp_get_rtt(void *);
void smcp_update_rtt(void *, int);

void smcp_init(void);
int smcp_input(struct mbuf **, int *, int);
int smcp_output(struct inpcb *, struct mbuf *, int);
void smcp_ctlinput(int, struct sockaddr *, void *);
int smcp_ctloutput(struct socket *, struct sockopt *);

static void
SMCP_PRINT(void *cb) 
{
	struct smcpcb *c = (struct smcpcb *)cb;

	printf("SMCP %p: {\n", c);
	printf("la%u, fa%u, ra%u, rp%u\n", c->l_addr, c->f_addr, c->r_addr, c->r_port);
	printf("id%u inp%p smpe%p\n", c->id, c->inp, c->so_mig_pentry);
	printf("state%u\n", c->state);
	printf("}\n");
}

//extern struct pr_usrreqs    smcp_usrreqs;

#endif
#endif

