/*
 *
 * tcp_migration_var.h
 *
 *
 */
#ifndef _TCP_MIGRATION_VAR_H_
#define _TCP_MIGRATION_VAR_H_

#ifdef _KERNEL

/*
 * Flags for tmhdr->cmd field.
 */
#define TM_CMD_HANDSHAKE	1
#define TM_CMD_PACKET		2
#define TM_CMD_MIGRATE		3
#define TM_CMD_LEAVE		4
#define TM_CMD_SYNC		5
#define TM_CMD_JOIN		6

/*
 * Flags for tmhdr->status field.
 */
#define TM_STATUS_NULL		0
#define TM_STATUS_OK		1
//#define TM_STATUS_REQUEST	2
//#define TM_STATUS_PROMOTION	3
//#define TM_STATUS_DEMOTION	4
#define TM_STATUS_FULL		5
#define TM_STATUS_WRONGTCPSTATE	6
#define TM_STATUS_OTHER		7

/*
 * Flags for tcpmig_pktinput
 */
#define	TM_PKTIN_BUFFER			0x00000001
#define	TM_PKTIN_TS			0x00000002
#define	TM_PKTIN_SPLIT_M1		0x00000004
#define	TM_PKTIN_SPLIT_M2		0x00000008
#define	TM_PKTIN_NO_BCAST		0x10000000
#define	TM_PKTIN_BCAST_IF_FULLSO	0x20000000
#define	TM_PKTIN_DONT_ACK		0x40000000

/*
 * Migration header struct
 * Appended after TCP header. 
 * 28bytes with every option on
 *
 * Layout of types:
 * HS: | TCPIP | TMHDR | VER | NODELIST |
 *
 */
struct tmhdr {
	uint32_t magic;
	uint16_t cmd;
	uint16_t status;
#ifdef SMCP
	uint32_t addr;	    /* replicated tcp socket address */
	uint16_t port;	    /* replicated tcp socket port*/
	uint8_t  id;	    /* sender so_mig_id */
	uint8_t  padding;
#endif
	uint32_t debug_seq;
#ifdef SOMIG_TIMING_DIAG
	uint32_t stime;	    /* sending timestamp (recorded on PRIMARY, echoed from REPLICA) */
#endif
	uint32_t len;	    /* Total length(Header+nodes+exlen+payload) */
	uint32_t exlen;	    /* Size of extra payload (Eg. Nodelist / TMVer) */
};

int	tcpmig_m_stitch(struct mbuf **, struct mbuf *, int *, int);
struct mbuf * tcpmig_m_extize(struct mbuf *);

static __inline void
MBUFPRINT(struct mbuf *m)
{
	char *a;
	int prtsz = 0;
	
	if (m == NULL) {
		printf("NULL mbuf @ %p\n", m);
		return;
	}

	printf("======mbuf @ %p [len=%d]\n", m, m_length(m, NULL));

	while (m) {
		printf(" | ");
		a = mtod(m, char *);
		for (int i=0;i<m->m_len;i++) {
			prtsz++;
			printf("%02X ", (unsigned int)(a[i] & 0xff));
		}
		m = m->m_next;
		if (prtsz > 10000) 
			break;
	}
	printf("\n========================\n");
}

static __inline void
MBUFPRINTN(struct mbuf *m, int n)
{
	char *a;
	int prtsz = 0;
	
	if (m == NULL) {
		printf("NULL mbuf @ %p\n", m);
		return;
	}

	printf("======mbuf @ %p [len=%d]\n", m, m_length(m, NULL));

	while (m) {
		printf(" | ");
		a = mtod(m, char *);
		for (int i=0;i<m->m_len;i++) {
			if (prtsz++ > n)
				break;
			printf("%02X ", (unsigned int)(a[i] & 0xff));
		}
		m = m->m_next;
		if (prtsz > 10000 || prtsz > n) 
			break;
	}
	printf("\n========================\n");
}

#endif
#endif
