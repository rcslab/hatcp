/*
 * tcp_migration_mbuf.c
 */
#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/types.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>

#include <netinet/tcp_migration_var.h>

static void tcpmig_m_extfree(struct mbuf *m);

int
tcpmig_m_stitch(struct mbuf **msp, struct mbuf *m0, int *msp_orig_size, int first_frag_size)
{
	int frag_size, error = 0;
	struct mbuf *m;
	//volatile u_int *refcnt;

	KASSERT(msp != NULL, ("Null msp"));

	frag_size = first_frag_size;
	m = m0;

	for (; m; m = m->m_next) {
		/* Increase the Refcnt for the first chain */
		/*
		if (m->m_flags & M_EXT) {
			if (m->m_ext.ext_flags & EXT_FLAG_EMBREF) {
				refcnt = &m->m_ext.ext_count;
			} else {
				KASSERT(m->m_ext.ext_cnt != NULL,
				    ("%s: no refcounting pointer on %p", __func__, m));
				refcnt = m->m_ext.ext_cnt;
			}

			if (*refcnt == 1)
				*refcnt += 1;
			else
				atomic_add_int(refcnt, 1);
		}
		*/

		if (m->m_len >= frag_size) {
			*msp_orig_size = (m->m_len == frag_size) ? 0: m->m_len;
			m->m_len = frag_size;
			*msp = m->m_next;
			m->m_next = NULL;
			break;
		}
		frag_size -= m->m_len;
	}

	/*
	m = *msp;
	for (; m; m = m->m_next) {
		if (m->m_flags & M_EXT) {
			if (m->m_ext.ext_flags & EXT_FLAG_EMBREF) {
				refcnt = &m->m_ext.ext_count;
			} else {
				KASSERT(m->m_ext.ext_cnt != NULL,
				    ("%s: no refcounting pointer on %p", __func__, m));
				refcnt = m->m_ext.ext_cnt;
			}

			if (*refcnt == 1)
				*refcnt += 1;
			else
				atomic_add_int(refcnt, 1);
		}
	}
	*/
	return (error);
}

/*
 * Make the provided mbuf point to the EXTernal data source instead of holding
 * the actual data
 *
 * NB: record all necessary info from m since m will be freed afterwards
 */
struct mbuf * 
tcpmig_m_extize(struct mbuf *m)
{
	struct mbuf *m0;
	char *buffer;

	if (!m) 
		return (NULL);

	if (m->m_flags & M_EXT)
		return (NULL);

	/* Dup the data */
	buffer = (char *)malloc(m->m_len, M_TEMP, M_NOWAIT | M_ZERO);
	if (!buffer)
		return (NULL);
	bcopy(m->m_data, buffer, m->m_len);

	/* EXTize*/
	m0 = m_gethdr(M_NOWAIT, MT_DATA);
	m0->m_len = m->m_len;

	m_extadd(m0, buffer, m->m_len, tcpmig_m_extfree, buffer, NULL, 
	    M_RDONLY, EXT_NET_DRV);

	/* Free the original mbuf */
	m->m_next = NULL;
	m_freem(m);

	return (m0);
}

static void
tcpmig_m_extfree(struct mbuf *m)
{
	free((void *)m->m_ext.ext_arg1, M_TEMP);
}
