/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)socketvar.h	8.3 (Berkeley) 2/19/95
 *
 * $FreeBSD$
 */

#ifndef _SYS_SOCKETVAR_H_
#define _SYS_SOCKETVAR_H_

/*
 * Socket generation count type.  Also used in xinpcb, xtcpcb, xunpcb.
 */
typedef uint64_t so_gen_t;

#if defined(_KERNEL) || defined(_WANT_SOCKET)
#include <sys/queue.h>			/* for TAILQ macros */
#include <sys/selinfo.h>		/* for struct selinfo */
#include <sys/_lock.h>
#include <sys/_mutex.h>
#include <sys/osd.h>
#include <sys/_sx.h>
#include <sys/sockbuf.h>
#ifdef _KERNEL
#include <sys/caprights.h>
#include <sys/sockopt.h>

#ifdef SOMIGRATION
#include <vm/uma.h>
#include <sys/taskqueue.h>
#endif

#endif

#ifdef SOMIGRATION

#ifndef SOMIG_MAXNODE
#define SOMIG_MAXNODE	    8	/* Maximum replica supports */
#endif


#define SOMIG_V_MAJOR	    1
#define SOMIG_V_MINOR	    0
#define SOMIG_V_FEATURE	    1

#define SOMIG_DUP_ALL	    0
#define SOMIG_DUP_INHERIT   1

#define SOMIG_ADDR_TUPLE_LOCAL 0
#define SOMIG_ADDR_TUPLE_FOREIGN 1

#define SOMIG_LISTEN_BACKLOG 5

#define SOMIG_WAITOK 0
#define SOMIG_NOWAIT 1

#define SOMIG_THROTTLE_COUNT 5

#endif	

struct vnet;

/*
 * Kernel structure per socket.
 * Contains send and receive buffer queues,
 * handle on protocol and pointer to protocol
 * private data and error information.
 */
typedef	int so_upcall_t(struct socket *, void *, int);
typedef	void so_dtor_t(struct socket *);

struct socket;

/*
 * SOMIG structs
 */
#ifdef SOMIGRATION
extern uma_zone_t somig_pkt_zone;

#define	SOMIG_SO_NULL		0
#define	SOMIG_SO_PENDING	1
#define	SOMIG_SO_CONNECTED	2
#define	SOMIG_SO_DISCONNECTED	3
#define	SOMIG_SO_FREEING	4

#define	SOMIG_CB_TCPCB		0
#define	SOMIG_CB_INPCB		1
#define	SOMIG_CB_CC		2

/*
 * SOMIG internal peer TAILQ entry
 */
#ifdef SOMIG_TIMING_DIAG_CLIENT
struct somig_timing_entry {
	uint32_t seq; 
	uint32_t len;
	uint32_t snd_ts;

	TAILQ_ENTRY(somig_timing_entry) list;
};
TAILQ_HEAD(somig_timing_queue, somig_timing_entry);
#endif
#if defined(SOMIG_TIMING_DIAG_CLIENT) || defined(SOMIG_TIMING_DIAG)
#define SOMIG_TIMING_BUCKET_COUNT   30
#define SOMIG_TIMING_BUCKET_INTERVAL   100
#endif

#ifdef SMCP
#define SMCP_FLAG_NORMAL    2
#define SMCP_FLAG_KILL	    254
#endif

struct somig_pkt_data_syn {
	struct mbuf *t_scm;
	int t_syncookies;
	int t_syncookiesonly;
	void *t_sc;
	void *t_sch;
	uint16_t t_fsc;
};

#define SOMIG_PKT_FLAG_SPLIT_M1			0x00000001
#define SOMIG_PKT_FLAG_SPLIT_M2			0x00000002

struct somig_pkt_entry {
	struct mbuf	*m;
	int		offp;
	uint32_t	gack;
	uint32_t	seq;
	uint32_t	ack;
	int		thflags;
	int		drop_hdrlen;
	int		tlen;
	int		sent;
	int		rexmt;  /* Need to re-feed into TCP stack, SOMIG level flag */
	int		flag;
	uint16_t	port;	/* Record port in tcp_input_with_port call */
	uint32_t	rej_count;  /* How many times this pkt gets rejected from stack */
	uint32_t	snd_ts; /* Debugging use: ts at sending */
	uint32_t	snd_off; /* PRI snd_off when receiving curr pkt */
	void		*th;
	void		*data;

	TAILQ_ENTRY(somig_pkt_entry) list;
};

TAILQ_HEAD(somig_pkt_queue, somig_pkt_entry);


/* Address Port are in NBO */
struct somig_peer_entry {
	uint8_t		id;
	uint8_t		role;
	uint8_t		state;
	uint32_t	ip;		/* Peer Ctl addr */
#ifndef SMCP
	uint16_t	port;
#endif
#ifdef SMCP
	void		*smcpcb;
	struct socket	*hso;
	uint32_t	p_addr;		/* JOIN queue use only */
	uint16_t	p_port;		/* JOIN queue use only */
#else
	struct socket	*so;
#endif

	TAILQ_ENTRY(somig_peer_entry) list;
};

TAILQ_HEAD(somig_peer_queue, somig_peer_entry);

#define		SOMIG_SEND_FLAG_REXMT	0x00000001

struct somig_task_entry {
	void		*ctl_blk;
	struct socket	*so;		/* HSO */
	struct mbuf	*m;
	struct task	task;
	struct somig_pkt_entry *spe;
	uint32_t flag;
	//struct timeout_task	task;

	TAILQ_ENTRY(somig_task_entry) list;
};

TAILQ_HEAD(somig_task_queue, somig_task_entry);

struct somig_func {
#ifdef SMCP
	int (*so_mig_connect)(void *, uint16_t v_major, 
	    uint16_t v_minor, uint32_t v_feature);
	int (*so_mig_sync)(void *);
	int (*so_mig_migrate)(void *, uint32_t flag, uint32_t who);
#else
	int (*so_mig_connect)(struct socket *, uint16_t v_major, 
	    uint16_t v_minor, uint32_t v_feature);
	int (*so_mig_sync)(struct socket *so);
	int (*so_mig_migrate)(struct socket *so, uint32_t flag, uint32_t who);
#endif
	int (*so_mig_join)(struct socket *head, struct socket *so, int role);
	int (*so_mig_disconnect)(struct socket *so);
	int (*so_mig_update_sooptions)(struct socket *so);
	int (*so_mig_get_addrtuple)(struct socket *so, struct sockaddr *sa, 
	    int which);
	void (*so_mig_flushpkt)(struct socket *so);
	void (*so_mig_taskqueue_thread)(void *s);
	void (*so_mig_getcb)(struct socket *so, void *buf, int buf_len, int who, int *len);
#ifdef SOMIG_FASTMIG
	void (*so_mig_if_down)(struct socket *so);
#endif
#ifdef SMCP
	int (*smcp_newcb)(void **, void *);
	int (*smcp_freecb)(void **);
	int (*smcp_bind)(void *, uint32_t, uint16_t, uint32_t, int);/* set id to 0 always*/
	int (*smcp_listen)(void *);
	void (*smcp_set_pentry)(void *, struct somig_peer_entry *);
	int (*smcp_get_state)(void *);
	void (*smcp_set_primary)(void *, uint32_t, uint16_t);
	uint32_t (*smcp_get_so_laddr)(void *);
	uint16_t (*smcp_get_so_lport)(void *);
	uint32_t (*smcp_get_so_faddr)(void *);
	uint16_t (*smcp_get_so_fport)(void *);
	void (*smcp_set_laddr)(void *, uint32_t);
	void (*smcp_set_faddr)(void *, uint32_t);
	void (*smcp_inherit)(void *, void *);
#endif
};

#endif


enum socket_qstate {
	SQ_NONE = 0,
	SQ_INCOMP = 0x0800,	/* on sol_incomp */
	SQ_COMP = 0x1000,	/* on sol_comp */
};

/*-
 * Locking key to struct socket:
 * (a) constant after allocation, no locking required.
 * (b) locked by SOCK_LOCK(so).
 * (cr) locked by SOCKBUF_LOCK(&so->so_rcv).
 * (cs) locked by SOCKBUF_LOCK(&so->so_snd).
 * (e) locked by SOLISTEN_LOCK() of corresponding listening socket.
 * (f) not locked since integer reads/writes are atomic.
 * (g) used only as a sleep/wakeup address, no value.
 * (h) locked by global mutex so_global_mtx.
 * (k) locked by KTLS workqueue mutex
 */
TAILQ_HEAD(accept_queue, socket);
struct socket {
	struct mtx	so_lock;
	volatile u_int	so_count;	/* (b / refcount) */
	struct selinfo	so_rdsel;	/* (b/cr) for so_rcv/so_comp */
	struct selinfo	so_wrsel;	/* (b/cs) for so_snd */
	short	so_type;		/* (a) generic type, see socket.h */
	int	so_options;		/* (b) from socket call, see socket.h */
	short	so_linger;		/* time to linger close(2) */
	short	so_state;		/* (b) internal state flags SS_* */
	void	*so_pcb;		/* protocol control block */
	struct	vnet *so_vnet;		/* (a) network stack instance */
	struct	protosw *so_proto;	/* (a) protocol handle */
	short	so_timeo;		/* (g) connection timeout */
	u_short	so_error;		/* (f) error affecting connection */
	u_short so_rerror;		/* (f) error affecting connection */
	struct	sigio *so_sigio;	/* [sg] information for async I/O or
					   out of band data (SIGURG) */
	struct	ucred *so_cred;		/* (a) user credentials */
	struct	label *so_label;	/* (b) MAC label for socket */
	/* NB: generation count must not be first. */
	so_gen_t so_gencnt;		/* (h) generation count */
	void	*so_emuldata;		/* (b) private data for emulators */
	so_dtor_t *so_dtor;		/* (b) optional destructor */
	struct	osd	osd;		/* Object Specific extensions */
	/*
	 * so_fibnum, so_user_cookie and friends can be used to attach
	 * some user-specified metadata to a socket, which then can be
	 * used by the kernel for various actions.
	 * so_user_cookie is used by ipfw/dummynet.
	 */
	int so_fibnum;		/* routing domain for this socket */
	uint32_t so_user_cookie;

	int so_ts_clock;	/* type of the clock used for timestamps */
	uint32_t so_max_pacing_rate;	/* (f) TX rate limit in bytes/s */
	union {
		/* Regular (data flow) socket. */
		struct {
			/* (cr, cs) Receive and send buffers. */
			struct sockbuf		so_rcv, so_snd;

			/* (e) Our place on accept queue. */
			TAILQ_ENTRY(socket)	so_list;
			struct socket		*so_listen;	/* (b) */
			enum socket_qstate so_qstate;		/* (b) */
			/* (b) cached MAC label for peer */
			struct	label		*so_peerlabel;
			u_long	so_oobmark;	/* chars to oob mark */

			/* (k) Our place on KTLS RX work queue. */
			STAILQ_ENTRY(socket)	so_ktls_rx_list;
		};
		/*
		 * Listening socket, where accepts occur, is so_listen in all
		 * subsidiary sockets.  If so_listen is NULL, socket is not
		 * related to an accept.  For a listening socket itself
		 * sol_incomp queues partially completed connections, while
		 * sol_comp is a queue of connections ready to be accepted.
		 * If a connection is aborted and it has so_listen set, then
		 * it has to be pulled out of either sol_incomp or sol_comp.
		 * We allow connections to queue up based on current queue
		 * lengths and limit on number of queued connections for this
		 * socket.
		 */
		struct {
			/* (e) queue of partial unaccepted connections */
			struct accept_queue	sol_incomp;
			/* (e) queue of complete unaccepted connections */
			struct accept_queue	sol_comp;
			u_int	sol_qlen;    /* (e) sol_comp length */
			u_int	sol_incqlen; /* (e) sol_incomp length */
			u_int	sol_qlimit;  /* (e) queue limit */

			/* accept_filter(9) optional data */
			struct	accept_filter	*sol_accept_filter;
			void	*sol_accept_filter_arg;	/* saved filter args */
			char	*sol_accept_filter_str;	/* saved user args */

			/* Optional upcall, for kernel socket. */
			so_upcall_t	*sol_upcall;	/* (e) */
			void		*sol_upcallarg;	/* (e) */

			/* Socket buffer parameters, to be copied to
			 * dataflow sockets, accepted from this one. */
			int		sol_sbrcv_lowat;
			int		sol_sbsnd_lowat;
			u_int		sol_sbrcv_hiwat;
			u_int		sol_sbsnd_hiwat;
			short		sol_sbrcv_flags;
			short		sol_sbsnd_flags;
			sbintime_t	sol_sbrcv_timeo;
			sbintime_t	sol_sbsnd_timeo;

			/* Information tracking listen queue overflows. */
			struct timeval	sol_lastover;	/* (e) */
			int		sol_overcount;	/* (e) */
		};
	};

	/*
	 * Do not change the first variable below
	 * uipc_socket.c: solisten_proto 
	 * will bzero all variables after so_rcv
	 * so_mig_id is used as the offset to prevent this.
	 *
	 */
#ifdef SOMIGRATION
		uint8_t				so_mig_id;
		uint8_t				so_mig_role;
		uint8_t				so_mig_virgin;
		char				so_mig_token[129];
		struct mtx			so_mig_lock;
		uint32_t			so_mig_state;

#ifdef SMCP
		void				*smcpcb;
		struct mtx			so_mig_delivery_lock;
#else
		struct socket			*so_mig_ctl;
#endif
		struct socket			*so_mig_hostso;
		struct socket			*so_mig_head;
		struct somig_peer_queue		so_mig_peer;
		struct somig_peer_queue		so_mig_join;
		/* Used on REPLICA to identify the packet source when output */
		struct somig_peer_entry		*so_mig_inputpeer;
		struct somig_peer_entry		*so_mig_pentry;
#ifdef SOMIG_TASKQUEUE
		/* Taskqueue for traffic duplication and broadcast */
		struct thread			*so_mig_task_thread;
		/* TailQ for storing any duplciation tasks used in taskqueue */
		struct somig_task_queue		so_mig_tasks;
		struct mtx			so_mig_task_lock;
		int				so_mig_task_done;
#endif
		/*
		 * Used only duing establishment. 
		 */
		int				so_mig_head_peer_size;
		/* 
		 * Counts only connected peers 
		 * Inc when new connection established on CTL chan
		 */
		int				so_mig_peer_size;
		/* 
		 * Counts all potential peers
		 * Bump up when new connection established on TCP 
		 */
		int				so_mig_total_size;
		int				so_mig_id_seed;
		int				so_mig_notifyfd;
		uint32_t			so_mig_gack_full;
		/* Address of PrimarySo (to client, in NBO) */
		uint32_t			so_mig_primary_addr;
		uint32_t			so_mig_local_ctl_addr;
		/* Mbuf stored for incoming segment */
		struct mbuf			*so_mig_pending_m;
		int				so_mig_pending_tlen;
		/* How many bytes consumed by the current pkt (RSO) */
		int				so_mig_pkt_consumption;
		/* Stored packets queue(for distributing to replicas */
		/* rwlock is used to make sure the exclusive write to pkt queue */
		struct mtx			so_mig_pktlock;
		struct somig_pkt_queue		so_mig_pkt;
		/* Total length buffered on pkt queue (RSO) */
		int				so_mig_pkt_buffered;
		/* Total length buffered on curr CtlSo (See tp->t_currctlso) */
		int				so_mig_pkt_buffered_cso;
		uint32_t			so_mig_unack;
		/* CPU ID used by upper layer ISR */
		int				so_mig_cli_cpu;
		int				so_mig_smg_cpu;
		/* stream id */
		int				so_mig_sid;
		/* host pid */
		int				so_mig_pid;

		/* PRIMARY only, throttle count */
		int				so_throttle;

		/* Last *UNSENT* packet ptr */
		struct somig_pkt_entry *	so_mig_pkt_unsnd;

		uint32_t			so_mig_pkt_counter;

		/*
		 * REPLICA only, rso wnd size
		 */
		int				so_mig_rsownd;
		/*
		 * SOMIG function call pointers
		 */
		struct somig_func		*so_mig_func;
#ifdef SOMIG_TIMING_DIAG
		/*
		 * Replication channel RTT diag toggle
		 */
		int				so_mig_timing_diag;
#endif
#endif

#ifdef SOMIG_TIMING_DIAG_CLIENT
	uint32_t timing_bucket[SOMIG_TIMING_BUCKET_COUNT + 1];
	struct somig_timing_queue	so_timing_queue;
#endif

};
#endif	/* defined(_KERNEL) || defined(_WANT_SOCKET) */

/*
 * Socket state bits.
 *
 * Historically, these bits were all kept in the so_state field.
 * They are now split into separate, lock-specific fields.
 * so_state maintains basic socket state protected by the socket lock.
 * so_qstate holds information about the socket accept queues.
 * Each socket buffer also has a state field holding information
 * relevant to that socket buffer (can't send, rcv).
 * Many fields will be read without locks to improve performance and avoid
 * lock order issues.  However, this approach must be used with caution.
 */
#define	SS_NOFDREF		0x0001	/* no file table ref any more */
#define	SS_ISCONNECTED		0x0002	/* socket connected to a peer */
#define	SS_ISCONNECTING		0x0004	/* in process of connecting to peer */
#define	SS_ISDISCONNECTING	0x0008	/* in process of disconnecting */
#define	SS_NBIO			0x0100	/* non-blocking ops */
#define	SS_ASYNC		0x0200	/* async i/o notify */
#define	SS_ISCONFIRMING		0x0400	/* deciding to accept connection req */
#define	SS_ISDISCONNECTED	0x2000	/* socket disconnected from peer */

#ifdef SOMIGRATION
#define	SMGS_INIT		0x0001
#define	SMGS_LISTEN		0x0002
#define	SMGS_SYNC		0x0004
#define	SMGS_CONNECTED		0x0008
#endif

/*
 * Protocols can mark a socket as SS_PROTOREF to indicate that, following
 * pru_detach, they still want the socket to persist, and will free it
 * themselves when they are done.  Protocols should only ever call sofree()
 * following setting this flag in pru_detach(), and never otherwise, as
 * sofree() bypasses socket reference counting.
 */
#define	SS_PROTOREF		0x4000	/* strong protocol reference */

#ifdef _KERNEL

#define	SOCK_MTX(so)		(&(so)->so_lock)
#define	SOCK_LOCK(so)		mtx_lock(&(so)->so_lock)
#define	SOCK_OWNED(so)		mtx_owned(&(so)->so_lock)
#define	SOCK_UNLOCK(so)		mtx_unlock(&(so)->so_lock)
#define	SOCK_LOCK_ASSERT(so)	mtx_assert(&(so)->so_lock, MA_OWNED)
#define	SOCK_UNLOCK_ASSERT(so)	mtx_assert(&(so)->so_lock, MA_NOTOWNED)

#ifdef SOMIGRATION

#define	SOMIG_MTX(so)		&(so)->so_mig_lock
#define	SOMIG_LOCK(so)		mtx_lock(&(so)->so_mig_lock)
#define	SOMIG_OWNED(so)		mtx_owned(&(so)->so_mig_lock)
#define	SOMIG_UNLOCK(so)	mtx_unlock(&(so)->so_mig_lock)
#define	SOMIG_LOCK_ASSERT(so)	mtx_assert(&(so)->so_mig_lock, MA_OWNED)
#define	SOMIG_UNLOCK_ASSERT(so)	mtx_assert(&(so)->so_mig_lock, MA_NOTOWNED)

#define	SOMIG_PKT_MTX(so)		&(so)->so_mig_pktlock
#define	SOMIG_PKT_LOCK(so)		mtx_lock(&(so)->so_mig_pktlock)
#define	SOMIG_PKT_OWNED(so)		mtx_owned(&(so)->so_mig_pktlock)
#define	SOMIG_PKT_UNLOCK(so)		mtx_unlock(&(so)->so_mig_pktlock)
#define	SOMIG_PKT_LOCK_ASSERT(so)	mtx_assert(&(so)->so_mig_pktlock, MA_OWNED)
#define	SOMIG_PKT_UNLOCK_ASSERT(so)	mtx_assert(&(so)->so_mig_pktlock, MA_NOTOWNED)

#ifdef SOMIG_TASKQUEUE
#define	SOMIG_TASK_MTX(so)		&(so)->so_mig_task_lock
#define	SOMIG_TASK_LOCK(so)		mtx_lock_spin(&(so)->so_mig_task_lock)
#define	SOMIG_TASK_OWNED(so)		mtx_owned(&(so)->so_mig_task_lock)
#define	SOMIG_TASK_UNLOCK(so)		mtx_unlock_spin(&(so)->so_mig_task_lock)
#define	SOMIG_TASK_LOCK_ASSERT(so)	mtx_assert(&(so)->so_mig_task_lock, MA_OWNED)
#define	SOMIG_TASK_UNLOCK_ASSERT(so)	mtx_assert(&(so)->so_mig_task_lock, MA_NOTOWNED)

#endif

#ifdef SMCP
#define	SOMIG_DELIVERY_OWNED(so)	mtx_owned(&(so)->so_mig_delivery_lock)
#define	SOMIG_DELIVERY_LOCK(so)		mtx_lock(&(so)->so_mig_delivery_lock)
#define	SOMIG_DELIVERY_UNLOCK(so)	mtx_unlock(&(so)->so_mig_delivery_lock)
#endif

#endif	/* SOMIGRATION */


#define	SOLISTENING(sol)	(((sol)->so_options & SO_ACCEPTCONN) != 0)
#define	SOLISTEN_LOCK(sol)	do {					\
	mtx_lock(&(sol)->so_lock);					\
	KASSERT(SOLISTENING(sol),					\
	    ("%s: %p not listening", __func__, (sol)));			\
} while (0)
#define	SOLISTEN_TRYLOCK(sol)	mtx_trylock(&(sol)->so_lock)
#define	SOLISTEN_UNLOCK(sol)	do {					\
	KASSERT(SOLISTENING(sol),					\
	    ("%s: %p not listening", __func__, (sol)));			\
	mtx_unlock(&(sol)->so_lock);					\
} while (0)
#define	SOLISTEN_LOCK_ASSERT(sol)	do {				\
	mtx_assert(&(sol)->so_lock, MA_OWNED);				\
	KASSERT(SOLISTENING(sol),					\
	    ("%s: %p not listening", __func__, (sol)));			\
} while (0)

/*
 * Macros for sockets and socket buffering.
 */

/*
 * Flags to soiolock().
 */
#define	SBL_WAIT	0x00000001	/* Wait if not immediately available. */
#define	SBL_NOINTR	0x00000002	/* Force non-interruptible sleep. */
#define	SBL_VALID	(SBL_WAIT | SBL_NOINTR)


#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? 0 : SBL_WAIT)

#define	SOCK_IO_SEND_LOCK(so, flags)					\
	soiolock((so), &(so)->so_snd.sb_sx, (flags))
#define	SOCK_IO_SEND_UNLOCK(so)						\
	soiounlock(&(so)->so_snd.sb_sx)
#define	SOCK_IO_RECV_LOCK(so, flags)					\
	soiolock((so), &(so)->so_rcv.sb_sx, (flags))
#define	SOCK_IO_RECV_UNLOCK(so)						\
	soiounlock(&(so)->so_rcv.sb_sx)

/*
 * Do we need to notify the other side when I/O is possible?
 */
#define	sb_notify(sb)	(((sb)->sb_flags & (SB_WAIT | SB_SEL | SB_ASYNC | \
    SB_UPCALL | SB_AIO | SB_KNOTE)) != 0)

/* do we have to send all at once on a socket? */
#define	sosendallatonce(so) \
    ((so)->so_proto->pr_flags & PR_ATOMIC)

/* can we read something from so? */
#define	soreadabledata(so) \
	(sbavail(&(so)->so_rcv) >= (so)->so_rcv.sb_lowat || \
	(so)->so_error || (so)->so_rerror)
#define	soreadable(so) \
	(soreadabledata(so) || ((so)->so_rcv.sb_state & SBS_CANTRCVMORE))

/* can we write something to so? */
#define	sowriteable(so) \
    ((sbspace(&(so)->so_snd) >= (so)->so_snd.sb_lowat && \
	(((so)->so_state&SS_ISCONNECTED) || \
	  ((so)->so_proto->pr_flags&PR_CONNREQUIRED)==0)) || \
     ((so)->so_snd.sb_state & SBS_CANTSENDMORE) || \
     (so)->so_error)

/*
 * soref()/sorele() ref-count the socket structure.
 * soref() may be called without owning socket lock, but in that case a
 * caller must own something that holds socket, and so_count must be not 0.
 * Note that you must still explicitly close the socket, but the last ref
 * count will free the structure.
 */
#define	soref(so)	refcount_acquire(&(so)->so_count)
#define	sorele(so) do {							\
	SOCK_LOCK_ASSERT(so);						\
	if (refcount_release(&(so)->so_count))				\
		sofree(so);						\
	else								\
		SOCK_UNLOCK(so);					\
} while (0)

/*
 * In sorwakeup() and sowwakeup(), acquire the socket buffer lock to
 * avoid a non-atomic test-and-wakeup.  However, sowakeup is
 * responsible for releasing the lock if it is called.  We unlock only
 * if we don't call into sowakeup.  If any code is introduced that
 * directly invokes the underlying sowakeup() primitives, it must
 * maintain the same semantics.
 */
#define	sorwakeup_locked(so) do {					\
	SOCKBUF_LOCK_ASSERT(&(so)->so_rcv);				\
	if (sb_notify(&(so)->so_rcv))					\
		sowakeup((so), &(so)->so_rcv);	 			\
	else								\
		SOCKBUF_UNLOCK(&(so)->so_rcv);				\
} while (0)

#define	sorwakeup(so) do {						\
	SOCKBUF_LOCK(&(so)->so_rcv);					\
	sorwakeup_locked(so);						\
} while (0)

#define	sowwakeup_locked(so) do {					\
	SOCKBUF_LOCK_ASSERT(&(so)->so_snd);				\
	if (sb_notify(&(so)->so_snd))					\
		sowakeup((so), &(so)->so_snd); 				\
	else								\
		SOCKBUF_UNLOCK(&(so)->so_snd);				\
} while (0)

#define	sowwakeup(so) do {						\
	SOCKBUF_LOCK(&(so)->so_snd);					\
	sowwakeup_locked(so);						\
} while (0)

struct accept_filter {
	char	accf_name[16];
	int	(*accf_callback)
		(struct socket *so, void *arg, int waitflag);
	void *	(*accf_create)
		(struct socket *so, char *arg);
	void	(*accf_destroy)
		(struct socket *so);
	SLIST_ENTRY(accept_filter) accf_next;
};

#define	ACCEPT_FILTER_DEFINE(modname, filtname, cb, create, destroy, ver) \
	static struct accept_filter modname##_filter = {		\
		.accf_name = filtname,					\
		.accf_callback = cb,					\
		.accf_create = create,					\
		.accf_destroy = destroy,				\
	};								\
	static moduledata_t modname##_mod = {				\
		.name = __XSTRING(modname),				\
		.evhand = accept_filt_generic_mod_event,		\
		.priv = &modname##_filter,				\
	};								\
	DECLARE_MODULE(modname, modname##_mod, SI_SUB_DRIVERS,		\
	    SI_ORDER_MIDDLE);						\
	MODULE_VERSION(modname, ver)

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_ACCF);
MALLOC_DECLARE(M_PCB);
MALLOC_DECLARE(M_SONAME);
#endif

/*
 * Socket specific helper hook point identifiers
 * Do not leave holes in the sequence, hook registration is a loop.
 */
#define HHOOK_SOCKET_OPT		0
#define HHOOK_SOCKET_CREATE		1
#define HHOOK_SOCKET_RCV 		2
#define HHOOK_SOCKET_SND		3
#define HHOOK_FILT_SOREAD		4
#define HHOOK_FILT_SOWRITE		5
#define HHOOK_SOCKET_CLOSE		6
#define HHOOK_SOCKET_LAST		HHOOK_SOCKET_CLOSE

struct socket_hhook_data {
	struct socket	*so;
	struct mbuf	*m;
	void		*hctx;		/* hook point specific data*/
	int		status;
};

extern int	maxsockets;
extern u_long	sb_max;
extern so_gen_t so_gencnt;

struct file;
struct filecaps;
struct filedesc;
struct mbuf;
struct sockaddr;
struct ucred;
struct uio;

//#ifdef SOMIGRATION
struct somig_migopt;
//#endif

/* 'which' values for socket upcalls. */
#define	SO_RCV		1
#define	SO_SND		2

/* Return values for socket upcalls. */
#define	SU_OK		0
#define	SU_ISCONNECTED	1

/*
 * From uipc_socket and friends
 */
int	getsockaddr(struct sockaddr **namp, const struct sockaddr *uaddr,
	    size_t len);
int	getsock_cap(struct thread *td, int fd, cap_rights_t *rightsp,
	    struct file **fpp, u_int *fflagp, struct filecaps *havecaps);
void	soabort(struct socket *so);
int	soaccept(struct socket *so, struct sockaddr **nam);
void	soaio_enqueue(struct task *task);
void	soaio_rcv(void *context, int pending);
void	soaio_snd(void *context, int pending);
int	socheckuid(struct socket *so, uid_t uid);
int	sobind(struct socket *so, struct sockaddr *nam, struct thread *td);
int	sobindat(int fd, struct socket *so, struct sockaddr *nam,
	    struct thread *td);
int	soclose(struct socket *so);
#ifdef SOMIGRATION
int	somigclose(struct socket *so);
#endif
int	soconnect(struct socket *so, struct sockaddr *nam, struct thread *td);
int	soconnectat(int fd, struct socket *so, struct sockaddr *nam,
	    struct thread *td);
int	soconnect2(struct socket *so1, struct socket *so2);
int	socreate(int dom, struct socket **aso, int type, int proto,
	    struct ucred *cred, struct thread *td);
int	sodisconnect(struct socket *so);
void	sodtor_set(struct socket *, so_dtor_t *);
struct	sockaddr *sodupsockaddr(const struct sockaddr *sa, int mflags);
void	sofree(struct socket *so);
void	sohasoutofband(struct socket *so);
int	solisten(struct socket *so, int backlog, struct thread *td);
void	solisten_proto(struct socket *so, int backlog);
int	solisten_proto_check(struct socket *so);
int	solisten_dequeue(struct socket *, struct socket **, int);
struct socket *
	sonewconn(struct socket *head, int connstatus);
struct socket *
	sopeeloff(struct socket *);
int	sopoll(struct socket *so, int events, struct ucred *active_cred,
	    struct thread *td);
int	sopoll_generic(struct socket *so, int events,
	    struct ucred *active_cred, struct thread *td);
int	soreceive(struct socket *so, struct sockaddr **paddr, struct uio *uio,
	    struct mbuf **mp0, struct mbuf **controlp, int *flagsp);
int	soreceive_stream(struct socket *so, struct sockaddr **paddr,
	    struct uio *uio, struct mbuf **mp0, struct mbuf **controlp,
	    int *flagsp);
int	soreceive_dgram(struct socket *so, struct sockaddr **paddr,
	    struct uio *uio, struct mbuf **mp0, struct mbuf **controlp,
	    int *flagsp);
int	soreceive_generic(struct socket *so, struct sockaddr **paddr,
	    struct uio *uio, struct mbuf **mp0, struct mbuf **controlp,
	    int *flagsp);
int	soreserve(struct socket *so, u_long sndcc, u_long rcvcc);
void	sorflush(struct socket *so);
int	sosend(struct socket *so, struct sockaddr *addr, struct uio *uio,
	    struct mbuf *top, struct mbuf *control, int flags,
	    struct thread *td);
int	sosend_dgram(struct socket *so, struct sockaddr *addr,
	    struct uio *uio, struct mbuf *top, struct mbuf *control,
	    int flags, struct thread *td);
int	sosend_generic(struct socket *so, struct sockaddr *addr,
	    struct uio *uio, struct mbuf *top, struct mbuf *control,
	    int flags, struct thread *td);
int	soshutdown(struct socket *so, int how);
void	soupcall_clear(struct socket *, int);
void	soupcall_set(struct socket *, int, so_upcall_t, void *);
void	solisten_upcall_set(struct socket *, so_upcall_t, void *);
void	sowakeup(struct socket *so, struct sockbuf *sb);
void	sowakeup_aio(struct socket *so, struct sockbuf *sb);
void	solisten_wakeup(struct socket *);
int	selsocket(struct socket *so, int events, struct timeval *tv,
	    struct thread *td);
void	soisconnected(struct socket *so);
void	soisconnecting(struct socket *so);
void	soisdisconnected(struct socket *so);
void	soisdisconnecting(struct socket *so);
void	socantrcvmore(struct socket *so);
void	socantrcvmore_locked(struct socket *so);
void	socantsendmore(struct socket *so);
void	socantsendmore_locked(struct socket *so);
void	soroverflow(struct socket *so);
void	soroverflow_locked(struct socket *so);
int	soiolock(struct socket *so, struct sx *sx, int flags);
void	soiounlock(struct sx *sx);

/* somig */
#ifdef SOMIGRATION
#define SMGTPRT(so, ...) somig_timeprint(__func__, __LINE__, (so), __VA_ARGS__)
#ifdef SMCP
void	somig_create(void **, struct socket *hso);
#else
void	somig_create(struct socket **aso, struct socket *hso);
#endif
int	somig_connect(struct socket *so, struct sockaddr *sa, struct thread *td,
	    int wait);
int	somig_connect_tuple(struct socket *so, struct socket *hso, uint32_t ip, 
	    uint16_t port);

int	somig_close(struct somig_peer_entry *peer);

void	somig_disconn_hook(struct socket *so);

void	somig_ctlso_newconn_hook(struct socket *head);
int	somig_prso_newconn_hook(struct socket *head, struct socket *so, 
	    int which);

int	somig_init_replica(struct socket *so, struct thread *td);
int	somig_disconnect_replica(struct socket *so);

int	somig_add_peer_to_hostso(struct socket *hso, 
	    struct somig_peer_entry *peer, int replace);
int	somig_opcheck(struct socket *so, int op);

uint8_t	somig_alloc_id(struct socket *head);
void	somig_dup(struct socket *src, struct socket *dst, int mode);
void	somig_timeprint(const char * func, int line, void *id, ...);

#endif


/*
 * Accept filter functions (duh).
 */
int	accept_filt_add(struct accept_filter *filt);
int	accept_filt_del(char *name);
struct	accept_filter *accept_filt_get(char *name);
#ifdef ACCEPT_FILTER_MOD
#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_inet_accf);
#endif
int	accept_filt_generic_mod_event(module_t mod, int event, void *data);
#endif

#endif /* _KERNEL */

/*
 * Structure to export socket from kernel to utilities, via sysctl(3).
 */
struct xsocket {
	ksize_t		xso_len;	/* length of this structure */
	kvaddr_t	xso_so;		/* kernel address of struct socket */
	kvaddr_t	so_pcb;		/* kernel address of struct inpcb */
	uint64_t	so_oobmark;
	int64_t		so_spare64[8];
	int32_t		xso_protocol;
	int32_t		xso_family;
	uint32_t	so_qlen;
	uint32_t	so_incqlen;
	uint32_t	so_qlimit;
	pid_t		so_pgid;
	uid_t		so_uid;
	int32_t		so_spare32[8];
	int16_t		so_type;
	int16_t		so_options;
	int16_t		so_linger;
	int16_t		so_state;
	int16_t		so_timeo;
	uint16_t	so_error;
	struct xsockbuf {
		uint32_t	sb_cc;
		uint32_t	sb_hiwat;
		uint32_t	sb_mbcnt;
		uint32_t	sb_mcnt;
		uint32_t	sb_ccnt;
		uint32_t	sb_mbmax;
		int32_t		sb_lowat;
		int32_t		sb_timeo;
		int16_t		sb_flags;
	} so_rcv, so_snd;
};

#ifdef _KERNEL
void	sotoxsocket(struct socket *so, struct xsocket *xso);
void	sbtoxsockbuf(struct sockbuf *sb, struct xsockbuf *xsb);
#endif

/*
 * Socket buffer state bits.  Exported via libprocstat(3).
 */
#define	SBS_CANTSENDMORE	0x0010	/* can't send more data to peer */
#define	SBS_CANTRCVMORE		0x0020	/* can't receive more data from peer */
#define	SBS_RCVATMARK		0x0040	/* at mark on input */

#endif /* !_SYS_SOCKETVAR_H_ */
