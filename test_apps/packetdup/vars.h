#ifndef VARS_H_
#define VARS_H_



struct inpcb {
};

struct dummy_tseg_qent {
	//TAILQ_ENTRY(tseg_qent) tqe_q;
	void *a;
	void **b;

	void   *tqe_m;		/* mbuf contains packet */
	void   *tqe_last;	/* last mbuf in chain */
	uint32_t tqe_start;		/* TCP Sequence number start */
	int	tqe_len;		/* TCP segment data length */
	uint32_t tqe_flags;		/* The flags from the th->th_flags */
	uint32_t tqe_mbuf_cnt;		/* Count of mbuf overhead */
};

struct dummy_tsegqe_head {
	//struct dummy_tseg_qent *a;
	//struct dummy_tseg_qent *b;
	void *a;
	void *b;
}; 

struct dummy_sackblk {
	uint32_t start;		/* start seq no. of sack block */
	uint32_t end;		/* end seq no. */
};

struct dummy_sackhole {
	uint32_t start;		/* start seq no. of hole */
	uint32_t end;		/* end seq no. */
	uint32_t rxmit;		/* next seq. no in hole to be retransmitted */
	//TAILQ_ENTRY(sackhole) scblink;	/* scoreboard linkage */
	void *a;
	void **aa;
};

struct dummy_sackhint {
	struct dummy_sackhole	*nexthole;
	int32_t		sack_bytes_rexmit;
	uint32_t		last_sack_ack;	/* Most recent/largest sacked ack */

	int32_t		delivered_data; /* Newly acked data from last SACK */

	int32_t		sacked_bytes;	/* Total sacked bytes reported by the
					 * receiver via sack option
					 */
	uint32_t	recover_fs;	/* Flight Size at the start of Loss recovery */
	uint32_t	prr_delivered;	/* Total bytes delivered using PRR */
	uint32_t	prr_out;	/* Bytes sent during IN_RECOVERY */
};

#define	MAX_SACK_BLKS	6
#define TCP_FASTOPEN_MAX_COOKIE_LEN	16
#define TCP_END_BYTE_INFO 8

//tp size 720, snd_holes size 16, t_logs size 16
struct tcpcb {
	/* Cache line 1 */
	void *t_inpcb;		/* back pointer to internet pcb */
	void *t_fb;/* TCP function call block */
	void	*t_fb_ptr;		/* Pointer to t_fb specific data */
	uint32_t t_maxseg:24,		/* maximum segment size */
		t_logstate:8;		/* State of "black box" logging */
	uint32_t t_port:16,		/* Tunneling (over udp) port */
		t_state:4,		/* state of this connection */
		t_idle_reduce : 1,
		t_delayed_ack: 7,	/* Delayed ack variable */
		t_fin_is_rst: 1,	/* Are fin's treated as resets */
		t_log_state_set: 1,
		bits_spare : 2;
	u_int	t_flags;
	uint32_t snd_una;		/* sent but unacknowledged */
	uint32_t snd_max;		/* highest sequence number sent;
					 * used to recognize retransmits
					 */
	uint32_t snd_nxt;		/* send next */
	uint32_t	snd_up;			/* send urgent pointer */
	uint32_t  snd_wnd;		/* send window */
	uint32_t  snd_cwnd;		/* congestion-controlled window */
	uint32_t t_peakrate_thr; 	/* pre-calculated peak rate threshold */
	/* Cache line 2 */
	u_int32_t  ts_offset;		/* our timestamp offset */
	u_int32_t	rfbuf_ts;	/* recv buffer autoscaling timestamp */
	int	rcv_numsacks;		/* # distinct sack blks present */
	u_int	t_tsomax;		/* TSO total burst length limit in bytes */
	u_int	t_tsomaxsegcount;	/* TSO maximum segment count */
	u_int	t_tsomaxsegsize;	/* TSO maximum segment size in bytes */
	uint32_t	rcv_nxt;		/* receive next */
	uint32_t	rcv_adv;		/* advertised window */
	uint32_t  rcv_wnd;		/* receive window */
	u_int	t_flags2;		/* More tcpcb flags storage */
	int	t_srtt;			/* smoothed round-trip time */
	int	t_rttvar;		/* variance in round-trip time */
	u_int32_t  ts_recent;		/* timestamp echo data */
	u_char	snd_scale;		/* window scaling for send window */
	u_char	rcv_scale;		/* window scaling for recv window */
	u_char	snd_limited;		/* segments limited transmitted */
	u_char	request_r_scale;	/* pending window scaling */
	uint32_t	last_ack_sent;
	u_int	t_rcvtime;		/* inactivity time */
	/* Cache line 3 */
	uint32_t	rcv_up;			/* receive urgent pointer */
	int	t_segqlen;		/* segment reassembly queue length */
	uint32_t t_segqmbuflen;		/* Count of bytes mbufs on all entries */
	struct dummy_tsegqe_head t_segq;	/* segment reassembly queue */
	void      *t_in_pkt;
	void	 *t_tail_pkt;
	void *t_timers;	/* All the TCP timers in one struct */
	void *t_vnet;		/* back pointer to parent vnet */
	uint32_t  snd_ssthresh;		/* snd_cwnd size threshold for
					 * for slow start exponential to
					 * linear switch
					 */
	uint32_t	snd_wl1;		/* window update seg seq number */
	/* Cache line 4 */
	uint32_t	snd_wl2;		/* window update seg ack number */

	uint32_t	irs;			/* initial receive sequence number */
	uint32_t	iss;			/* initial send sequence number */
	u_int	t_acktime;		/* RACK and BBR incoming new data was acked */
	u_int	t_sndtime;		/* time last data was sent */
	u_int	ts_recent_age;		/* when last updated */
	uint32_t	snd_recover;		/* for use in NewReno Fast Recovery */
	uint16_t cl4_spare;		/* Spare to adjust CL 4 */
	char	t_oobflags;		/* have some */
	char	t_iobc;			/* input character */
	int	t_rxtcur;		/* current retransmit value (ticks) */

	int	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	u_int	t_rtttime;		/* RTT measurement start time */

	uint32_t	t_rtseq;		/* sequence number being timed */
	u_int	t_starttime;		/* time connection was established */
	u_int	t_fbyte_in;		/* ticks time when first byte queued in */
	u_int	t_fbyte_out;		/* ticks time when first byte queued out */

	u_int	t_pmtud_saved_maxseg;	/* pre-blackhole MSS */
	int	t_blackhole_enter;	/* when to enter blackhole detection */
	int	t_blackhole_exit;	/* when to exit blackhole detection */
	u_int	t_rttmin;		/* minimum rtt allowed */

	u_int	t_rttbest;		/* best rtt we've seen */

	int	t_softerror;		/* possible error not yet reported */
	uint32_t  max_sndwnd;		/* largest window peer has offered */
	/* Cache line 5 */
	uint32_t  snd_cwnd_prev;	/* cwnd prior to retransmit */
	uint32_t  snd_ssthresh_prev;	/* ssthresh prior to retransmit */
	uint32_t	snd_recover_prev;	/* snd_recover prior to retransmit */
	int	t_sndzerowin;		/* zero-window updates sent */
	u_long	t_rttupdated;		/* number of times rtt sampled */
	int	snd_numholes;		/* number of holes seen by sender */
	u_int	t_badrxtwin;		/* window for retransmit recovery */
	//TAILQ_HEAD(sackhole_head, sackhole) snd_holes;
	char dummy1[16];
					/* SACK scoreboard (sorted) */
	uint32_t	snd_fack;		/* last seq number(+1) sack'd by rcv'r*/
	struct dummy_sackblk sackblks[MAX_SACK_BLKS]; /* seq nos. of sack blocks */
	struct dummy_sackhint	sackhint;	/* SACK scoreboard hint */
	int	t_rttlow;		/* smallest observerved RTT */
	int	rfbuf_cnt;		/* recv buffer autoscaling byte count */
	void	*tod;		/* toedev handling this connection */
	int	t_sndrexmitpack;	/* retransmit packets sent */
	int	t_rcvoopack;		/* out-of-order packets received */
	void	*t_toe;			/* TOE pcb pointer */
	void	*cc_algo;	/* congestion control algorithm */
	void	*ccv;		/* congestion control specific vars */
	void	*osd;		/* storage for Khelp module data */
	int	t_bytes_acked;		/* # bytes acked during current RTT */
	u_int   t_maxunacktime;
	u_int	t_keepinit;		/* time to establish connection */
	u_int	t_keepidle;		/* time before keepalive probes begin */
	u_int	t_keepintvl;		/* interval between keepalives */
	u_int	t_keepcnt;		/* number of keepalives before close */
	int	t_dupacks;		/* consecutive dup acks recd */
	int	t_lognum;		/* Number of log entries */
	int	t_loglimit;		/* Maximum number of log entries */
	int64_t	t_pacing_rate;		/* bytes / sec, -1 => unlimited */
	//struct tcp_log_stailq t_logs;	/* Log buffer */
	char dummy2[16];
	void *t_lin;
	void *t_lib;
	void *t_output_caller;	/* Function that called tcp_output */
	void *t_stats;	/* Per-connection stats */
	uint32_t t_logsn;		/* Log "serial number" */
	uint32_t gput_ts;		/* Time goodput measurement started */
	uint32_t gput_seq;		/* Outbound measurement seq */
	uint32_t gput_ack;		/* Inbound measurement ack */
	int32_t t_stats_gput_prev;	/* XXXLAS: Prev gput measurement */
	uint32_t t_maxpeakrate;		/* max peak rate set by user, in bytes/s */
	uint32_t t_sndtlppack;		/* tail loss probe packets sent */
	uint64_t t_sndtlpbyte;		/* total tail loss probe bytes sent */
	uint64_t t_sndbytes;		/* total bytes sent */
	uint64_t t_snd_rxt_bytes;	/* total bytes retransmitted */

	uint8_t t_tfo_client_cookie_len; /* TCP Fast Open client cookie length */
	uint32_t t_end_info_status;	/* Status flag of end info */
	unsigned int *t_tfo_pending;	/* TCP Fast Open server pending counter */
	union {
		uint8_t client[TCP_FASTOPEN_MAX_COOKIE_LEN];
		uint64_t server;
	} t_tfo_cookie;			/* TCP Fast Open cookie to send */
	union {
		uint8_t t_end_info_bytes[TCP_END_BYTE_INFO];
		uint64_t t_end_info;
	};
};


#endif
