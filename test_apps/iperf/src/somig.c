#include "iperf_config.h"

#ifdef SOMIGRATION
/*
#ifndef SOMIGRATION
#define SOMIGRATION
#endif
*/

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <paths.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <limits.h>
#include <memstat.h>
#include <kvm.h>

#include "somig.h"
#include "net.h"

/* Per-cpu time states */
static long *pcpu_cp_time;
static long *pcpu_cp_old;
static long *pcpu_cp_diff;
static int *pcpu_cpu_states;
static long *times;
static int maxcpu;
static int maxid;
static int ncpus;
static unsigned long cpumask;
static int init = 0;

static uint64_t mbuf_init_count = 0;
static uint64_t mbuf_9k_init_count = 0;
static uint64_t net_mem_init_size = 0;
static long percentages(int cnt, int *out, long *new, long *old, long *diffs);

void
somig_init()
{
	int empty, i, j;
	size_t size;

	if (init != 0) 
		return;

	size = sizeof(maxcpu);
	if (sysctlbyname("kern.smp.maxcpus", &maxcpu, &size, NULL, 0) != 0) {
		printf("sysctlbyname kern.smp.maxcpus\n");
		exit(0);
	}

	times = calloc(maxcpu * CPUSTATES, sizeof(long));
	size = sizeof(long) * maxcpu * CPUSTATES;
	if (sysctlbyname("kern.cp_times", times, &size, NULL, 0) == -1) {
		printf("sysctlbyname kern.cp_times %d\n", errno);
		exit(0);
	}

	pcpu_cp_time = calloc(1, size);
	maxid = (size / CPUSTATES / sizeof(long)) - 1;
	for (i = 0; i <= maxid; i++) {
		empty = 1;
		for (j = 0; empty && j < CPUSTATES; j++) {
			if (times[i * CPUSTATES + j] != 0)
			empty = 0;
		}
		if (!empty) {
			cpumask |= (1ul << i);
			ncpus++;
		}
	}
	pcpu_cp_old = calloc(ncpus * CPUSTATES, sizeof(long));
	pcpu_cp_diff = calloc(ncpus * CPUSTATES, sizeof(long));
	pcpu_cpu_states = calloc(ncpus * CPUSTATES, sizeof(int));

	somig_stat_get_mbuf_usage(&mbuf_init_count, &mbuf_9k_init_count);
	somig_stat_get_net_memory_usage(&net_mem_init_size);
}

int
#ifdef SMCP
somig_init_primary(int fd, int domain, int proto, const char *mso, int ctl_port,
    const char *local, int port)
#else
somig_init_primary(int fd, int domain, int proto, const char *mso, int ctl_port)
#endif
{
	int rt = 0, opt;
	struct sockaddr_in address;

	if (fd <= 0) {
		return (-1);
	}

	if (domain != AF_INET || domain != PF_INET) {
		printf("Unsupported socket domain type %d\n", domain);
		//return (-1);
	}

	opt = SOMIG_PRIMARY;
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_ROLE, &opt, sizeof(opt))) {
		perror("setsockopt - role");
		return (-1);
	}

#ifdef SMCP
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(local); 
	address.sin_port = htons(port);

	if (setsockopt(fd, SOL_SOCKET, SO_MIG_PREBIND, 
		(struct sockaddr*)&address, sizeof(address))) {
		perror("setsockopt - somigpostbind");
		return (-1);
	}
#endif

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(mso);
	address.sin_port = htons(ctl_port);
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_BIND,
		(struct sockaddr *)&address, sizeof(address))) {
		perror("setsockopt - somigbind");
		return (-1);
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_LISTEN, &opt, sizeof(opt))) {
		perror("setsockopt - somiglisten");
		return (-1);
	}

	return (rt);
}


int 
#ifdef SMCP
somig_init_replica(int domain, int proto, const char *mso, const char *rso, 
    const char *local, int port)
#else
somig_init_replica(int domain, int proto, const char *mso, const char *rso, 
    int ctl_port)
#endif
{
	int fd, opt;
	struct sockaddr_in address;

	if (domain != AF_INET || domain != PF_INET) {
		printf("Unsupported socket domain type %d\n", domain);
		//return (-1);
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("Failed to create socket\n");
		return (-1);
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) { 
		perror("setsockopt"); 
		return (-1);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) { 
		perror("setsockopt"); 
		return (-1);
	}

	opt = SOMIG_REPLICA;
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_ROLE, &opt, sizeof(opt))) {
		perror("setsockopt - role"); 
		return (-1);
	}

#ifdef SMCP
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(local); 
	address.sin_port = htons(port);

	if (setsockopt(fd, SOL_SOCKET, SO_MIG_PREBIND, 
		(struct sockaddr*)&address, sizeof(address))) {
		perror("setsockopt - somigpostbind");
		return (-1);
	}
#endif

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(rso); 
#ifndef SMCP
	address.sin_port = htons(ctl_port);
#endif
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_BIND, 
		(struct sockaddr*)&address, sizeof(address))) {
		perror("setsockopt - somigbind");
		return (-1);
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_LISTEN, 
		(struct sockaddr*)&opt, sizeof(opt))) {
		perror("setsockopt - somiglisten");
		return (-1);
	}

	/* Connect to PRIMARY */
	address.sin_addr.s_addr = inet_addr(mso);
#ifndef SMCP
	address.sin_port = htons(ctl_port); 
#endif
	if (setsockopt(fd, SOL_SOCKET, SO_MIG_CONNECT, (struct sockaddr*)&address, 
		sizeof(address))) {
		perror("CTLSO connect");
		return (-1);
	}
	
	return (fd);
}

int 
somig_init_app_sock(int fd, const char *app_addr, int ctl_port)
{
	struct sockaddr_in address;

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(app_addr);
	address.sin_port = htons(ctl_port);

	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("socket(replica) bind");
		return (-1);
	}

	listen(fd, INT_MAX);
	return (0);
}

int
somig_migrate(int fd, int dest, int mode)
{
	struct somig_migopt opt;

	opt.node = dest;
	opt.flag = mode;

	if (setsockopt(fd, SOL_SOCKET, SO_MIG_MIGRATE, (char *)&opt, sizeof(opt))) {
		perror("SOMIG migration");
		return (-1);
	}

	return 0;
}

void 
somig_stat_get_mbuf_usage(uint64_t *mbuf_count, uint64_t *mbuf_9k_count)
{
	size_t size;
	uint64_t val = 0, val_9k = 0;
	struct memory_type_list *mtlp;
	struct memory_type *mtp;

	mtlp = memstat_mtl_alloc();
	if (mtlp == NULL)
		goto done;
	if (memstat_sysctl_uma(mtlp, 0) < 0) {
		printf("UMA sysctl\n");
		exit(0);
	}
	mtp = memstat_mtl_find(mtlp, ALLOCATOR_UMA, "mbuf");
	val = memstat_get_count(mtp);

	mtp = memstat_mtl_find(mtlp, ALLOCATOR_UMA, "mbuf_jumbo_9k");
	val_9k = memstat_get_count(mtp);
done:
	*mbuf_count = val - mbuf_init_count;
	*mbuf_9k_count = val_9k - mbuf_9k_init_count;
}

void
somig_stat_get_net_memory_usage(uint64_t *bt)
{
	uint64_t mbuf_bytes;
	uint64_t packet_count, packet_bytes, packet_free;
	uint64_t cluster_count, cluster_size;
	uint64_t tag_bytes;
	uint64_t jumbo9_count, jumbo9_size;
	struct memory_type_list *mtlp;
	struct memory_type *mtp;

	mtlp = memstat_mtl_alloc();
	if (mtlp == NULL)
		goto error;
	if (memstat_sysctl_uma(mtlp, 0) < 0) {
		printf("UMA sysctl\n");
		exit(0);
	}
	
	mtp = memstat_mtl_find(mtlp, ALLOCATOR_UMA, "mbuf");
	if (mtp) {
		mbuf_bytes = memstat_get_bytes(mtp);
	}
	
	mtp = memstat_mtl_find(mtlp, ALLOCATOR_UMA, "mbuf_packet");
	if (mtp) {
		packet_bytes = memstat_get_bytes(mtp);
		packet_count = memstat_get_count(mtp);
		packet_free = memstat_get_free(mtp);
	}
	
	mtp = memstat_mtl_find(mtlp, ALLOCATOR_UMA, "mbuf_cluster");
	if (mtp) {
		cluster_size = memstat_get_size(mtp);
		cluster_count = memstat_get_count(mtp);
	}

/*
	mtp = memstat_mtl_find(mtlp, ALLOCATOR_MALLOC, "mbuf_tag");
	if (mtp) {
		tag_bytes = memstat_get_bytes(mtp);
	}

	mtp = memstat_mtl_find(mtlp, ALLOCATOR_UMA, "mbuf_jumbo_9k");
	if (mtp) {
		jumbo9_count = memstat_get_count(mtp);
		jumbo9_size = memstat_get_size(mtp);
	}
*/
	*bt =
	    mbuf_bytes +			/* straight mbuf memory */
	    packet_bytes +			/* mbufs in packets */
	    (packet_count * cluster_size) +	/* clusters in packets */
	    /* other clusters */
	    ((cluster_count - packet_count - packet_free) * cluster_size);
	//+
	//    tag_bytes +
	//    (jumbo9_count * jumbo9_size) - net_mem_init_size;

	return;
error:
	*bt = 0;
}

void 
somig_stat_get_cpu_usage(int *cli, int *smg, int *iperf_cpuid, int *iperf)
{
	kvm_t *kd = NULL;
	struct kinfo_proc *pbase = NULL;
	int nproc;
	int cli_id, smg_id, iperf_id;
	int curproc;
	size_t size;
	int i, j, val;

	if (!(cli && smg))
		return;

	cli_id = *cli;
	smg_id = *smg;
	iperf_id = 0;
	*cli = 0;
	*smg = 0;
	*iperf = 0;

	kd = kvm_open(NULL, _PATH_DEVNULL, NULL, O_RDONLY, NULL);
	if (kd == NULL) {
		return;
	}

	pbase = kvm_getprocs(kd, KERN_PROC_PROC, 0, &nproc);
	if (pbase == NULL) {
		return;
	}

	for (i=0;i<nproc;i++) {
		curproc = pbase[i].ki_pid;
		if (curproc == *iperf_cpuid) {
			*iperf_cpuid = pbase[i].ki_oncpu;
			if (*iperf_cpuid == -1) 
				*iperf_cpuid = pbase[i].ki_lastcpu;
			iperf_id = *iperf_cpuid;
			break;
		}
	}
	
	kvm_close(kd);

	size = (maxid + 1) * CPUSTATES * sizeof(long);
	if (sysctlbyname("kern.cp_times", pcpu_cp_time, &size, NULL, 0) == -1) {
		printf("sysctlbyname kern.cp_times\n");
		exit(0);
	}

	/* convert cp_time counts to percentages */
	for (i = j = 0; i <= maxid; i++) {
		if ((cpumask & (1ul << i)) == 0)
			continue;
		percentages(CPUSTATES, &pcpu_cpu_states[j * CPUSTATES],
		    &pcpu_cp_time[j * CPUSTATES],
		    &pcpu_cp_old[j * CPUSTATES],
		    &pcpu_cp_diff[j * CPUSTATES]);
		j++;
	}

	*cli = *(pcpu_cpu_states + CPUSTATES * cli_id + CP_INTR);
	if (*cli > 1000) *cli = 1000;
	
	*smg = *(pcpu_cpu_states + CPUSTATES * smg_id + CP_INTR);
	if (*smg > 1000) *smg = 1000;

	*iperf = *(pcpu_cpu_states + CPUSTATES * iperf_id + CP_SYS);
	if (*iperf > 1000) *iperf = 1000;
}

static long
percentages(int cnt, int *out, long *new, long *old, long *diffs)
{
    int i;
    long change;
    long total_change;
    long *dp;
    long half_total;

    /* initialization */
    total_change = 0;
    dp = diffs;

    /* calculate changes for each state and the overall change */
    for (i = 0; i < cnt; i++)
    {
        if ((change = *new - *old) < 0)
        {
            /* this only happens when the counter wraps */
            change = (int)
                ((unsigned long)*new-(unsigned long)*old);
        }
        total_change += (*dp++ = change);
        *old++ = *new++;
    }

    /* avoid divide by zero potential */
    if (total_change == 0)
    {
        total_change = 1;
    }

    /* calculate percentages based on overall change, rounding up */
    half_total = total_change / 2l;

        for (i = 0; i < cnt; i++)
        {
                *out++ = (int)((*diffs++ * 1000 + half_total) / total_change);
        }

    /* return the total in case the caller wants to use it */
    return(total_change);
}


#endif
