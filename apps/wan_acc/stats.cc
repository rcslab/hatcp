#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <paths.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <limits.h>
#include <memstat.h>
#include <kvm.h>

#include "stats.h" 


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
static long percentages(int cnt, int *out, long *ne, long *old, long *diffs);

void 
stats_init()
{
	int empty, i, j;
	size_t size;

	if (init != 0) 
		return;

	cpumask = 0;
	ncpus = 0;

	size = sizeof(maxcpu);
	if (sysctlbyname("kern.smp.maxcpus", &maxcpu, &size, NULL, 0) != 0) {
		printf("sysctlbyname kern.smp.maxcpus\n");
		exit(0);
	}

	times = (long *)calloc(maxcpu * CPUSTATES, sizeof(long));
	size = sizeof(long) * maxcpu * CPUSTATES;
	if (sysctlbyname("kern.cp_times", times, &size, NULL, 0) == -1) {
		printf("sysctlbyname kern.cp_times\n");
		exit(0);
	}

	pcpu_cp_time = (long *)calloc(1, size);
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
	pcpu_cp_old = (long *)calloc(ncpus * CPUSTATES, sizeof(long));
	pcpu_cp_diff = (long *)calloc(ncpus * CPUSTATES, sizeof(long));
	pcpu_cpu_states = (int *)calloc(ncpus * CPUSTATES, sizeof(int));

	somig_stat_get_mbuf_usage(&mbuf_init_count, &mbuf_9k_init_count);
	somig_stat_get_net_memory_usage(&net_mem_init_size);
}

void
somig_stat_get_mbuf_usage(uint64_t *mbuf_count, uint64_t *mbuf_9k_count)
{
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
	//printf("mbuf init %u, 9k: %u, count: %u, 9k: %u\n", mbuf_init_count, mbuf_9k_init_count, val, val_9k);
	if (val <= mbuf_init_count)
		*mbuf_count = 0;
	else
		*mbuf_count = val - mbuf_init_count;
	
	if (val_9k <= mbuf_9k_init_count)
		*mbuf_9k_count = 0;
	else
		*mbuf_9k_count = val_9k - mbuf_9k_init_count;
}

void
somig_stat_get_net_memory_usage(uint64_t *bt)
{
	uint64_t mbuf_bytes;
	uint64_t packet_count, packet_bytes, packet_free;
	uint64_t cluster_count, cluster_size;
	//uint64_t tag_bytes;
	//uint64_t jumbo9_count, jumbo9_size;
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
somig_stat_refresh_cpu_usage()
{
	size_t size;
	int i, j;

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
}

int
somig_stat_get_current_app_cpu()
{
	int my_pid;
	kvm_t *kd = NULL;
	struct kinfo_proc *pbase = NULL;
	int nproc, curproc;
	int my_cpu = -1;

	my_pid = getpid();

	kd = kvm_open(NULL, _PATH_DEVNULL, NULL, O_RDONLY, NULL);
	if (kd == NULL) {
		return (-1);
	}

	pbase = kvm_getprocs(kd, KERN_PROC_PROC, 0, &nproc);
	if (pbase == NULL) {
		return (-1);
	}

	for (int i=0;i<nproc;i++) {
		curproc = pbase[i].ki_pid;
		if (curproc == my_pid) {
			my_cpu = pbase[i].ki_oncpu;
			if (my_cpu == -1) 
				my_cpu = pbase[i].ki_lastcpu;
			break;
		}
	}
	kvm_close(kd);

	return (my_cpu);
}

static void
cpu_util(int *syscpu, int *usrcpu, struct rusage *rlast)
{
    clock_t ctemp;
    struct rusage rtemp;
    double timediff;
    double userdiff;
    double systemdiff;

    //iperf_time_now(&now);
    getrusage(RUSAGE_SELF, &rtemp);
 
    //iperf_time_diff(&now, &last, &temp_time);
    //timediff = iperf_time_in_usecs(&temp_time);
    timediff = 1 * 1000 * 1000;

    userdiff = ((rtemp.ru_utime.tv_sec * 1000000.0 + rtemp.ru_utime.tv_usec) -
                (rlast->ru_utime.tv_sec * 1000000.0 + rlast->ru_utime.tv_usec));
    systemdiff = ((rtemp.ru_stime.tv_sec * 1000000.0 + rtemp.ru_stime.tv_usec) -
                  (rlast->ru_stime.tv_sec * 1000000.0 + rlast->ru_stime.tv_usec));

    //pcpu[0] = (((ctemp - clast) * 1000000.0 / CLOCKS_PER_SEC) / 1) * 100;
    *usrcpu = (userdiff / timediff) * 100;
    *syscpu = (systemdiff / timediff) * 100;

    memcpy(rlast, &rtemp, sizeof(struct rusage));
}

void
somig_stat_get_app_cpu(int *app, struct rusage *rlast)
{
	int syscpu, usrcpu, total;

	if (!app)
		return;

	cpu_util(&syscpu, &usrcpu, rlast);
	total = (syscpu + usrcpu) * 10;
	//printf("app usage(avg) %d: sys %d usr %d, sum %d\n", total, syscpu, usrcpu, syscpu + usrcpu);

	*app = total;
}



void
somig_stat_get_cpu_usage(int *cli, int *smg)
{
	int cli_id, smg_id;

	if (!(cli && smg))
		return;

	cli_id = *cli;
	smg_id = *smg;

	*cli = *(pcpu_cpu_states + CPUSTATES * cli_id + CP_INTR);
	if (*cli > 1000) *cli = 1000;
	
	*smg = *(pcpu_cpu_states + CPUSTATES * smg_id + CP_INTR);
	if (*smg > 1000) *smg = 1000;

	/*
	if (app_id != -1) {
	    *app = *(pcpu_cpu_states + CPUSTATES * app_id + CP_SYS);
	    if (*app > 1000) *app = 1000;
	} else {
	    *app = -1;
	}
	*/
}

static long
percentages(int cnt, int *out, long *ne, long *old, long *diffs)
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
        if ((change = *ne - *old) < 0)
        {
            /* this only happens when the counter wraps */
            change = (int)
                ((unsigned long)*ne-(unsigned long)*old);
        }
        total_change += (*dp++ = change);
        *old++ = *ne++;
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



