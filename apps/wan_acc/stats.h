#ifndef STATS_H_
#define STATS_H_

void stats_init();
void somig_stat_get_mbuf_usage(uint64_t *mbuf_count, uint64_t *mbuf_9k_count);
void somig_stat_get_net_memory_usage(uint64_t *bt);
void	somig_stat_refresh_cpu_usage();
int	somig_stat_get_current_app_cpu();
void	somig_stat_get_cpu_usage(int *cli, int *smg);
void	somig_stat_get_app_cpu(int *app, struct rusage *rlast);

#endif


