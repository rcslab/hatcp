#ifndef __SOMIG_H
#define __SOMIG_H

void somig_init();
#ifdef SMCP
int somig_init_primary(int fd, int domain, int proto, const char *mso, 
	int ctl_port, const char *local, int port);
int somig_init_replica(int domain, int proto, const char *mso, const char *rso, 
	const char *local, int port);
#else
int somig_init_replica(int domain, int proto, const char *mso, const char *rso, 
	int ctl_port);
int somig_init_primary(int fd, int domain, int proto, const char *mso, 
	int ctl_port);
#endif

int somig_init_app_sock(int fd, const char *app_addr, int ctl_port);
int somig_migrate(int fd, int dest, int mode);
void somig_stat_get_cpu_usage(int*, int*, int*, int*);
void somig_stat_get_mbuf_usage(uint64_t *, uint64_t *);
void somig_stat_get_net_memory_usage(uint64_t *);

#endif /* __SOMIG_H */
