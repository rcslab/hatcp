#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdalign.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread_np.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <netdb.h>
#include <vector>
#include <sstream>

#include "options.h"
#include "reqproc.h"
#include <const.h>
#include <util.h>
#ifdef SOMIGRATION
#include "netutils.h"
#endif

#include <unordered_map>

#include <msg.pb.h>

static constexpr int NEVENT = 2048;
static constexpr int SOCK_BACKLOG = 10000;
static constexpr int SINGLE_LEGACY = -1;
static constexpr int DEFAULT_PORT = 9898;

static std::vector<int> client_conns;

static std::unordered_map<std::string, std::string> mode_params;

struct alignas(CACHE_LINE_SIZE) cache_item {
	int val;
};
static_assert(sizeof(struct cache_item) == CACHE_LINE_SIZE, "cache_item not cache line sized");

struct conn_hint {
	req_proc * proc;
};

struct alignas(CACHE_LINE_SIZE) worker_thread {
	pthread_t thrd;
	int kqfd;
	long evcnt;
	int id;
};
static_assert(sizeof(struct worker_thread) == CACHE_LINE_SIZE, "worker_thread not cache line sized");

server_option options = {.threads = 1, 
						.skq = 0,
						.skq_flag = 0, 
						.cpu_affinity = 0,
						.skq_dump = 0,
						.verbose = 0,
						.kq_rtshare = 100,
						.kq_tfreq = 0,
						.failover_time = 0,
						.mode = WORKLOAD_TYPE::ECHO,
						.server_addr = NULL,
						.port = DEFAULT_PORT, 
						.somig_mode = 0,
						.num_mode_params = 0};

/* cpu assignment */
static int ncpu = 0;
static int cur = 0;

static void
conn_hint_destroy(struct conn_hint *hint)
{
	delete hint->proc;
	delete hint;
}

static void 
server_socket_prepare(std::vector<int> *socks, server_option * opt) 
{
	struct sockaddr_in server_addr;
	int status, fd = 0;
	const int enable = 1;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(options.port);
	if (opt->server_addr == NULL)
		server_addr.sin_addr.s_addr = INADDR_ANY;
	else
		server_addr.sin_addr.s_addr = inet_addr(opt->server_addr);

	for (int i = 0; i < 1; i++) {
		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fd < 0) {
			perror("server listen socket");
			exit(1);
		}
#ifdef SOMIGRATION
		if (opt->somig_mode == SOMIG_REPLICA)
			init_replica(fd, inet_addr(opt->server_addr), htons(opt->port),
			    inet_addr(opt->mso_addr), htons(opt->mso_port),
			    inet_addr(opt->rso_addr), htons(opt->rso_port));
#endif
				
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
			E("server listen setsockopt reuseaddr");
		}

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) < 0) {
			E("server listen setsockopt reuseport");
		}

		if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) < 0) {
			E("server listen setsockopt NODELAY");
		}

		status = ::bind(fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
		if (status < 0) {
			perror("server listen bind");
			exit(1);
		}

		status = listen(fd, SOCK_BACKLOG);
		if (status < 0) {
			perror("listen");
			exit(1);
		}

#ifdef SOMIGRATION
		if (opt->somig_mode == SOMIG_PRIMARY)  
			init_primary(fd, inet_addr(opt->server_addr), htons(opt->port),
			    inet_addr(opt->mso_addr), htons(opt->mso_port));
#endif
		socks->push_back(fd);
	}
}

static void
drop_conn(struct worker_thread *tinfo, struct kevent *kev)
{
	int status;
	int conn_fd = kev->ident;
	struct kevent ev;
	EV_SET(&ev, conn_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	
	status = kevent(tinfo->kqfd, &ev, 1, 0, 0, NULL);

	if (status < 0) {
		E("Failed to delete connection %d from kqueue\n", conn_fd);
	}

	client_conns.erase(std::remove(
	    client_conns.begin(), client_conns.end(), conn_fd), client_conns.end());
	close(conn_fd);

	conn_hint_destroy((struct conn_hint *)kev->udata);
}

static int
handle_event(struct worker_thread *tinfo, struct kevent* kev)
{
	int conn_fd;
	int status;
	struct conn_hint *hint;

	if (kev->filter != EVFILT_READ) {
		E("Unknown event filter %d\n", kev->filter);
	}

	conn_fd = kev->ident;
	hint = (struct conn_hint*)kev->udata;

	if (kev->flags & EV_EOF) {
		V("Thread %d, hint %p, connection %d dropped due to EOF. ERR: %d\n", tinfo->id, hint, conn_fd, kev->fflags);
		drop_conn(tinfo, kev);
		return ECONNRESET;
	}

	status = hint->proc->proc_req(conn_fd);

	if (status < 0) {
		W("Connection %d proc_req returned error %d\n", conn_fd, status);
		drop_conn(tinfo, kev);
		return status;
	}

	tinfo->evcnt++;
	return 0;
}

#ifdef SOMIGRATION
static int 
migration_event(std::vector<int> *socks)
{
	uint32_t flag;

	for (uint32_t i=0;i<client_conns.size();i++) {
		flag = 2;
		V("Migrating connection socks..\n");
		exit(flag);
		//somig_migrate(client_conns.at(i), 1, flag);
	}

	for (uint32_t i=0;i<socks->size();i++) {
		//flag = SOMIG_MIGRATION_FLAG_FAIL;
		V("Migrating listening socks..\n");
		flag = 2;
		if (i == socks->size() - 1) {
			flag |= 0x10000000;
		}
		exit(flag);
		//somig_migrate(socks->at(i), 1, flag);
	}
	return 0;
}
#endif

static void* 
work_thread(void *info) 
{
	struct worker_thread *tinfo = (struct worker_thread *)info;
	struct kevent kev[NEVENT];
	struct kevent skev[NEVENT];
	int skev_sz;
	int status;

	V("Thread %d started.\n", tinfo->id);
	
	skev_sz = 0;
	while (1) {
		status = kevent(tinfo->kqfd, skev, skev_sz, kev, NEVENT, NULL);

		if (status <= 0) {
			perror("Thread kevent");
			exit(1);
		}

		skev_sz = 0;
		for (int i = 0; i < status; i++) {
			if (handle_event(tinfo, &kev[i]) == 0) {
				if (options.skq && options.skq_flag == SINGLE_LEGACY) {
					EV_SET(&skev[skev_sz], (int)kev[i].ident, EVFILT_READ, EV_ENABLE, 0, 0, kev[i].udata);
					skev_sz++;
					V("Thread %d queued connection %d for EV_ENABLE\n", tinfo->id, (int)kev[i].ident);
				}
			}
		}
	}
}

void dump_options()
{
	std::stringstream ss;
	ss << "Configuration:\n"
	   << "        worker threads: " << options.threads << std::endl
	   << "        port: " << options.port << std::endl
	   << "        mode: " << options.mode << std::endl
	   << "        single KQ: " << options.skq << std::endl
	   << "        single KQ flags: " << options.skq_flag << std::endl
	   << "        single KQ dump:" << options.skq_dump << std::endl
	   << "        CPU affinity: " << options.cpu_affinity << std::endl
	   << "        verbose: " << options.verbose << std::endl
	   << "        kq_rtshare: " << options.kq_rtshare << std::endl
	   << "        kq_tfreq: " << options.kq_tfreq << std::endl
	   << "        priority client IPs (" << options.hpip.size() << "): " << std::endl;

	for(uint i = 0; i < options.hpip.size(); i++) {
		ss << "                " << options.hpip.at(i) << std::endl;
	}

	V("%s", ss.str().c_str());
}

static void
usage() 
{
	fprintf(stdout, "Usage:\n"
		   "    A: server addr\n"
		   "    p: server port\n" 
		   "    v: verbose mode\n"
		   "    a: affinitize worker threads\n"
		   "    m: use a single KQ (SKQ and legacy)\n"
		   "    d: SKQ dump interval (s)\n"
		   "    t: number of server threads\n"
		   "    h: show help\n"
		   "    H: client hostname\n"
#ifdef SOMIGRATION
		   "    s: somig mode: mso - Primary, rso - Replica, none(default)\n"
		   "    P: mso address\n"
		   "    C: mso control port\n"
		   "    R: rso address\n"
		   "    r: rso port\n"
		   "    f: failover time\n"
#endif
		   "    F: kqueue frequency\n"
		   "    M: server mode: 0 - ECHO, 1 - TOUCH\n"
		   "    O: mode specific parameters in the format \"key=value\"\n"
		   "    Workload specific parameters:\n"
	       "       TOUCH:\n"
		   "       ENTRIES - Number of cache-aligned entries per connection.\n\n");
}

static int
get_ncpu()
{
    int mib[4];
    int numcpu;
    size_t len = sizeof(numcpu);

    mib[0] = CTL_HW;
    mib[1] = HW_NCPU;

    sysctl(mib, 2, &numcpu, &len, NULL, 0);

    if (numcpu < 1)
    {
        E("< 1 cpu detected\n");
        exit(1);
    }

    return numcpu;
}

/* pin to non-hyperthreads then to hyperthreads*/
static int 
get_next_cpu()
{
    int ret;

    if (ncpu == 0) {
        ncpu = get_ncpu();
    }

    if (ncpu == 1) {
        return 0;
    }
    
    if(cur >= ncpu) {
        cur = cur % ncpu;
    }
    
    ret = cur;
    cur = cur + 2;

    return ret;
}


static void
create_workers(int kq, std::vector<struct worker_thread*> *thrds)
{
	int status;

	/* Start threads */
	for (int i = 0; i < options.threads; i++) {
		V("Creating worker thread %d...\n", i);

		struct worker_thread *thrd = (struct worker_thread *)aligned_alloc(CACHE_LINE_SIZE, sizeof(struct worker_thread));
		thrd->evcnt = 0;
		thrd->id = i;
		
		if (!options.skq) {
			kq = kqueue();
			if (kq <= 0) {
				E("Cannot create kqueue\n");
			}

#ifdef FKQMULTI
			int para = KQTUNE_MAKE(KQTUNE_RTSHARE, options.kq_rtshare);
			status = ioctl(kq, FKQTUNE, &para);
			if (status == -1) {
				E("rtshare ioctl failed. ERR %d\n", errno);
			}
			
			para = KQTUNE_MAKE(KQTUNE_FREQ, options.kq_tfreq);
			status = ioctl(kq, FKQTUNE, &para);
			if (status == -1) {
				E("freq ioctl failed. ERR %d\n", errno);
			}
#endif

			V("Thread %d KQ created. RTSHARE %d TFREQ %d\n", i, options.kq_rtshare, options.kq_tfreq);
		}

		thrd->kqfd = kq;

		pthread_attr_t  attr;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, 1024 * 1024);

		if (options.cpu_affinity) {
			int tgt;
			cpuset_t cpuset;

			tgt = get_next_cpu();
	
			V("Setting worker thread's affinity to CPU %d %d\n", tgt, tgt + 1);

			CPU_ZERO(&cpuset);
			CPU_SET(tgt, &cpuset);
			CPU_SET(tgt + 1, &cpuset);

			status = pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset);

			if (status != 0) {
					E("Can't set affinity: %d\n", status);
			}
		}
		
		status = pthread_create(&thrd->thrd, &attr, work_thread, thrd);

		thrds->push_back(thrd);
	}
}

static void
get_ip_from_hostname(const char* hostname, char* buf, int len) 
{
  struct in_addr **addr;
  struct hostent *he;

  if ((he = gethostbyname(hostname)) == NULL) {
    fprintf(stderr, "Hostname %s cannot be resolved.\n", hostname);
    exit(1);
  }
  addr = (struct in_addr**)he->h_addr_list;
  for (int i=0;addr[i]!=NULL;i++) {
    strncpy(buf, inet_ntoa(*addr[i]), len);
    break;
  }
}

void parse_mode_params()
{
	char * saveptr;

	for (int i = 0; i < options.num_mode_params; i++) {
		saveptr = NULL;
		char *key = strtok_r(options.mode_params[i], "=", &saveptr);
  		char *val = strtok_r(NULL, "=", &saveptr);
		
		mode_params.insert({key, val});

		V("Parsed workload parameter: %s = %s\n", key, val);
	}
}
/*
 * Creates a worker thread.
 */
int 
main(int argc, char *argv[]) 
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;

	int kq = -1;
	int status;
	char ch;
	std::vector<struct worker_thread *> wrk_thrds;
    std::vector<int> server_socks;

#ifdef FKQMULTI
	char dbuf[1024 * 1024 + 1];
#endif
	
	while ((ch = getopt(argc, argv, "A:d:p:at:m:vhH:F:M:O:s:P:C:R:r:f:")) != -1) {
		switch (ch) {
			case 'A':
				options.server_addr = optarg;
				break;
			case 'd':
				options.skq_dump = atoi(optarg);
				break;
			case 'p':
				options.port = atoi(optarg);
				break;
			case 'a':
				options.cpu_affinity = 1;
				break;
			case 't':
				options.threads = atoi(optarg);
				break;
			case 'm':
				options.skq = 1;
				options.skq_flag = atoi(optarg);
				break;
			case 'O': {
				strncpy(options.mode_params[options.num_mode_params], optarg, MAX_MODE_PARAMS_LEN);
				options.num_mode_params++;
				break;
			}
			case 'M':
				options.mode = atoi(optarg);
				break;
			case 'v':
				options.verbose = 1;
				W("Verbose mode can cause SUBSTANTIAL latency fluctuations in some terminals!\n");
				break;
			case 'H': {
				char* eip = new char[INET_ADDRSTRLEN + 1];
				get_ip_from_hostname(optarg, eip, INET_ADDRSTRLEN);
				options.hpip.push_back(eip);
				break;
			}
#ifdef SOMIGRATION
			case 's':
				if (strcmp("mso", optarg) == 0) {
					options.somig_mode = 3;
				} else if (strcmp("rso", optarg) == 0) {
					options.somig_mode = 1;
				} else {
					options.somig_mode = 0;
				}
				break;
			case 'P':
				options.mso_addr = optarg;
				break;
			case 'C':
				options.mso_port = atoi(optarg);
				break;
			case 'R':
				options.rso_addr = optarg;
				break;
			case 'r':
				options.rso_port = atoi(optarg);
				break;
			case 'F':
				options.kq_tfreq = atoi(optarg);
				break;
			case 'f':
				options.failover_time = atoi(optarg);
				break;
#endif
			case 'h':
			case '?':
				usage();
				exit(0);
			default:
				E("Unrecognized option -%c. See -h.\n\n", ch);
		}
	}

	dump_options();

	// don't raise SIGPIPE when sending into broken TCP connections
	::signal(SIGPIPE, SIG_IGN); 

	parse_mode_params();

	/*
	 * Initializing stats (cpu, mbuf) we might use later, not really somig
	 */
#ifdef SOMIGRATION
	V("PPD with SOMIG support.\n");
#endif

	V("Setting up listen sockets...\n");

	server_socket_prepare(&server_socks, &options);

	int mkqfd = kqueue();
	struct kevent kev;

	for(uint32_t i = 0; i < server_socks.size(); i++) {
		EV_SET(&kev, server_socks.at(i), EVFILT_READ, EV_ADD, 0, 0, NULL);

		status = kevent(mkqfd, &kev, 1, NULL, 0, NULL);
		if (status == -1) {
			E("Kevent failed %d\n", errno);
		}
	}

#define TIMER_FD (-1234)
	EV_SET(&kev, TIMER_FD, EVFILT_TIMER, EV_ADD, NOTE_MSECONDS, 1, NULL);
	status = kevent(mkqfd, &kev, 1, NULL, 0, NULL);
	if (status == -1) {
		E("Kevent failed %d\n", errno);
	}

#ifdef SOMIGRATION
#define SOMIG_FO_FD (-5678)
	if (options.failover_time > 0) {
		EV_SET(&kev, SOMIG_FO_FD, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, options.failover_time, NULL);
		status = kevent(mkqfd, &kev, 1, NULL, 0, NULL);
		if (status == -1) {
			E("Failover Kevent failed %d\n", errno);
		}
	}
#endif

	if (options.skq) {
		kq = kqueue();

		if (kq <= 0) {
			E("Failed to create kqueue. ERR %d\n", errno);
		}

#ifdef FKQMULTI
		if (options.skq_flag != SINGLE_LEGACY) {
			status = ioctl(kq, FKQMULTI, &options.skq_flag);
			if (status == -1) {
				E("ioctl failed. ERR %d\n", errno);
			}
			V("SKQ enabled. SFLAG %d\n", options.skq_flag);
		}

		int para = KQTUNE_MAKE(KQTUNE_RTSHARE, options.kq_rtshare);
		status = ioctl(kq, FKQTUNE, &para);
		if (status == -1) {
			E("rtshare ioctl failed. ERR %d\n", errno);
		}

		para = KQTUNE_MAKE(KQTUNE_FREQ, options.kq_tfreq);
		status = ioctl(kq, FKQTUNE, &para);
		if (status == -1) {
			E("freq ioctl failed. ERR %d\n", errno);
		}
		V("KQ IOCTL: RTSHARE %d TFREQ %d\n", options.kq_rtshare, options.kq_tfreq);
#else 
		/* legacy single KQ only supports flag -1 */
		options.skq_flag = SINGLE_LEGACY;
#endif
	}

	srand(time(NULL));
	create_workers(kq, &wrk_thrds);
	V("Entering main event loop...\n");
	int cur_thread = 0;
	long cur_ts = 0;
	while (1) {
		if (kevent(mkqfd, NULL, 0, &kev, 1, NULL) != 1) {
			E("Accept loop kevent failed %d\n", errno);
		}

		if (kev.ident == (uintptr_t)TIMER_FD) {
#ifdef FKQMULTI
			/* timer event */
			if (options.skq_dump > 0 && cur_ts % (options.skq_dump * 1000) == 0) {
				uintptr_t args = (uintptr_t)dbuf;
				memset(dbuf, 0, 1024 * 1024 + 1);
				status = ioctl(kq, FKQMPRNT, &args);
				if (status == -1) {
					E("SKQ dump failed %d\n", errno);
				} else {
					fprintf(stdout, "====== KQ DUMP ======\n%s\n", dbuf);
				}
			}
#endif
			cur_ts++;
			continue;
		}

#ifdef SOMIGRATION
		if (kev.ident == (uintptr_t)SOMIG_FO_FD) {
			migration_event(&server_socks);
		}
#endif

		struct sockaddr_in client_addr;
		socklen_t client_addr_size = sizeof(client_addr);

		int conn_fd = accept(kev.ident, (struct sockaddr*)&client_addr, &client_addr_size);

		if (conn_fd < 0) {
			W("Accept() failed on socket %d\n", (int)kev.ident);
			continue;
		}

		{
			const int enable = 1;
			if (setsockopt(conn_fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) < 0) {
				W("setsockopt() failed on socket %d\n", conn_fd);
				continue;
			}
		}

		char ipaddr[INET_ADDRSTRLEN + 1];
		strncpy(ipaddr, inet_ntoa(client_addr.sin_addr), INET_ADDRSTRLEN);
		ipaddr[INET_ADDRSTRLEN] = 0;

		V("Accepted new connection %d from %s\n", conn_fd, ipaddr);

		struct conn_hint *hint = new struct conn_hint;

		switch (options.mode) {
			case WORKLOAD_TYPE::ECHO:
				hint->proc = new echo_proc(&mode_params);
				break;
			case WORKLOAD_TYPE::TOUCH:
				hint->proc = new touch_proc(&mode_params);
				break;
			/*
			case WORKLOAD_TYPE::RDB:
				hint->proc = new rdb_proc(&mode_params);
				break;
			*/
			default:
				E("Unknown server mode %d", options.mode);
		}

		int target_kq = wrk_thrds.at(cur_thread)->kqfd;

		int ev_flags = EV_ADD;

#ifdef FKQMULTI
		for (uint32_t i = 0; i < options.hpip.size(); i++) {
			if (strcmp(ipaddr, options.hpip.at(i)) == 0) {
				V("Connection %d marked as realtime.\n", conn_fd);
				ev_flags |= EV_REALTIME;
			}
		}
#endif

		if (options.skq && options.skq_flag == SINGLE_LEGACY) {
			ev_flags |= EV_DISPATCH;
		}

		EV_SET(&kev, conn_fd, EVFILT_READ, ev_flags, 0, 0, hint);
		status = kevent(target_kq, &kev, 1, NULL, 0, NULL);

		if (status == -1) {
			E("Accept() kevent failed %d\n", errno);
		}

		client_conns.push_back(conn_fd);
		V("Connection %d assigned to thread %d\n", conn_fd, wrk_thrds.at(cur_thread)->id);
		cur_thread = (cur_thread + 1) % wrk_thrds.size();
	}
	
	google::protobuf::ShutdownProtobufLibrary();
	return 0;
}
