#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <signal.h>
#include <err.h>
#include <netdb.h>

#include <iostream>
#include <vector>
#include <thread>
#include <set>
#include <unordered_map>

#include <const.h>
#include <util.h>
#include "Generator.h"
#include "reqgen.h"
#include "options.h"

#define MSG_TEST_OK (0x1234)
#define MSG_TEST_START (0x2345)
#define MSG_TEST_STOP (0x3456)
#define MSG_TEST_QPS_ACK (0x4567)

using namespace std;

option options;

struct perf_counter {
	char pad1[64];
	int cnt; 
	char pad2[64];
};

static vector<struct perf_counter*> thrd_perf_counters;

/* client server stuff */
static vector<char *> client_ips;
static vector<int> client_fds;
static unordered_map<string, string> rgen_params;
static int master_fd = 0;

static int mt_kq; /* kq for the main thread. Has all connections and the clock timer */

static pthread_barrier_t prepare_barrier;
static pthread_barrier_t ok_barrier;

static pthread_mutex_t conn_mtx;

static const int depth_limit = 1;
static volatile uint64_t cur_time = 0;

struct datapt {
	uint64_t qps;
	uint64_t lat;
};

enum conn_state {
	STATE_LIMITING,
	STATE_WAITING,
	STATE_SENDING
};

struct kqconn {
	req_gen *rgen;
	Generator *gen;
	int conn_fd;
	int conn_id;
	int timer;
	int timer_expired;
	int kq;
	int depth;
	enum conn_state state;
	uint64_t next_send;
	uint64_t last_send;
	vector<struct kqconn*> *conns;
	vector<struct datapt*> *stats;
};

req_gen * create_rgen(WORKLOAD_TYPE type, const int conn_id, std::unordered_map<std::string, std::string> *args)
{
	switch (type) {
		case WORKLOAD_TYPE::ECHO :
			return new echo_gen(conn_id, args);
			break;
		case WORKLOAD_TYPE::TOUCH :
			return new touch_gen(conn_id, args);
			break;
#if 0
		case WORKLOAD_TYPE::HTTP :
			return new http_gen(conn_id, std::string(options.server_ip) + ":" + std::to_string(options.server_port) ,args);
			break;
		case WORKLOAD_TYPE::RDB :
			return new rdb_gen(conn_id, args);
			break;
#endif
		default:
			E("Unsupported workload type %d\n", type);
	}
}

void parse_rgen_params()
{
	char * saveptr;

	for (int i = 0; i < options.num_gen_params; i++) {
		saveptr = NULL;
		char *key = strtok_r(options.gen_params[i], "=", &saveptr);
  		char *val = strtok_r(NULL, "=", &saveptr);
		
		rgen_params.insert({key, val});

		V("Parsed workload parameter: %s = %s\n", key, val);
	}
}

void kqconn_cleanup(struct kqconn *conn)
{
	int status;
	struct kevent ev[2];
	int nev = 1;
	EV_SET(&ev[0], conn->conn_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	if (!conn->timer_expired) {
		EV_SET(&ev[1], conn->timer, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
		nev++;
	}
	
	status = kevent(conn->kq, ev, nev, NULL, 0, NULL);
	if (status == -1) {
		E("Error kevent kqconn_cleanup\n");
	}

	delete conn->rgen;
	delete conn->gen;
	delete conn;
}

void kqconn_state_machine(struct kqconn *conn)
{
	int64_t now;
	struct kevent ev;
	while(1) {
		switch (conn->state) {
			case STATE_WAITING: {
				now = conn->next_send - (int64_t)get_time_us();
				if (now > 0) {
					if (conn->timer_expired) {
						EV_SET(&ev, conn->timer, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_USECONDS, now, conn);
						if (kevent(conn->kq, &ev, 1, NULL, 0, NULL) == -1) {
							E("Error arming timer %d. ERR %d\n", conn->timer, errno);
						}
						conn->timer_expired = 0;
					}
					return;
				} else {
					conn->state = STATE_SENDING;
					break;
				}
			}

			case STATE_LIMITING:
				if (conn->depth >= depth_limit) {
					return;
				}
				conn->state = STATE_WAITING;
				break;

			case STATE_SENDING: {
				/* send one packet and transfer to wait state */
				if (conn->depth >= depth_limit) {
					conn->state = STATE_LIMITING;
					/* wait for the read to call us */
					break;
				} else {
					now = get_time_us();
					if (now < (int64_t)conn->next_send) {
						/* only STATE_WAITING transfers us to this state
						 * the above condition cannot be true
						 */
						E("Oscar fucked up\n");
					}

					conn->depth++;
					conn->next_send += (int)(conn->gen->generate() * 1000000.0);
					conn->last_send = now;
					conn->state = STATE_WAITING;

					if (conn->rgen->send_req(conn->conn_fd) < 0) {
						/* effectively skipping this packet */
						W("Cannot write to connection %d\n", conn->conn_fd);
					}

					break;
				}
			}

			default:
				E("Oscar fucked up hard\n");
		}
	}
}

void ev_loop(int id, struct kevent *ev, struct kqconn *conn)
{
	int status;

	if ((int)ev->ident == conn->conn_fd) {
		/* we got something to read */
		status = conn->rgen->read_resp(conn->conn_fd);
		if (status < 0) {
			E("Connection %d read_resp failed. ERR: %d\n", conn->conn_fd, errno);
		}

		conn->depth--;
		if (conn->depth < 0) {
			E("More recved packets than sent.\n");
		}
		
		if ((long)cur_time >= options.warmup) {
			thrd_perf_counters[id]->cnt++;
			if (!options.client_mode) {
				struct datapt* dat = new struct datapt;
				dat->qps = 0;
				dat->lat = get_time_us() - conn->last_send;
				conn->stats->push_back(dat);
				V("Conn %d: TS: %d LAT: %ld, QPS: %ld\n", conn->conn_fd, (int)cur_time, dat->lat, (long)dat->qps);
			}
		}

		kqconn_state_machine(conn);

	} else if ((int)ev->ident == conn->timer) {
		conn->timer_expired = 1;
		kqconn_state_machine(conn);
	} else {
		E("Oscar really fucked up hard\n");
	}
}

void 
worker_thread(int id, int notif_pipe, vector<struct datapt*> *data)
{
	int timer_start = -1;
	int conn_fd;
	struct sockaddr_in server_addr;
	vector<struct kqconn*> conns;
	struct kevent ev[2];
	int kq = kqueue();

	EV_SET(&ev[0], notif_pipe, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &ev[0], 1, NULL, 0, NULL) == -1) {
		E("conn fd event kq reg problem");
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(options.server_port);
	server_addr.sin_addr.s_addr = inet_addr(options.master_mode ? options.master_server_ip : options.server_ip);

	pthread_mutex_lock(&conn_mtx);
	// initialize all the connections
	for (int i = 0 ; i < options.client_conn; i++) {
		while (true) {
			int enable = 1;
			struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };

			conn_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (conn_fd == -1) {
				W("Error in creating socket, will retry.\n");
				continue;
			}
			if (setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
				E("setsockopt rcvtimeo");
			}	
			if (setsockopt(conn_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
				E("setsockopt reuseaddr");
			}
			if (setsockopt(conn_fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) < 0) {
				E("setsockopt reuseport");
			}
			if (setsockopt(conn_fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) < 0) {
				E("setsockopt() failed on socket %d\n", conn_fd);
			}
			if (connect(conn_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
				E("Connection %d connect() failed. Dropping. Err: %d\n", conn_fd, errno);
			}

			struct kqconn* conn = new struct kqconn;
			conn->conn_fd = conn_fd;
			conn->conn_id = options.global_conn_start_idx.fetch_add(1);
			conn->timer = timer_start--;
			conn->kq = kq;
			conn->depth = 0;
			conn->conns = &conns;
			conn->next_send = 0;
			conn->timer_expired = 0;
			conn->state = STATE_WAITING;
			conn->stats = data;
			conn->gen = createGenerator(options.generator_name);
			if (conn->gen == NULL) {
				E("Unknown generator \"%s\"\n", options.generator_name);
			}
			conn->gen->set_lambda((double)options.target_qps / (double)(options.client_thread_count * options.client_conn));
			conn->rgen = create_rgen(options.workload_type, conn->conn_id, &rgen_params);

			EV_SET(&ev[0], conn->conn_fd, EVFILT_READ, EV_ADD, 0, 0, conn);
			EV_SET(&ev[1], conn->timer, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_USECONDS, 0, conn);
			if (kevent(kq, ev, 2, NULL, 0, NULL) == -1) {
				E("conn fd event kq reg problem");
			}

			conns.push_back(conn);
			V("Established connection %d with global id %d\n", conn->conn_fd, conn->conn_id);
			usleep(200);
			break;
		}
	}
	pthread_mutex_unlock(&conn_mtx);

	V("Thread %d has established %ld connections.\n", id, conns.size());
	pthread_barrier_wait(&prepare_barrier);

	V("Thread %d waiting for START...\n", id);
	pthread_barrier_wait(&ok_barrier);

	V("Thread %d running...\n", id);
	/* send the initial packet now */
	for (uint32_t i = 0; i < conns.size(); i++) {
		conns.at(i)->next_send = get_time_us();
	}

	while(1) {
		struct kevent ev;
		if (kevent(kq, NULL, 0, &ev, 1, NULL) == 1) {
			struct kqconn *conn = (struct kqconn *)ev.udata;

			if (ev.flags & EV_EOF) {
				/* just error */
				E("Connection %d dropped due to EOF. ERR: %d\n", conn->conn_fd, ev.fflags);
				continue;
			}

			if ((int)ev.ident == notif_pipe) {
				char c;

				if (read(notif_pipe, &c, sizeof(c)) == -1)
					E("Error reading pipe. ERR %d\n", errno);

				if (c == 'e')
					break;
			}

			ev_loop(id, &ev, conn);
		} else {
			E("Thread %d kevent failed. ERR %d\n", id, errno);
		}
	}

	for (uint32_t i = 0; i < conns.size(); i++) {
		kqconn_cleanup(conns.at(i));
	}

	close(kq);

	V("Thread %d exiting...\n", id);
}

int
master_recv_qps()
{
	int qps = 0;
	int tot = 0;
	struct kevent kev;

	while(tot < options.client_num) {

		if (kevent(mt_kq, NULL, 0, &kev, 1, NULL) != 1) {
			E("Error recving qps. ERR %d\n", errno);
		}

		if (kev.flags & EV_EOF) {
			continue;
		}

		int msg;

		if (readbuf(kev.ident, &msg, sizeof(int)) == -1) {
			E("Failed to read from master_fd or message invalid. ERR %d\n", errno);
		}

		qps += msg;

		V("Received QPS %d from client %d\n", msg, (int)kev.ident);

		msg = MSG_TEST_QPS_ACK;
		if (writebuf(kev.ident, &msg, sizeof(int)) == -1) {
			E("Failed to send ACK to client %d. ERR %d\n", (int)kev.ident, errno);
		}

		V("Sent ACK to client %d\n", (int)kev.ident);
		tot++;
	}

	return qps;
}

int 
client_stop()
{
	int qps;
	int msg = MSG_TEST_STOP;
	int stop_cnt = 0;
	struct kevent kev;

	V("Sending clients STOP...\n");
	for (uint32_t i=0;i<client_fds.size();i++) {
		if (writebuf(client_fds[i], &msg, sizeof(msg)) < 0) {
			E("Failed to send client STOP. ERR %d\n", errno);
		}
	}

	V("Waiting for client QPS...\n");
	qps = master_recv_qps();

	V("Waiting for client connections to close.\n");
	while (stop_cnt < (int)client_fds.size()) {
		if (kevent(mt_kq, NULL, 0, &kev, 1, NULL) == -1) {
			E("Error waiting for clients to exit. ERR %d\n", errno);
		}

		if (kev.flags & EV_EOF) {
			V("Client %d disconnected.\n", (int)kev.ident);
			stop_cnt++;
			close(kev.ident);
		}
	}

	for (uint32_t i = 0; i < client_ips.size(); i++) {
		delete[] client_ips.at(i);
	}

	return qps;
}

static std::string 
get_ip_from_hostname(std::string hostname) 
{
  static char rt[100] = {0};
  struct in_addr **addr;
  struct hostent *he;

  if ((he = gethostbyname(hostname.c_str())) == NULL) {
    E("Hostname %s cannot be resolved.\n", hostname.c_str());
  }
  addr = (struct in_addr**)he->h_addr_list;
  for (int i=0;addr[i]!=NULL;i++) {
    strncpy(rt, inet_ntoa(*addr[i]), 99);
    return rt;
  }
  return rt;
}

static void send_master_ok()
{
	struct kevent kev;
	int status;
	int msg = MSG_TEST_OK;
	status = writebuf(master_fd, &msg, sizeof(msg));

	if (status < 0) {
		E("Failed to respond OK to master. ERR %d\n", errno);
	}

	/* wait for START */
	status = kevent(mt_kq, NULL, 0, &kev, 1, NULL);

	if (status != 1) {
		E("Failed to wait for START. ERR %d\n", errno);
	}

	status = readbuf(master_fd, &msg, sizeof(msg));
	
	if (status == -1 || msg != MSG_TEST_START) {
		E("Failed to read START from master. ERR %d\n", errno);
	}
}

static void wait_clients_ok()
{
	set<int> acked;
	int status;
	int msg;
	struct kevent kev;

	/* wait for client OKs */
	while(acked.size() < client_fds.size()) {
		status = kevent(mt_kq, NULL, 0, &kev, 1, NULL);

		if (status != 1) {
			E("kevent wait for client ok %d\n", errno);
		}

		V("Received client ok from %d\n", (int)kev.ident);

		status = readbuf(kev.ident, &msg, sizeof(int));

		if (status < 0) {
			E("readbuf wait for client ok %d\n", errno);
		}

		if (msg != MSG_TEST_OK || acked.find(kev.ident) != acked.end()) {
			E("Duplicate or invalid client ok message\n");
		}

		acked.insert(kev.ident);
	}

	sleep(1);
	/* start all clients */
	msg = MSG_TEST_START;
	for (uint32_t i = 0; i < client_fds.size(); i++) {
		if(writebuf(client_fds.at(i), &msg, sizeof(int)) < 0) {
			E("Error sending START to client %d. ERR %d\n",client_fds.at(i) , errno);
		}
	}
}

static void prepare_clients()
{
	int real_conn = options.master_conn == -1 ? options.client_conn : options.master_conn;
	int real_thread = options.master_thread_count == -1 ? options.client_thread_count : options.master_thread_count;
	int real_qps;
	
	if (options.master_qps != -1) {
		real_qps = options.master_qps;
	} else {
		real_qps = options.target_qps * (real_conn * real_thread) / (real_conn * real_thread + options.client_num * options.client_conn * options.client_thread_count);
	}

	/* this is the qps for each client */
	options.target_qps = (options.target_qps - real_qps) / client_ips.size();

	struct kevent *kev = new struct kevent[client_ips.size()];

	/* create a connection to the clients */
	for (uint32_t i=0; i < client_ips.size(); i++) {
		struct sockaddr_in csock_addr;
		int c_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		csock_addr.sin_family = AF_INET;
		csock_addr.sin_addr.s_addr = inet_addr(client_ips[i]);
		csock_addr.sin_port = htons(DEFAULT_CLIENT_CTL_PORT);

		V("Connecting to client %s...\n", client_ips.at(i));

		if (connect(c_fd, (struct sockaddr*)&csock_addr, sizeof(csock_addr)) != 0) {
			E("Connect failed. ERR %d\n", errno);
		}

		if (writebuf(c_fd, &options, sizeof(options)) < 0) {
			E("Write to client. ERR %d\n", errno);
		}

		client_fds.push_back(c_fd);
		V("Client connected %d/%lu.\n", i + 1, client_ips.size());

		EV_SET(&kev[i], c_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		
		options.global_conn_start_idx += options.client_conn * options.client_thread_count;
	}

	V("Registering client fds to mtkq...\n");
	/* add to main thread's kq */
	if (kevent(mt_kq, kev, client_ips.size(), NULL, 0, NULL) == -1) {
		E("Failed to add some clients to mtkq. ERR %d\n", errno);
	}

	delete[] kev;

	/* adjust the existing settings */
	options.client_conn = real_conn;
	options.client_thread_count = real_thread;
	options.target_qps = real_qps;
}

static void client_send_qps(int qps)
{
	struct kevent kev;
	int msg = 0;

	/* clients need to send qps */
	V("Sending master QPS %d\n", qps);
	if (writebuf(master_fd, &qps, sizeof(int)) < 0) {
		E("Error writing QPS to master\n");
	}

	V("Waiting for master ACK...\n");

	if (kevent(mt_kq, NULL, 0, &kev, 1, NULL) != 1) {
		E("kevent wait for master ack %d\n", errno);
	}

	if (readbuf((int)kev.ident, &msg, sizeof(int)) < 0) {
		E("Failed to receive ack from master\n");
	}

	if (msg != MSG_TEST_QPS_ACK) {
		E("Invalid ack message\n");
	}
}

static void wait_master_prepare()
{
	V("Waiting for master's PREPARE...\n");

	struct sockaddr_in csock_addr;
	int listen_fd;
	int enable = 1;
	csock_addr.sin_family = AF_INET;
	csock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	csock_addr.sin_port = htons(DEFAULT_CLIENT_CTL_PORT);
	listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (listen_fd < 0) {
		E("socket");
	}

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
		E("setsockopt reuseaddr");
	}
	
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) < 0) {
		E("setsockopt reuseport");
	}

	if (::bind(listen_fd, (struct sockaddr*)&csock_addr, sizeof(csock_addr)) < 0) {
		E("bind");
	}

	if (listen(listen_fd, 10) < 0) {
		E("ctl listen");
	}

	master_fd = accept(listen_fd, NULL, NULL);
	if (master_fd == -1) {
		E("Failed to accept master. ERR %d\n", errno);
	}

	close(listen_fd);

	if (readbuf(master_fd, &options, sizeof(options)) < 0) {
		E("Failed to receive options from master. ERR %d\n", errno);
	}

	V("Registering master fd to mtkq...\n");
	struct kevent kev;

	EV_SET(&kev, master_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(mt_kq, &kev, 1, NULL, 0, NULL) == -1) {
		E("Failed to register master fd to mtkq. ERR %d\n", errno);
	}

	/* set the correct mode */
	options.master_mode = 0;
	options.client_mode = 1;
	options.output_name = NULL;
}

static void usage() 
{
	fprintf(stdout, "Usage:\n"
					"    -s: server addr.\n"
					"    -p: server port.\n"
					"    -q: target qps.\n"
					"    -t: threads per client.\n"
					"    -c: connections per thread.\n"
					"    -o: test output file name.\n"
					"    -h: show help.\n"
					"    -v: verbose mode.\n"
					"    -W: warm up time.\n"
					"    -w: test duration.\n"
					"    -i: interarrival distribution. Default fb_ia. See mutilate.\n"
					"    -l: workload type. ECHO(0), TOUCH(1). Default 0.\n"
					"    -O: workload specific parameters. Format: param=value. E.g. -Otsala=patis.\n\n"
					"Master mode:\n"
					"    -a: client addr.\n"
					"    -A: client mode.\n"
					"    -C: master connections.\n"
					"    -Q: master qps.\n"
					"    -T: master threads.\n" 
					"    -S: master mode server ip.\n\n"
					"Workload specific parameters:\n"
					"    ECHO:\n"
					"        GEN: the generator for request delay. Default fixed:0.\n"
					"        CDELAY: enable per-connection delay. Default 0.\n"
					"    TOUCH:\n"
					"        GEN: the generator for items touched per request. Default fixed:64.\n"
					"        UPDATE: the update ratio of request. Default 0.\n"
					"\n");
}

/*
 * protocol:
 * 
 * master -> client options
 * client and master all establish connections to the server
 * client -> master OK
 * master -> client START (client runs forever)
 * master RUNS for X seconds
 * master -> client STOP
 */
int
main(int argc, char* argv[]) 
{
	int ch;
	FILE *resp_fp_csv;

	while ((ch = getopt(argc, argv, "q:s:C:p:o:t:c:hvW:w:T:Aa:Q:i:S:l:O:")) != -1) {
		switch (ch) {
			case 'q':
				options.target_qps = atoi(optarg);
				if (options.target_qps < 0) {
					E("Target QPS must be positive\n");
				}
				break;
			case 'Q':
				options.master_qps = atoi(optarg);
				if (options.master_qps < 0) {
					E("Master QPS must be positive\n");
				}
				break;
			case 's': {
				string ip = get_ip_from_hostname(optarg);
				strncpy(options.server_ip, ip.c_str(), INET_ADDRSTRLEN);
				break;
			}
			case 'p':
				options.server_port = atoi(optarg);
				if (options.server_port <= 0) {
					E("Server port must be positive\n");
				}
				break;
			case 'o':
				options.output_name = optarg;
				break;
			case 't':
				options.client_thread_count = atoi(optarg);
				if (options.client_thread_count <= 0) {
					E("Client threads must be positive\n");
				}
				break;
			case 'T':
				options.master_thread_count = atoi(optarg);
				if (options.master_thread_count <= 0) {
					E("Master threads must be positive\n");
				}
				break;
			case 'c':
				options.client_conn = atoi(optarg);
				if (options.client_conn <= 0) {
					E("Client connections must be positive\n");
				}
				break;
			case 'l': {
				options.workload_type = static_cast<WORKLOAD_TYPE>(atoi(optarg));
				break;
			}
			case 'C':
				options.master_conn = atoi(optarg);
				if (options.master_conn <= 0) {
					E("Master connections must be positive\n");
				}
				break;
			case 'S': {
				string ip = get_ip_from_hostname(optarg);
				options.master_server_ip_given = 1;
				strncpy(options.master_server_ip, ip.c_str(), INET_ADDRSTRLEN);
				break;
			}
			case 'O': {
				strncpy(options.gen_params[options.num_gen_params], optarg, MAX_GEN_PARAMS_LEN);
				options.num_gen_params++;
				break;
			}
			case 'h':
			case '?':
				usage();
				exit(0);
			case 'v':
				options.verbose = 1;
				W("Verbose mode can cause SUBSTANTIAL latency fluctuations in some(XFCE) terminals!\n");
				break;
			case 'a': {
				if (options.client_mode == 1) {
					E("Cannot be both master and client\n");
				}
				string ip = get_ip_from_hostname(optarg);
				char *rip = new char[INET_ADDRSTRLEN + 1];
				strncpy(rip, ip.c_str(), INET_ADDRSTRLEN);
				client_ips.push_back(rip);
				options.master_mode = 1;
				break;
			}
			case 'W':
				options.warmup = atoi(optarg);
				if (options.warmup < 0) {
					E("Warmup must be positive\n");
				}
				break;
			case 'w':
				options.duration = atoi(optarg);
				if (options.duration <= 0) {
					E("Test duration must be positive\n");
				}
				break;
			case 'A': {
				if (options.master_mode == 1) {
					E("Cannot be both master and client\n");
				}
				options.client_mode = 1;
				break;
			}
			case 'i': {
				strncpy(options.generator_name, optarg, MAX_GEN_LEN);
				break;
			}
			default:
				E("Unrecognized option -%c\n\n", ch);
		}
	}

	::signal(SIGPIPE, SIG_IGN);

	if (!options.client_mode) {
		resp_fp_csv = fopen(options.output_name, "w");
		if (resp_fp_csv == NULL) {
			E("cannot open file for writing %s.", options.output_name);
			exit(1);
		}
	}

	if (options.master_mode && options.master_server_ip_given == 0) {
		/* fall back to ip from -s */
		strncpy(options.master_server_ip, options.server_ip, INET_ADDRSTRLEN);
	}

	options.client_num = client_ips.size();

	mt_kq = kqueue();

	/* connect to clients and sync options */
	if (options.master_mode) {
		/* make master connections to clients */
		prepare_clients();
	} else if (options.client_mode) {
		/* in client mode we receive all parameters from the server */
		wait_master_prepare();
	}

	/* here EVERYONE is on the same page */
	options.dump();
	parse_rgen_params();

	vector<std::thread> threads;
	vector<int> send_pipes;
	vector<int> recv_pipes;
	send_pipes.resize(options.client_thread_count);
	recv_pipes.resize(options.client_thread_count);

	/* do our setup according to the options */
	pthread_barrier_init(&prepare_barrier, NULL, options.client_thread_count + 1);
	pthread_barrier_init(&ok_barrier, NULL, options.client_thread_count + 1);

	pthread_mutex_init(&conn_mtx, NULL);

	V("Creating %d threads...\n", options.client_thread_count);

	/* create worker threads */
    vector<struct datapt *> *data = new vector<struct datapt*>[options.client_thread_count];
	for (int i = 0; i < options.client_thread_count; i++) {
		int pipes[2];
		if (pipe(&pipes[0]) == -1) {
			E("Cannot create pipes. ERR %d\n", errno);
		}

		struct perf_counter *perf = new struct perf_counter;
		perf->cnt = 0;
		send_pipes[i] = pipes[0];
		recv_pipes[i] = pipes[1];
	
		thrd_perf_counters.push_back(perf);
		threads.push_back(std::thread(worker_thread, i, pipes[1], &data[i]));
	}

	V("Waiting for thread connection establishment.\n");
	pthread_barrier_wait(&prepare_barrier);

	if (options.master_mode) {
		V("Waiting for clients...\n");
		/* wait for ok messages from the clients */
		wait_clients_ok();
	} else if (options.client_mode) {
		V("Sending OK to master...\n");
		/* send ok messages to the master */
		send_master_ok();
	}


	/* create main thread timer loop */
	struct kevent kev;
#define TIMER_FD (-1)
	EV_SET(&kev, TIMER_FD, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, 1, NULL);

	if (kevent(mt_kq, &kev, 1, NULL, 0, NULL) == -1) {
		E("Cannot create kevent timer. ERR %d\n", errno);
	}

	/* kick off worker threads */
	pthread_barrier_wait(&ok_barrier);
	/* now we are free to start the experiment */
	V("Main thread running.\n");

	while(1) {
		/* client mode runs forever unless server sends us */
		if ((int)cur_time >= options.duration + options.warmup && !options.client_mode) {
			break;
		}

		if (kevent(mt_kq, NULL, 0, &kev, 1, NULL) != 1) {
			E("Error in main event loop. ERR %d\n", errno);
		}

		if ((int)kev.ident == TIMER_FD) {
			cur_time++;
		} else {
			/* its from either master or client */
			if (kev.flags & EV_EOF) {
				E("Client or master %d disconnected\n", (int)kev.ident);
			}

			int msg;

			if (readbuf(kev.ident, &msg, sizeof(msg)) == -1)
				E("Failed to read from master_fd or message invalid. ERR %d\n", errno);

			if (msg == MSG_TEST_STOP) {
				V("Received STOP from master\n");
				break;
			} else {
				E("Unexpected message from master: %d\n", msg);
			}
		}
	}

	int qps = 0;

	for(int i = 0; i < options.client_thread_count; i++) {
		qps += thrd_perf_counters[i]->cnt;
	}
	V("Local QPS: %d\n", qps);

	if (options.client_mode) {
		client_send_qps(qps);
		close(master_fd);
	}

	V("Signaling threads to exit...\n");
	for (int i = 0; i < options.client_thread_count; i++) {
		if (write(send_pipes[i], "e", sizeof(char)) == -1) {
			E("Couldn't write to thread pipe %d. ERR %d\n", send_pipes[i], errno);
		}
	}

	for (int i = 0; i < options.client_thread_count; i++) {
		threads.at(i).join();
		delete thrd_perf_counters[i];
		close(send_pipes[i]);
		close(recv_pipes[i]);
	}

	if (options.master_mode) {
		V("Shutting down clients...\n");
		qps += client_stop();
	}

	V("Aggregated %d operations over %d seconds\n", qps, options.duration);
	qps = qps / (options.duration);

	if (!options.client_mode) {
		/* stop the measurement */
		V("Saving results...\n");
		for (int i = 0; i < options.client_thread_count; i++) {
			for (uint32_t j = 0; j < data[i].size(); j++) {
				struct datapt *pt = data[i].at(j);
				fprintf(resp_fp_csv, "%d %ld\n", qps, pt->lat);
				delete pt;
			}
		}
		
		delete[] data;

		fclose(resp_fp_csv);
	}

	close(mt_kq);
	
	return 0;
}
