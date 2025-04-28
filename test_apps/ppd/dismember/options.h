#pragma once

#include <arpa/inet.h>
#include <string.h>
#include <atomic>

#include <const.h>
#include <util.h>

static constexpr const int MAX_GEN_LEN = 31;
static constexpr const int DEFAULT_SERVER_CLIENT_CONN_PORT = 9898;
static constexpr const int DEFAULT_CLIENT_CTL_PORT = 9901;
static constexpr const char* DEFAULT_OUTPUT = "output.sample";
static constexpr const int MAX_GEN_PARAMS = 8;
static constexpr const int MAX_GEN_PARAMS_LEN = 31;

struct option;

extern option options;

struct option {
	int verbose;

	enum WORKLOAD_TYPE workload_type;

	const char *output_name;

	int client_num;
	int client_thread_count;
	int master_thread_count;

	int client_conn;
	int master_conn;

	int target_qps;
	int master_qps;

	int master_mode;
	int client_mode;

	std::atomic_int global_conn_start_idx;

	char server_ip[INET_ADDRSTRLEN + 1];
	char generator_name[MAX_GEN_LEN + 1];

	char gen_params[MAX_GEN_PARAMS][MAX_GEN_PARAMS_LEN + 1];
	int num_gen_params;

	int master_server_ip_given;
	char master_server_ip[INET_ADDRSTRLEN + 1];
	int server_port;
	int depth_limit;

	int warmup;
	int duration;

	option()
	{
		this->verbose = 0;
		this->depth_limit = 1;
		this->output_name = DEFAULT_OUTPUT;
		this->client_thread_count = 1;
		this->master_thread_count = -1;
		this->client_conn = 1;
		this->master_conn = -1;
		this->target_qps = 0;
		this->master_qps = -1;
		this->client_mode = 0;
		this->master_mode = 0;
		this->warmup = 0;
		this->duration = 10;
		this->server_port = DEFAULT_SERVER_CLIENT_CONN_PORT;
		this->master_server_ip_given = 0;
		this->workload_type = WORKLOAD_TYPE::ECHO;
		this->num_gen_params = 0;
		this->global_conn_start_idx = 0;

		for(int i = 0; i < MAX_GEN_PARAMS; i++) {
			memset(gen_params[i], 0, MAX_GEN_LEN + 1);
		}

		/* set default values */
		strncpy(this->generator_name, "fb_ia" , MAX_GEN_LEN);
		strncpy(this->server_ip, "127.0.0.1" , INET_ADDRSTRLEN);
		strncpy(this->master_server_ip, "127.0.0.1", INET_ADDRSTRLEN);
	}
	
	void dump()
	{
		V ("Configuration:\n"
			"        Connections per thread: %d\n"
			"        Num threads: %d\n"
			"        Target QPS: %d\n"
			"        warmup: %d\n"
			"        duration: %d\n"
			"        master_mode: %d\n"
			"        client_mode: %d\n"
			"        output_file: %s\n"
			"        server_ip: %s\n"
			"        server_port: %d\n"
			"        IA_DIST: %s\n"
			"        master_server_ip: %s\n"
			"        workload_type: %d\n"
			"        num_workload_param: %d\n"
			"        global_conn_idx: %d\n",
			this->client_conn,
			this->client_thread_count,
			this->target_qps,
			this->warmup,
			this->duration,
			this->master_mode,
			this->client_mode,
			this->output_name,
			this->server_ip,
			this->server_port,
			this->generator_name,
			this->master_server_ip,
			this->workload_type,
			this->num_gen_params,
			this->global_conn_start_idx.load());
	}
};
/* Don't send god damn vtables */
static_assert(std::is_standard_layout<option>(), "struct option must be standard layout");
