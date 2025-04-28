#pragma once

//#include <rocksdb/db.h>
#include <cstdint>
#include <string>
#include <random>
#include <unordered_map>
#include <const.h>
#include <atomic>
#include <sys/param.h>

#include <msg.pb.h>

#define DISABLE_EVIL_CONSTRUCTORS(name) \
	name(const name&) = delete; \
	void operator=(const name) = delete

struct alignas(CACHE_LINE_SIZE) ppd_touch_cache_item {
	int val;
};

class req_proc {
	protected:
		constexpr static int MAX_READ_BUF_SIZE = 1024 * 1024;
		char * read_buf;
	public:
		req_proc() {this->read_buf = new char[MAX_READ_BUF_SIZE]; }; 
		virtual ~req_proc() {delete[] this->read_buf;};
		virtual int proc_req(int fd) = 0;
};

class touch_proc : public req_proc
{
	private:
		int buffer_sz;
		std::default_random_engine * rgen;
		std::uniform_int_distribution<int> * rdist;
		struct ppd_touch_cache_item* buffer;
		static constexpr const char* PARAM_TBSZ = "ENTRIES";
		static constexpr const int PARAM_TBSZ_DEFAULT = 64;
		constexpr static int MAX_SZ = 1024 * 1024;
	public:
		touch_proc(std::unordered_map<std::string, std::string>* args);
		touch_proc() = delete;
		~touch_proc();
		DISABLE_EVIL_CONSTRUCTORS(touch_proc);
		int proc_req(int fd);
};

class echo_proc : public req_proc
{
	private:
		ppd_echo_req req;
		ppd_echo_resp resp;
	public:
		echo_proc(std::unordered_map<std::string, std::string>* args);
		echo_proc() = delete;
		~echo_proc();
		DISABLE_EVIL_CONSTRUCTORS(echo_proc);
		int proc_req(int fd);
};
#if 0
class rdb_proc : public req_proc
{
	private:
		constexpr static bool USE_DIRECT_IO_FOR_FLUSH_AND_COMPACTION = true;
		constexpr static bool USE_DIRECT_READS = true;
		constexpr static int CACHE_SIZE = 268435456;
		constexpr static int MAX_MSG_SZ = 4096;
		static constexpr const char* PARAM_PATH = "PATH";
		static std::atomic<int> db_init;
		static rocksdb::DB *db;
	public:
		rdb_proc(std::unordered_map<std::string, std::string>* args);
		rdb_proc() = delete;
		~rdb_proc();
		DISABLE_EVIL_CONSTRUCTORS(rdb_proc);
		int proc_req(int fd);
};
#endif
