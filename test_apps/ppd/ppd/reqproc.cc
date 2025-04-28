#include "reqproc.h"
#include <arpa/inet.h>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <random>
#include <stdint.h>
#include <sstream>
#include <sys/endian.h>
#include <sys/param.h>
#include <chrono>
#include <unistd.h>
#include "options.h"
#if 0
#include "rocksdb/cache.h"
#include "rocksdb/status.h"

#include <rocksdb/cache.h>
#include <rocksdb/db.h>
#include <rocksdb/env.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>
#include <rocksdb/perf_context.h>
#include <rocksdb/persistent_cache.h>
#include <rocksdb/rate_limiter.h>
#include <rocksdb/slice.h>
#include <rocksdb/slice_transform.h>
#include <rocksdb/stats_history.h>
#include <rocksdb/utilities/object_registry.h>
#include <rocksdb/utilities/optimistic_transaction_db.h>
#include <rocksdb/utilities/options_util.h>
#include <rocksdb/utilities/sim_cache.h>
#include <rocksdb/utilities/transaction.h>
#include <rocksdb/utilities/transaction_db.h>
#include <rocksdb/write_batch.h>
#include <rocksdb/table.h>
#endif

#include <msg.pb.h>
#include <util.h>
#include <const.h>

////////////////
// TOUCH Generator 
////////////////
touch_proc::touch_proc(std::unordered_map<std::string, std::string>* args) : req_proc()
{
	if (args->find(PARAM_TBSZ) != args->end()) {
		this->buffer_sz = atoi(args->at(PARAM_TBSZ).c_str());
	} else {
		this->buffer_sz = PARAM_TBSZ_DEFAULT;
	}
	
	V("Allocating %d items x %d CASZ for connnection\n", this->buffer_sz, CACHE_LINE_SIZE);
	this->buffer = (struct ppd_touch_cache_item *)aligned_alloc(CACHE_LINE_SIZE, this->buffer_sz * sizeof(struct ppd_touch_cache_item));

	this->rgen = new std::default_random_engine();
	this->rdist = new std::uniform_int_distribution<int>(0, INT32_MAX);
}

touch_proc::~touch_proc()
{
	delete this->buffer;
	delete this->rgen;
	delete this->rdist;
}

int touch_proc::proc_req(int fd)
{
	int sum;
	ppd_touch_req req;
	ppd_touch_resp resp;
	struct ppd_msg *msg = (struct ppd_msg *)this->read_buf;

	int ret = readmsg(fd, this->read_buf, this->MAX_READ_BUF_SIZE);

	if (ret < 0) {
		W("Readmsg failed with %d for connection %d\n", ret, fd);
		return ret;
	}

	if (!req.ParseFromArray(msg->payload, msg->size)) {
		W("ParseFromArray failed for connection %d\n", fd);
		return EINVAL; 
	}

	V("Conn %d touching %d items...\n", fd, req.touch_cnt());

	//int sum = 0;
	int rand = (*this->rdist)(*this->rgen);
	for(int64_t i = rand; i < rand + req.touch_cnt(); i++) {
		if (req.inc() > 0) {
			this->buffer[i % this->buffer_sz].val += 1;
		} else {
			/* only read */
			//sum += this->buffer[i % this->buffer_sz].val;
		}
	}

	resp.set_status(0);
	if (!resp.SerializeToArray(this->read_buf, MAX_READ_BUF_SIZE)) {
		W("Couldn't searialize to array connection %d\n", fd);
	}

	ret = writemsg(fd, this->read_buf, MAX_READ_BUF_SIZE, this->read_buf, resp.ByteSizeLong());
	if (ret < 0) {
		W("Writemsg failed with %d for connection %d\n", ret, fd);
	}

	return ret;
}

////////////////
// ECHO Generator
////////////////

echo_proc::echo_proc(std::unordered_map<std::string, std::string>*) : req_proc()
{
}

echo_proc::~echo_proc()
{
}

int echo_proc::proc_req(int fd) 
{
	uint64_t ms1, ms2;
	struct ppd_msg *msg = (struct ppd_msg *)this->read_buf;
	int ret = readmsg(fd, this->read_buf, MAX_READ_BUF_SIZE);

	if (ret < 0) {
		W("Readbuf failed with %d for connection %d\n", ret, fd);
		return ret;
	}

	ms1 = get_time_us();
	if (!req.ParseFromArray(msg->payload, msg->size)) {
		W("ParseFromArray failed for connection %d\n", fd);
		return EINVAL;
	}

	V("Connection %d delay %d us \n", fd, req.enable_delay());

	if (req.enable_delay() > 0) {
		uint64_t server_delay = req.enable_delay();
		uint64_t now = get_time_us();
		while (get_time_us() - now <= server_delay) {};
	}

	resp.set_status(0);
	if (!resp.SerializeToArray(this->read_buf, MAX_READ_BUF_SIZE)) {
		W("Couldn't searialize to array connection %d\n", fd);
	}
	ms2 = get_time_us();

	V("Serialization: TIME: %ld\n", ms2 - ms1);

	ret = writemsg(fd, this->read_buf, MAX_READ_BUF_SIZE, this->read_buf, resp.ByteSizeLong());
	if (ret < 0) {
		W("Writemsg failed with %d for connection %d\n", ret, fd);
	}

	return ret;
}


////////////////
// rdb Generator
////////////////
#if 0
rocksdb::DB * rdb_proc::db = nullptr;
std::atomic<int> rdb_proc::db_init {0};

rdb_proc::rdb_proc(std::unordered_map<std::string, std::string>* args) : req_proc()
{
	const char * db_path;
	int desired = 0;
	int target = 1;
	if (std::atomic_compare_exchange_strong(&rdb_proc::db_init, &desired, target)) {
		if (args->find(PARAM_PATH) != args->end()) {
			db_path = args->at(PARAM_PATH).c_str();
		} else {
			E("Must specify -OPATH for rocksdb.\n");
		}

		V("Initializing rocksdb, path: %s.\n", db_path);
		
		rocksdb::Options opt;
		std::shared_ptr<rocksdb::Cache> cache = rocksdb::NewLRUCache(CACHE_SIZE, 6, false, 0.0);
		opt.use_direct_io_for_flush_and_compaction = USE_DIRECT_IO_FOR_FLUSH_AND_COMPACTION;
		opt.use_direct_reads = USE_DIRECT_READS;

		rocksdb::BlockBasedTableOptions block_based_options;
		block_based_options.index_type = rocksdb::BlockBasedTableOptions::kBinarySearch;
		block_based_options.block_cache = cache;
		opt.table_factory.reset(rocksdb::NewBlockBasedTableFactory(block_based_options)); 

		opt.IncreaseParallelism(12);
		opt.OptimizeLevelStyleCompaction(1024 * 1024 * 1024);
		opt.OptimizeUniversalStyleCompaction(1024 * 1024 * 1024);
		opt.write_buffer_size = 1024 * 1024 * 1024;
		opt.create_if_missing = false;
		opt.compression = rocksdb::kNoCompression;


		rocksdb::Status s = rocksdb::DB::Open(opt, std::string(db_path), &this->db);
		if (!s.ok()) {
			E("Could not open rocksdb! Err %s\n", s.ToString().c_str()); 
		}

		rdb_proc::db_init.store(2);
		V("Finished initializing rocksdb.\n");
	} else {
		V("Checking for rocksdb initialization...\n");
		while(rdb_proc::db_init.load() != 2) {};
		V("Detected initialized rocksdb.\n");
	}
}

rdb_proc::~rdb_proc()
{
	
}

int rdb_proc::proc_req(int fd)
{
	ppd_rdb_resp resp;
	ppd_rdb_req req;
	rocksdb::Status s;
	struct ppd_msg *msg = (struct ppd_msg *)this->read_buf;

	int i = 0;
	int status = readmsg(fd, this->read_buf, MAX_READ_BUF_SIZE);

	if (status != 0) {
		W("Readmsg failed with %d for connection %d\n", status, fd);
		return status;
	}

	if (!req.ParseFromArray(msg->payload, msg->size)) {
		W("ParseFromArray failed for connection %d\n", fd);
		return EINVAL;
	}

	V("Connection %d op: %d, key: %s. val: %s. optarg: %d.\n", fd, req.op(), req.key().c_str(), req.val().c_str(), req.optarg());

	switch (req.op()) {
		case PPD_RDB_OP_PUT:{
			s = this->db->Put(rocksdb::WriteOptions(), req.key(), req.val());
			resp.set_status(s.code());
			break;
		}
		case PPD_RDB_OP_GET: {
			std::string val;
			s = this->db->Get(rocksdb::ReadOptions(), req.key(), &val);
			if (s.ok()) {
				resp.set_result(val);
			}
			resp.set_status(s.code());
			break;
		}
		case PPD_RDB_OP_SEEK: {
			rocksdb::Slice val;
			rocksdb::Iterator *it = this->db->NewIterator(rocksdb::ReadOptions(false, true));
			
			it->Seek(req.key());
			resp.set_status(it->status().code());

			if (it->Valid()) {
				val = it->value();
				resp.set_result(val.data(), val.size());
			}

			for(int64_t j = 0; j < req.optarg() && it->Valid(); j++) {
				rocksdb::Slice val = it->value();
				// do something about the key
				std::memcpy(this->read_buf, val.data(), MIN(val.size(), MAX_READ_BUF_SIZE));
				it->Next();
				if (!it->status().ok()) {
					resp.set_status(it->status().code());
					break;
				}
			}
			delete it;
			break;
		}
		default: {
			W("Invalid opcode %d for connection %d\n", req.op(), fd);
			return EINVAL;
		}
	}
	
	resp.set_status(0);

	status = writemsg(fd, this->read_buf, MAX_READ_BUF_SIZE, this->read_buf, resp.ByteSizeLong());
	if (status < 0) {
		W("Writemsg failed with %d for connection %d\n", status, fd);
	}

	
	return status;
}

#endif
