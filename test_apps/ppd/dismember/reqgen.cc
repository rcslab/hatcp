#include "google/protobuf/stubs/common.h"
#include "options.h"
#include <msg.pb.h>
#include <stdint.h>
#include <sstream>
#include <sys/_stdint.h>
#include <unistd.h>
#include <util.h>
//#include <rocksdb/db.h>

#include "reqgen.h"
////////////////
// TOUCH Generator
////////////////

touch_gen::touch_gen(const int conn_id, std::unordered_map<std::string, std::string>* args) : req_gen(conn_id)
{
    this->ugen = createGenerator("uniform:100");
	if (this->ugen == NULL) {
		E("Failed to create ugen for touch_gen\n");
	}

	if (args->find(PARAM_GEN) == args->end()) {
    	this->wgen = createGenerator(PARAM_GEN_DEFAULT);
	} else {
		this->wgen = createGenerator(args->at(PARAM_GEN));
	}

	if (this->wgen == NULL) {
		E("Failed to create wgen for touch_gen\n");
	}

	if (args->find(PARAM_UPDATE) == args->end()) {
		this->update_ratio = PARAM_UPDATE_DEFAULT;
	} else {
		this->update_ratio = atoi(args->at(PARAM_UPDATE).c_str());
	}
}

touch_gen::~touch_gen()
{
    delete wgen;
	delete ugen;
}

int touch_gen::send_req(int fd) 
{
	ppd_touch_req req;

	if (options.master_mode) {
		req.set_touch_cnt(0);
	} else {
		req.set_touch_cnt(this->wgen->generate());
	}

	if (this->ugen->generate() < this->update_ratio) {
		req.set_inc(1);
	} else {
		req.set_inc(0);
	}

	if (!req.SerializeToArray(this->send_buf, MAX_SEND_BUF_SIZE)) {
		E("Failed to serialize to array for fd %d", fd);
	}

	return writemsg(fd, this->send_buf, this->MAX_SEND_BUF_SIZE, this->send_buf, req.ByteSizeLong());
}

int touch_gen::read_resp(int fd)
{
    ppd_touch_resp resp;
	struct ppd_msg * msg = (struct ppd_msg *)this->send_buf;

    if (readmsg(fd, this->send_buf, MAX_SEND_BUF_SIZE) < 0) {
		E("Readbuf failed for fd %d\n", fd);
	}

	resp.ParseFromArray(msg->payload, msg->size);

    return resp.status();
}

////////////////
// ECHO Generator
////////////////
int echo_gen::delay_table[DT_SZ];
std::atomic<int> echo_gen::delay_table_populated = ATOMIC_VAR_INIT(0);

void
echo_gen::populate_delay_table()
{
	int idx = 0;
	int expected = 0;

	// hack
	if (echo_gen::DT_SZ != 100) {
		E("Delay table size isn't 100");
	}

	/* 95 + 4 + 1 = 100 */
	if (!delay_table_populated.compare_exchange_weak(expected, 1)) {
		return;
	}

	delay_table[idx++] = 200;

	for(int i = 0; i < 4; i++) {
		delay_table[idx++] = 50;
	}

	for(int i = 0; i < 95; i++) {
		delay_table[idx++] = 10;
	}
}

echo_gen::echo_gen(const int conn_id, std::unordered_map<std::string, std::string>* args) : req_gen(conn_id)
{
	
	if (args->find(PARAM_GEN) == args->end()) {
		this->wgen = createGenerator(PARAM_GEN_DEFAULT);
	} else {
    	this->wgen = createGenerator(args->at(PARAM_GEN));
	}

	if (this->wgen == NULL) {
		E("Failed to create wgen for echo_gen");
	}
	
	if (args->find(PARAM_CDELAY) == args->end()) {
		this->cdelay = PARAM_CDELAY_DEFAULT;
	} else {
		this->cdelay = atoi(args->at(PARAM_CDELAY).c_str());
	}

	if (this->cdelay) {
		populate_delay_table();
	}
}

echo_gen::~echo_gen()
{
    delete wgen;
}

int echo_gen::get_delay()
{
	if (cdelay) {
		return delay_table[conn_id % DT_SZ];
	} else {
		return this->wgen->generate();
	}
}

int echo_gen::send_req(int fd) 
{
	ppd_echo_req req;

	if (options.master_mode) {
		req.set_enable_delay(0);
	} else {
		req.set_enable_delay(get_delay());
	}

	if (!req.SerializeToArray(this->send_buf, MAX_SEND_BUF_SIZE)) {
		E("Failed to serialize to array for fd %d\n", fd);
	}

	return writemsg(fd, this->send_buf, MAX_SEND_BUF_SIZE, this->send_buf, req.ByteSizeLong());
}

int echo_gen::read_resp(int fd)
{
    ppd_echo_resp resp;
	struct ppd_msg * msg = (struct ppd_msg *)this->send_buf;

    if (readmsg(fd, this->send_buf, MAX_SEND_BUF_SIZE) < 0) {
		E("Readbuf failed for fd %d\n", fd);
	}

	resp.ParseFromArray(msg->payload, msg->size);

    return resp.status();
}

#if 0
////////////////
// HTTP Generator
////////////////
char http_gen::cons_buf[CONS_SZ];

http_gen::http_gen(const int conn_id, const std::string& host, std::unordered_map<std::string, std::string>* args) : req_gen(conn_id)
{
	// hack
	method = "GET";
	headers.insert({"Host", host});
	headers.insert({"Connection", "keep-alive"});
	major_ver = 1;
	minor_ver = 1;
	uri = "/";
}

http_gen::~http_gen()
{

}

std::string
http_gen::build_req()
{
	std::stringstream ss;

	ss << method << ' ' \
		<< uri << ' ' \
		<< "HTTP/" + std::to_string(major_ver) + "." + std::to_string(minor_ver) \
		<< "\r\n";

	for(auto &i : headers) {
		ss << i.first.c_str() << ": " << i.second.c_str() << "\r\n";
	}

	ss << "\r\n";

	return ss.str();
}

int http_gen::send_req(int fd) 
{
	std::string req = build_req();
	//V("Sending Request: %s\n", req.c_str());
	return writebuf(fd, (void*)req.c_str(), req.length());
}

int http_gen::read_resp(int fd)
{
	// hack
	// consume everything
	return read(fd, cons_buf, CONS_SZ);;
}

////////////////
// RDB Generator
////////////////
rdb_gen::rdb_gen(const int conn_id, std::unordered_map<std::string, std::string>* args) : req_gen(conn_id), rand(1000 + conn_id)
{
	this->key = AllocateKey(&this->key_guard, KEY_SIZE);
	std::vector<double> ratio {GET_RATIO, PUT_RATIO, SEEK_RATIO};
	this->query.Initiate(ratio);
	gen_exp.InitiateExpDistribution(TOTAL_KEYS, KEYRANGE_DIST_A, KEYRANGE_DIST_B, KEYRANGE_DIST_C, KEYRANGE_DIST_D);
}

rdb_gen::~rdb_gen()
{
	
}

int rdb_gen::send_req(int fd) 
{
	int status;
	ppd_rdb_req req;

	int64_t ini_rand = GetRandomKey(&this->rand);
	int64_t key_rand = gen_exp.DistGetKeyID(ini_rand, this->KEYRANGE_DIST_A, this->KEYRANGE_DIST_B);

	int64_t rand_v = ini_rand % TOTAL_KEYS;
	double u = (double)rand_v / TOTAL_KEYS;

	int query_type = options.master_mode ? 0 : query.GetType(rand_v);
	
	GenerateKeyFromInt(key_rand, TOTAL_KEYS, KEY_SIZE, &this->key);

	V("SENDING KEY: %s.\n", this->key.data());
	switch (query_type) {
		case 0: {
			// get query
			req.set_op(PPD_RDB_OP_GET);
			req.set_key(this->key.data(), this->key.size());
			break;
		}
		case 1: {
			// put query
			int val_sz = ParetoCdfInversion(u, VALUE_THETA, VALUE_K, VALUE_SIGMA);
			rocksdb::Slice val = gen.Generate((unsigned int)val_sz);
			req.set_op(PPD_RDB_OP_PUT);
			req.set_key(this->key.data(), this->key.size());
			req.set_val(val.data(), val.size());
			break;
		}
		case 2: {
			// seek query
			int64_t scan_length = ParetoCdfInversion(u, ITER_THETA, ITER_K, ITER_SIGMA);
			req.set_op(PPD_RDB_OP_SEEK);
			req.set_key(this->key.data(), this->key.size());
			req.set_optarg(scan_length);
			break;
		}
		default: {
			E("Unsupported query type %d", query_type);
		}
	}

	if (!req.SerializeToArray(this->send_buf, MAX_SEND_BUF_SIZE)) {
		E("Failed to serialize protobuf");
	}

	status = writemsg(fd, this->send_buf, MAX_SEND_BUF_SIZE, this->send_buf, req.ByteSizeLong());

	return status;
}

int rdb_gen::read_resp(int fd)
{
    ppd_rdb_resp resp;
	struct ppd_msg * msg = (struct ppd_msg *)this->send_buf;

    if (readmsg(fd, this->send_buf, MAX_SEND_BUF_SIZE) < 0) {
		E("Readbuf failed for fd %d", fd);
	}

	resp.ParseFromArray(msg->payload, msg->size);

    return resp.status();
}
#endif
