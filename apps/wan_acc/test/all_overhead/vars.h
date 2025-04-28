#ifndef VARS_H_
#define VARS_H_

/* 
 * We use datahdr to identify the source of a data segment(DS).
 * When (front-server) receives a DS it will append the datahdr in front and
 * send it to the (back-server). Once the back-server receives this DS, 
 * it will look up the local hash table using datahdr as the key to find 
 * the occupancy of the (end-server) socket. If so, sending the DS with 
 * datahdr trimed off.
 */
struct data_hdr {
	//uint32_t ip;
	//uint16_t port;
	int len;
	uint64_t hash;
};

struct so_entry {
	uint64_t id;		/* src fd */
	int fd;
	UT_hash_handle hh;
};

#endif
