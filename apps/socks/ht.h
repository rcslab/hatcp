#ifndef HT_H_
#define HT_H_

#define HASH_TABLE_SIZE (16384)

#include "uthash.h"

struct hash_entry {
	int id;
	void *data;
	int count;
	UT_hash_handle hh;
};

struct hash_entry * hashtable_find(struct hash_entry *ht, int id);
int hashtable_insert(struct hash_entry ** ht, int id, void *c);

void hashentry_free(struct hash_entry *he);

#endif
