#ifndef HT_H_
#define HT_H_

#define HASH_TABLE_SIZE (16384)

#include "uthash.h"
#include <pthread.h>

struct hash_entry {
	unsigned char id[HASH_LENGTH];
	struct chunk *data;
	int count;
	UT_hash_handle hh;
};

struct hashtable {
	struct hash_entry *hashtable;
	pthread_mutex_t mtx;
};

void hashtable_init(struct hashtable *ht);
struct hash_entry * hashtable_find(struct hashtable *ht, unsigned char *id);
struct hash_entry * hashtable_findinsert(struct hashtable *ht, unsigned char *id, struct chunk *c);
int hashtable_insert(struct hashtable *ht, unsigned char *id, struct chunk *c);

//void hashentry_free(struct hash_entry *he);

#endif
