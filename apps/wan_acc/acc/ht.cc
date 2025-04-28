#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <string.h>
#include <sha256.h>

#include "dedup.h"
#include "rbkp.h"

#include "uthash.h"

#include "vars.h"
#include "chunk.h"
#include "ht.h"

static void hashtable_compact(struct hash_entry ** ht);
static int hash_sort_cmp(void *a, void *b);
static int hashtable_insert_internal(struct hash_entry ** ht, unsigned char *id, struct chunk *c);

void
hashtable_init(struct hashtable *ht)
{
	ht->hashtable = NULL;
	ht->mtx = PTHREAD_MUTEX_INITIALIZER;
}

struct hash_entry * 
hashtable_find(struct hashtable *ht, unsigned char *id)
{
	struct hash_entry *he = NULL;

	if (!ht) return (NULL);

	HASH_FIND_SHA(ht->hashtable, (char *)id, HASH_LENGTH, he);
	/*
	if (he == NULL) {
		struct hash_entry *h, *tmp;
		printf("ALL keys find\n");
		for (h = ht->hashtable; h != NULL; h = h->hh.next) {
			for (int i=0;i<8;i++)
			    printf("%x", h->id[i] & 0xff );
			printf("\n\n");
		}
	}
	*/

	return (he);
}

struct hash_entry *
hashtable_findinsert(struct hashtable *ht, unsigned char *id, struct chunk *c)
{
	struct hash_entry *he = NULL;

	if (!ht) return (NULL);

	HASH_FIND_SHA(ht->hashtable, (char *)id, HASH_LENGTH, he);

	if (!he) {
		if (!hashtable_insert_internal(&ht->hashtable, id, c)) {
			//TODO
		}
		he = NULL;
	}

	/*
	if (he == NULL) {
		struct hash_entry *h, *tmp;
		printf("ALL keys\n");
		for (h = ht->hashtable; h != NULL; h = h->hh.next) {
			for (int i=0;i<8;i++)
			    printf("%x", h->id[i] & 0xff );
			printf("\n\n");
		}
	}
	*/

	return (he);
}

int 
hashtable_insert(struct hashtable *ht, unsigned char *id, struct chunk *c)
{
	hashtable_insert_internal(&ht->hashtable, id, c);
	/*
	struct hash_entry *h, *tmp;
	printf("ALL keys\n");
	for (h = ht->hashtable; h != NULL; h = h->hh.next) {
		for (int i=0;i<8;i++)
		    printf("%x", h->id[i] & 0xff );
		printf("\n\n");
	}
	*/
}

static int
hashtable_insert_internal(struct hash_entry ** ht, unsigned char *id, struct chunk *c)
{
	struct hash_entry *he;
	struct chunk *ic;
	uint32_t ht_size;
	
	if (ht == NULL) return (0);

	/*
	ic = chunk_alloc(c->len);
	chunk_copy(ic, c);
	*/
	ic = c;
	ic->flag |= CHUNK_FLAG_DONTFREE;

	he = (struct hash_entry *)malloc(sizeof(struct hash_entry));
	memcpy((char *)he->id, (char *)id, HASH_LENGTH);
	he->data = ic;
	he->count = 1;

	/* If our HT is full, do the clean up */
	ht_size = HASH_COUNT(*ht);
	if (ht_size >= HASH_TABLE_SIZE) {
		hashtable_compact(ht);
	}
	
	//HASH_ADD_KEYPTR(hh, hashtable, (char *)he->id, strlen((char *)he->id), he);
	HASH_ADD_SHA(*ht, id, HASH_LENGTH, he);

	return (ic->len);
}

void
hashentry_free(struct hash_entry *he)
{
	if (!he) return;
	if (he->data) 
		free(he->data);
	free(he);
}

static void 
hashtable_compact(struct hash_entry **ht)
{
	struct hash_entry *he, *tmp;
	int idx = 0, total = HASH_COUNT(*ht);

	/* Sort HT based on entry count */
	HASH_SORT(*ht, hash_sort_cmp);

	/* Remove old entries */
	/* For now let's just simply remove 1/2 of the entires */
	HASH_ITER(hh, *ht, he, tmp) {
		if (idx++ <= total / 2) {
			HASH_DEL(*ht, he);
			hashentry_free(he); 
		}
	}
}

static int
hash_sort_cmp(void *a, void *b) {
	/* compare a to b (cast a and b appropriately)
	 * return (int) -1 if (a < b)
	 * return (int)  0 if (a == b)
	 * return (int)  1 if (a > b)
	*/
	int ca, cb;
	ca = ((struct hash_entry *)a)->count;
	cb = ((struct hash_entry *)b)->count;
    
	return (ca == cb ? 0: (int)((ca-cb) / abs(ca-cb)));
}
