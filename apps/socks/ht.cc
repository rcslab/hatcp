#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <string.h>
#include <sha256.h>

#include "uthash.h"

#include "hosts.h"
#include "ht.h"

static void hashtable_compact(struct hash_entry ** ht);
static int hash_sort_cmp(void *a, void *b);


struct hash_entry * 
hashtable_find(struct hash_entry *ht, int id)
{
	struct hash_entry *he = NULL;

	if (!ht) return (NULL);

	HASH_FIND_INT(ht, &id, he);

	return (he);
}

int 
hashtable_insert(struct hash_entry ** ht, int id, void *c)
{
	struct hash_entry *he;
	struct hostaddr *ic;
	uint32_t ht_size;
	
	if (ht == NULL) return (0);

	/*
	ic = chunk_alloc(c->len);
	chunk_copy(ic, c);
	*/
	ic = (struct hostaddr *)c;

	he = (struct hash_entry *)malloc(sizeof(struct hash_entry));
	he->id = id;
	he->data = ic;
	he->count = 1;

	HASH_ADD_INT(*ht, id, he);

	/* If our HT is full, do the clean up */
	ht_size = HASH_COUNT(*ht);
	if (ht_size >= HASH_TABLE_SIZE) {
		hashtable_compact(ht);
	}

	return (ht_size);
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
