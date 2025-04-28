#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <assert.h>
#include <sys/queue.h>
#include <sha256.h>

#include "uthash.h"
#include "lz4.h"
#include "rbkp.h"
#include "vars.h"
#include "chunk.h"
#include "dedup.h"
#include "../utils.h"

void
dedup_init()
{
	rbkp_init();
}

struct chunk *
dedup_chunk_data(char * pld, int target, int min, int max, int length, struct hashtable *ht)
{
	struct chunk *c = NULL;
	rbkp_chunker(pld, target, min, max, length, &c, ht);
	return (c);
}

void
dedup_get_orig_chunk(struct chunk **c, struct hashtable *ht)
{
	struct chunk *tc = NULL;

	if ((*c)->flag & CHUNK_FLAG_DUP) {
		// Extract from local hashtable
		tc = rbkp_constructor_fast((*c)->hash, *c, ht);
		if (!tc) {
			// Fatal error, hash is not in our table.
			// TODO    maybe send a ctlmsg to ask?
			for (int i=0;i<HASH_LENGTH;i++)
				printf("%02x", ((*c)->hash)[i] & 0xff);
			printf("\n");
			DBG("Fatal error: hash entry not found. (hash%u)", (*c)->dhdr.hash);
			exit(0);
		}

		*c = tc;
	} else {
		// Insert to local hashtable
		if (!rbkp_add_hash((*c)->hash, *c, ht)) {
		}
	}
}

void
dedup_record_chunk(struct chunk *c, struct hashtable *ht)
{
	int error;
	
	if (!(c->flag & CHUNK_FLAG_DUP)) {
		error = rbkp_add_hash(c->hash, c, ht);
		if (error) {

		}
	}
}
