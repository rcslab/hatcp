#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <string.h>
#include <assert.h>
#ifdef HASH_SKEIN_256
    #include "skein/skein.h"
    #include "skein/SHA3api_ref.h"
#elif HASH_MD5
    #include <openssl/md5.h>
#elif HASH_SHA3_256
    #include <openssl/evp.h>
#elif HASH_RANDOM
    #include <time.h>
#else
    #include <sha256.h>
#endif

#include "lz4.h"
#include "uthash.h"
#include "vars.h"
#include "rbkp.h"
#include "ht.h"
#include "dedup.h"
#include "chunk.h"
#include "../utils.h"

static uint64_t rfhash_from_payload(char * pld, struct chunk *c, int len, int *error);
static uint64_t rfhash_from_payload_idx(char * pld, int st, int len, int *error);
static uint64_t rfhash_rolling(uint64_t hash, char in, char out);
static int chunk_from_payload(char * pld, struct chunk *c, int len);

static struct hash_entry *hashtable = NULL;
static uint32_t pow_lookup_table[256];

void
rbkp_init()
{
	uint64_t tok = 1;

	for (int i=0;i<HASH_LENGTH;i++) 
		tok *= HASH_PRIME;
	for (int i=0;i<256;i++)
		pow_lookup_table[i] = i * tok;

#ifdef HASH_RANDOM
	srand((unsigned)time(NULL));
	INFO("Warning: hash values are generated randomly. This is only for debugging purpose.");
#endif
}

int
rbkp_chunker(char * pld, int target, int min_c, int max_c, int length,
    struct chunk **ic, struct hashtable *ht)
{
	uint64_t hash = 0;
	char data;
	int idx, error, tlen, min, max;
	struct hash_entry *he = NULL;
	struct chunk *c = NULL;	/* Chunk struct for current cuting chunk */
#ifdef HASH_SKEIN_256
	Skein_256_Ctxt_t ctx;
#elif HASH_MD5
	MD5_CTX ctx;
	int ctx_len;
	int ctx_off;
#elif HASH_SHA3_256
	unsigned int dlen;
	const EVP_MD *algo = EVP_sha3_256();
	EVP_MD_CTX *ctx;
#elif HASH_RANDOM
	//do nothing
#else
	SHA256_CTX ctx;
#endif

	if (*ic) return (1);

	min = min_c;
	max = max_c;
	
	if (length == 0) return (1);

	/* adjusting min and max to eliminate rbkp's chunking range */
	if (min >= length) {
		min = length;
		max = length;
		goto chunk_allocation;
	}
	if (max >= length) {
		max = length;
	}

chunk_allocation:
	c = chunk_alloc(max);

	// get the init chunk by offseting min size.
	//                <----<  WINDOW  >--> 
	//    |-----------|----[-|--------]---|
	//		 MIN    MAX 
	//
	// We simply bypass the calculation of the first MIN worth of data and
	// start the calculation from the MIN position.
	idx = min;
	if (length <= idx) {
		error = chunk_from_payload(pld, c, length);
		if (error) {
			DBG("Cannot get chunk from user packet.");
			goto error;
		}
		goto SHA;
	}

	/* Get chunk from the beginning to MIN position */
	error = chunk_from_payload(pld, c, min);
	if (error) {
		DBG("Cannot get chunk from user packet.");
		goto error;
	}

	/* Get rolling window chunk at MIN position */
	hash = rfhash_from_payload_idx(pld, 0, WINDOW_SIZE, &error);
	if (error) {
		//TODO fatal error......
		
		DBG("Cannot calculate hash value for chunk");
		goto error;
	}

	/* Keep rolling the window */
	while (idx < max) {
		if ((hash % target) == 1) {
			break;
		}
		data = pld[idx++];

		hash = rfhash_rolling(hash, data, pld[idx - WINDOW_SIZE]);
		CHUNK_DATA(c)[c->len++] = data;
	}

SHA:
#ifdef HASH_SKEIN_256
	Skein_256_Init(&ctx, HASH_LENGTH);
	Skein_256_Update(&ctx, (const u08b_t *)CHUNK_DATA(c), c->len);
	Skein_256_Final(&ctx, c->hash);
#elif HASH_MD5
	MD5_Init(&ctx);

	ctx_len = c->len;
	ctx_off = 0;
	while (ctx_len > 0) {
		if (ctx_len > 512) {
			MD5_Update(&ctx, (char *)CHUNK_DATA(c) + ctx_off, 512);
			ctx_len -= 512;
			ctx_off += 512;
		} else {
			MD5_Update(&ctx, (char *)CHUNK_DATA(c) + ctx_off, ctx_len);
			ctx_len = 0;
			ctx_off = ctx_len;
		}
	}

	MD5_Final(c->hash, &ctx);
#elif HASH_SHA3_256
	if ((ctx = EVP_MD_CTX_create()) == NULL) {
		printf("%s:%d error EVP_MD_CTX_create\n", __func__, __LINE__);
		exit(0);
	}

	if (EVP_DigestInit_ex(ctx, algo, NULL) != 1) {
		printf("%s:%d error EVP\n", __func__, __LINE__);
		exit(0);
	}

	if (EVP_DigestUpdate(ctx, CHUNK_DATA(c), c->len) != 1) {
		printf("%s:%d error EVP\n", __func__, __LINE__);
		exit(0);
	}

	dlen = EVP_MD_size(algo);

	if (EVP_DigestFinal_ex(ctx, c->hash, &dlen) != 1) {
		printf("%s:%d error EVP\n", __func__, __LINE__);
		exit(0);
	}

	EVP_MD_CTX_destroy(ctx);
#elif HASH_RANDOM
	for (int i=0;i<HASH_LENGTH;i++) 
		c->hash[i] = rand() % 0xff;
#else
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, CHUNK_DATA(c), c->len);
	SHA256_Final(c->hash, &ctx);
#endif
	
	c->hash[HASH_LENGTH] = '\0';
	c->src_len = c->len;

	he = hashtable_findinsert(ht, c->hash, c);
	if (he) {
#ifdef HASH_DEBUG
		// Validate the chunk is identical to the one in HT

#endif

		//DBG("Found dup chunk in HT with count %d", he->count);
		he->count++;

		c->flag |= CHUNK_FLAG_DUP; 
	} 

	*ic = c;
	
	return (0);

error:
	chunk_free(c);
	return (1);
}

/*
 * Fast chunk construction from hash table.
 *
 * Note: make sure the dest chunk has enough space.
 */
struct chunk *
rbkp_constructor_fast(unsigned char *id, struct chunk * c, struct hashtable *ht)
{
	struct hash_entry *he;

	if (!id) return (NULL);
	//if (strlen((char *)id) != HASH_LENGTH) return (NULL);

	he = hashtable_find(ht, id);
	if (!he) {
		return (NULL);
	}

	he->count++;

#ifdef CHUNK_DEBUG
	assert(c->allocation_size >= he->data->len + sizeof(struct chunk));
#endif

	chunk_copydata(c, he->data);

	return (c);
}

struct chunk *
rbkp_constructor(unsigned char *id, struct hashtable *ht)
{
	struct hash_entry *he;	
	struct chunk *c;

	if (!id) return (NULL);
	//if (strlen((char *)id) != HASH_LENGTH) return (NULL);

	he = hashtable_find(ht, id);
	if (!he) {
		return (NULL);
	}

	he->count++;

	c = chunk_alloc(he->data->len);
	chunk_copy(c, he->data);

	return (c);
}

int 
rbkp_add_hash(unsigned char *id, struct chunk *c, struct hashtable *ht)
{
	hashtable_insert(ht, id, c);
	return (0);
}

/*
 * Calculate hash value(Rabin Fingerprint) && copy payload to chunk structure
 */
static uint64_t 
rfhash_from_payload(char * pld, struct chunk *c, int len, int *error)
{
	uint64_t hash = 0;

	*error = 1;
	if (!pld || !c) return (0);

	for (int i=0;i<len;i++) {
		CHUNK_DATA(c)[i] = pld[i];
		hash *= HASH_PRIME;
		hash += pld[i];
	}

	c->len = len;

	*error = 0;
	return (hash);
}

/*
 * Calculate hash value at specific position
 * Note: make sure the starting position and ending position is within the range
 */
static uint64_t 
rfhash_from_payload_idx(char * pld, int st, int len, int *error)
{
	uint64_t hash = 0;

	*error = 1;
	if (!pld) return (0);

	for (int i=0;i<len;i++) {
		hash *= HASH_PRIME;
		hash += pld[st + i];
	}

	*error = 0;
	return (hash);
}

/*
 * Calculate hash(Rabin Fingerprint), rolling style
 */
static uint64_t 
rfhash_rolling(uint64_t hash, char in, char out)
{
	return ((hash - pow_lookup_table[(uint8_t)out]) * HASH_PRIME + (uint8_t)in);
}

/*
 * get chunk from payload at specific offset/len
 */
static int
chunk_from_payload(char * pld, struct chunk *c, int len)
{
	if (!pld || !c) return 1;
	
	memcpy(CHUNK_DATA(c), pld, len); 
	c->len = len;

	return 0;
}


