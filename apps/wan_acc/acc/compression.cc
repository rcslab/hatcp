#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <assert.h>
#include <sys/queue.h>
#include <sha256.h>

#include "lz4.h"
#include "uthash.h"

#include "compression.h"
#include "rbkp.h"
#include "vars.h"
#include "chunk.h"
#include "../utils.h"

struct chunk *
compress_chunk(struct chunk *ic)
{
	int max_dst_size, compressed_data_size;
	char *compressed_data;
	struct chunk *c;

	assert(ic != NULL);
	if (ic->flag & CHUNK_FLAG_COMPRESSED) return NULL;
	if (ic->len < COMPRESSION_THRESHOLD) return NULL;
	
	max_dst_size = LZ4_compressBound(ic->len);
	if (ic->flag & CHUNK_FLAG_DONTFREE) {
		c = chunk_alloc(max_dst_size);
		chunk_copyhdr(c, ic);
		compressed_data = CHUNK_DATA(c);
	} else {
		c = ic;
		compressed_data = (char *)malloc(max_dst_size);
		if (compressed_data == NULL) {
			free(compressed_data);
			DBG("Cannot allocate memory for compression");
			return NULL;
		}
	}
		
	c->src_len = c->len;

	compressed_data_size = LZ4_compress_default(CHUNK_DATA(ic), 
	    compressed_data, c->src_len, max_dst_size);
	if (compressed_data_size <= 0) {
		free(compressed_data);
		DBG("Cannot compress data");
		return NULL;
	} else {
		DBG("Compressed. Ratio: %.2f", 
		    c->src_len / (float)compressed_data_size);
	}

	c->flag |= (CHUNK_FLAG_COMPRESSED | CHUNK_FLAG_COMPRESSION_LZ4);
	c->len = compressed_data_size;
	if (!(ic->flag & CHUNK_FLAG_DONTFREE)) {
		memcpy(CHUNK_DATA(c), compressed_data, compressed_data_size);
		free(compressed_data);
	}
	CHUNK_DATA(c)[c->len] = '\0';

	return (c);
}


/*
 * When allocate the memory, make sure the size could fit the uncompressed data
 * to avoid realloc
 */
void 
decompress_chunk(struct chunk *c)
{
	if (!c) return;
	if (~(c->flag & CHUNK_FLAG_COMPRESSED)) return;

	assert(!(c->flag & CHUNK_FLAG_DONTFREE));

	decompress_chunk_raw(CHUNK_DATA(c), &(c->len), &(c->src_len), c);
	c->flag -= CHUNK_FLAG_COMPRESSED;
	/* Assume we always use LZ4 */
	c->flag -= CHUNK_FLAG_COMPRESSION_LZ4;
}

void
decompress_chunk_raw(void * data, uint32_t *len, uint32_t *src_len, struct chunk *c)
{
	char * decompressed_data;
	int decompressed_size;

	if (!c) return;

	assert(!(c->flag & CHUNK_FLAG_DONTFREE));

	decompressed_data = (char *)malloc(*src_len);
	if (decompressed_data == NULL) {
		DBG("Cannot allocate memory for decompression");
		exit(0);
	}

	decompressed_size = LZ4_decompress_safe((const char *)data, decompressed_data, 
	    *len, *src_len);
	if (decompressed_size < 0) {
		DBG("Cannot decompress data");
		exit(0);
	} else {
		if (decompressed_size != *src_len) {
			DBG("Decompressed size does not match the original");
			exit(0);
		}
		DBG("Decompressed.");
	}
	
	c->len = decompressed_size;
	   
	memcpy(CHUNK_DATA(c), decompressed_data, decompressed_size);

	free(decompressed_data);
}
