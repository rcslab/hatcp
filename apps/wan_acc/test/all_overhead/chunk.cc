#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <sys/queue.h>
#include <assert.h>
#include <sha256.h>

#include "uthash.h"
#include "vars.h"
#include "rbkp.h"
#include "chunk.h"

/*
 * size is the actual user payload size without header
 */
struct chunk *
chunk_alloc(uint32_t size)
{
	struct chunk *c;

	c = (struct chunk *)calloc(1, size + sizeof(struct chunk));
#ifdef CHUNK_DEBUG
	c->allocation_size = size + sizeof(struct chunk);
#endif

	return (c);
}

void
chunk_free(struct chunk *c)
{
	if (!c) return;
	free(c);
}

void
chunk_copy(struct chunk *dst, struct chunk *src)
{
	if (!dst || !src) return;
#ifdef CHUNK_DEBUG
	assert(dst->allocation_size >= src->allocation_size);
#endif

#ifdef CHUNK_DEBUG
	memcpy((char *)dst + 1, (char *)src + 1, 
	    src->len + sizeof(struct chunk) - 1);
#else
	memcpy(dst, src, src->len + sizeof(struct chunk)); 
#endif
}



/*
 * TODO: remove if we don't need to set variables after deserilization.
 */
struct chunk *
chunk_deserialize(void *chunk, int len)
{
	struct chunk *c;

	c = (struct chunk *)chunk;
	
	/* sanity check */
#ifdef CHUNK_DEBUG
	assert(c->len == len + sizeof(struct chunk) - 1);
#else
	assert(c->len == len + sizeof(struct chunk));
#endif

	return (c);
}

void
chunk_copyhdr(struct chunk *dst, struct chunk *src)
{
	if (!dst || !src) return;

	dst->len = src->len;
	dst->src_len = src->src_len;
	dst->flag = src->flag;
	memcpy(dst->hash, src->hash, HASH_LENGTH);
	dst->dhdr = src->dhdr;
}

void
chunk_copydata(struct chunk *dst, struct chunk *src)
{
	if (!dst || !src) return;

#ifdef CHUNK_DEBUG
	assert(dst->allocation_size >= src->allocation_size);
#endif
	memcpy(CHUNK_DATA(dst), CHUNK_DATA(src), src->len); 
}

