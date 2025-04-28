#ifndef CHUNK_H_
#define CHUNK_H_

#define CHUNK_FLAG_DONTCACHE		0x1
#define CHUNK_FLAG_DUP			0x2
#define CHUNK_FLAG_COMPRESSED		0x4
#define CHUNK_FLAG_COMPRESSION_LZ4	0x8
#define CHUNK_FLAG_COMPRESSION_DONTUSE	0x10
#define CHUNK_FLAG_COLORED		0x20
#define CHUNK_FLAG_DONTFREE		0x40

#define CHUNK_DATA(c)		((char *)((char *)c + sizeof(struct chunk)))
#define CHUNK_LEN(c)		(sizeof(struct chunk) + \
				((c->flag&CHUNK_FLAG_DUP) ? 0 : c->len))

#define IS_CHUNK_DUP(x)		(((struct chunk *)x)->flag & CHUNK_FLAG_DUP)

#include "uthash.h"
#include "vars.h"
#include "rbkp.h"

struct chunk {
#ifdef CHUNK_DEBUG
	int allocation_size;
#endif
	uint32_t len;	/* the length of actual payload in this chunk */
	uint32_t src_len;	/* used for LZ4 */
	uint32_t flag;
	unsigned char hash[HASH_LENGTH+1];
	struct data_hdr dhdr;	/* the info of orig payload before chunking */
};

struct chunk * chunk_alloc(uint32_t size);
void chunk_free(struct chunk *c);
struct chunk * chunk_deserialize(void *chunk, int len);
void chunk_copy(struct chunk *dst, struct chunk *src);
void chunk_copyhdr(struct chunk *dst, struct chunk *src);
void chunk_copydata(struct chunk *dst, struct chunk *src);

static int
get_chunk_size(struct chunk *hdr, int len)
{
	if (len >= sizeof(struct chunk)) {
		return (CHUNK_LEN(hdr));
	}

	return (-1);
}

#endif 
