#ifndef COMPRESSION_H_
#define COMPRESSION_H_

#define COMPRESSION_THRESHOLD	2

struct chunk * compress_chunk(struct chunk *ic);
void decompress_chunk(struct chunk *c);
void decompress_chunk_raw(void * data, uint32_t *len, uint32_t *src_len, struct chunk *c); 

#endif
