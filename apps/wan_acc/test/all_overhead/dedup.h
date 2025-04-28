#ifndef DEDUP_H_
#define DEDUP_H_

#define CHUNK_SIZE_TARGET	4096
#define CHUNK_SIZE_MIN		2048
#define CHUNK_SIZE_MAX		8192


void dedup_init();
struct chunk *
dedup_chunk_data(char * pld, int target, int min, int max, int length, struct hashtable *ht);
void dedup_get_orig_chunk(struct chunk **c, struct hashtable *ht);
void dedup_record_chunk(struct chunk *c, struct hashtable *ht);

#endif
