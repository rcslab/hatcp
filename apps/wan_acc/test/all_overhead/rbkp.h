#ifndef RBKP_H_
#define RBKP_H_

#define WINDOW_SIZE	(1024)
#define HASH_PRIME	(31)

#ifdef HASH_SKEIN_256
#define HASH_LENGTH	(32)
#elif HASH_SHA3_256
#define HASH_LENGTH	(32)
#elif HASH_MD5
#define HASH_LENGTH	(16)
#elif HASH_RANDOM
#define HASH_LENGTH	(32)
#else 
#define HASH_LENGTH	(SHA256_DIGEST_LENGTH)
#endif

#include "ht.h"

struct chunk;

/* c has to be NULL */
int rbkp_chunker(char * pld, int target, int min_c, int max_c, int length,
    struct chunk **, struct hashtable *);
void rbkp_init();
struct chunk * rbkp_constructor(unsigned char *id, struct hashtable *);
struct chunk * rbkp_constructor_fast(unsigned char *id, struct chunk *, struct hashtable *);
int rbkp_add_hash(unsigned char *id, struct chunk *c, struct hashtable *);

#endif
