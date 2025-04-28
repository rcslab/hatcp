#include <stdio.h>
#include <string.h>

#include <sys/hash.h>
#include <sys/queue.h>
#include <arpa/inet.h>

#include "utils.h"
#include "ht.h"
#include <ev.h>
#include "socks.h"
#include "hosts.h"

static int hosts_insert(struct hostaddr *, struct hostaddr *);
static uint32_t hosts_hash(struct hostaddr *);
static int parse_host_line(char *line, struct hostaddr *, struct hostaddr *);

static struct hash_entry *hashtable = NULL;

int 
hosts_init(const char *fn)
{
	FILE * fp;
	char line[65536];
	int count = 0, rt = 0;
	struct hostaddr *addr;
	struct hostaddr orig_addr;

	if (fn == NULL)
		return (0);

	fp = fopen(fn, "r");
	if (fp == NULL) {
		APPERR("Failed to open hosts file %s", fp);
		exit(0);
	}

	while (1) {
		memset(line, '\0', sizeof(line));
		if (fgets(line, sizeof(line), fp) == NULL) {
			break;
		}

		addr = calloc(1, sizeof(struct hostaddr));
		
		rt = parse_host_line(line, &orig_addr, addr);
		if (rt) {
			free(addr);
			continue;
		}

		rt = hosts_insert(&orig_addr, addr);
		if (rt) {
			DBG("[hosts] Cannot insert to hosts HT");
			free(addr);
			continue;
		}

		count++;
	}
	DBG("[hosts] %d columns buffered.", count);

	fclose(fp);
	return (count);
}

int
hosts_free()
{
}

static int
hosts_insert(struct hostaddr *orig_addr, struct hostaddr *map_addr)
{
	uint32_t hash;

	hash = hosts_hash(orig_addr);
	if (!hashtable_insert(&hashtable, hash, map_addr)) {
		return (1);
	}
	if (map_addr->type == SOCKS_ATYP_IPV4) {
		DBG("[hosts] ipv4 Hash %u: Addr %u\n", hash, map_addr->ip_addr);
	} else if (map_addr->type == SOCKS_ATYP_IPV6) {
	}

	return (0);
}

static uint32_t
hosts_hash(struct hostaddr *addr)
{
	int len = 0;
	uint8_t *ptr;

	switch (addr->type) {
	case SOCKS_ATYP_IPV4:
		len = 4;
		ptr = &addr->ip_addr;
		break;
	case SOCKS_ATYP_IPV6:
		len = 16;
		ptr = addr->ip6_addr;
		break;
	default:
		return (0);
	}

	return (hash32_buf(ptr, len, HASHINIT));
}

static int
parse_host_line(char *line, struct hostaddr *orig_addr, struct hostaddr *map_addr)
{
	int state = 0;
	int og_atyp = -1, ne_atyp = -1;
	int ogl = -1, ogr = -1;
	int nel = -1, ner = -1;
	int oglen = 0, nelen = 0;
	char *og_addr, *ne_addr;
	uint32_t ip4_addr_og, ip4_addr_ne;

	for (int i=0;i<strlen(line);i++) {
		if (state == 0 || state == 2) {
			if (line[i] == '#' || line[i] == '\n' || line[i] == '\0') {
				return (1);
			}
			if (line[i] != ' ')
				state++;
			else
				continue;
		}

		switch (state) {
		case 1:
			if (ogl == -1)
				ogl = i;

			if (line[i] == ' ') {
				ogr = i;
				state++;
			}
			break;
		case 3:
			if (nel == -1)
				nel = i;
			if (line[i] == ' ' || i == (strlen(line)-1)) {
				ner = i;
				state++;
			}
			break;
		}
	}

	oglen = ogr - ogl;
	nelen = ner - nel;

	if (state != 4 
	    || (ogl < 0) || (ogr < 0) 
	    || (nel < 0) || (ner < 0)
	    || (oglen <= 0) || (oglen >= strlen(line))
	    || (nelen <= 0) || (nelen >= strlen(line))
	    || (oglen+nelen >= strlen(line))) 
		return (1);
	
	og_addr = calloc(1, oglen + 1);
	ne_addr = calloc(1, nelen + 1);

	memcpy(og_addr, line + ogl, oglen);
	memcpy(ne_addr, line + nel, nelen);

	if (strchr(og_addr, '.') != NULL) {
		og_atyp = SOCKS_ATYP_IPV4;
	} else if (strchr(og_addr, ':') != NULL) {
		og_atyp = SOCKS_ATYP_IPV6;
	} else {
		goto bad;
	}

	if (strchr(ne_addr, '.') != NULL) {
		ne_atyp = SOCKS_ATYP_IPV4;
	} else if (strchr(ne_addr, ':') != NULL) {
		ne_atyp = SOCKS_ATYP_IPV6;
	} else {
		goto bad;
	}

	if (og_atyp == SOCKS_ATYP_IPV4) {
		ip4_addr_og = inet_addr(og_addr);
		if (ip4_addr_og == -1)
			goto bad;

		orig_addr->type = SOCKS_ATYP_IPV4;
		orig_addr->ip_addr = ip4_addr_og;
	} else {
		printf("TODO: ipv6 hosts");
		exit(0);
	}

	if (ne_atyp == SOCKS_ATYP_IPV4) {
		ip4_addr_ne = inet_addr(ne_addr);
		if (ip4_addr_ne < 0)
			goto bad;

		map_addr->type = SOCKS_ATYP_IPV4;
		map_addr->ip_addr = ip4_addr_ne;
	} else {
		printf("TODO: ipv6 hosts");
		exit(0);
	}

	return (0);

bad:
	free(og_addr);
	free(ne_addr);
	return (1);

}

int 
hosts_query(struct hostaddr *in, struct hostaddr **out)
{
	struct hash_entry *he;
	uint32_t id;

	id = hosts_hash(in);
	he = hashtable_find(hashtable, id);
	if (!he) {
		return (1);
	}

	*out = he->data;
	return (0);
}
