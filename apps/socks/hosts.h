#ifndef        HOSTS_H
#define        HOSTS_H

struct hostaddr {
	int type;
	union {
	    uint32_t ip_addr;
	    uint8_t ip6_addr[16];
	};
};

int hosts_init(const char *fn);
int hosts_free();

int hosts_query(struct hostaddr *, struct hostaddr **);


#endif
