#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "addr_pool.h"
#include "rss.h"
#include "debug.h"

#define MIN_PORT (1025)
#define MAX_PORT (65535 + 1)

/*----------------------------------------------------------------------------*/
struct addr_entry
{
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	};
	TAILQ_ENTRY(addr_entry) addr_link;
};
/*----------------------------------------------------------------------------*/
struct addr_map
{
	struct addr_entry *addrmap[MAX_PORT];
};
/*----------------------------------------------------------------------------*/
struct addr_pool
{
	struct addr_entry *pool;		/* address pool */
	struct addr_map *mapper;		/* address map  */

	struct sockaddr_storage addr_base;
	int num_addr;					/* number of addresses in use */

	int num_entry;
	int num_free;
	int num_used;

	pthread_mutex_t lock;
	TAILQ_HEAD(, addr_entry) free_list;
	TAILQ_HEAD(, addr_entry) used_list;
};
/*----------------------------------------------------------------------------*/
addr_pool_t 
CreateAddressPool(const struct sockaddr* addr_base, int num_addr)
{
	struct addr_pool *ap;
	int num_entry;
	int i, j, cnt;
	struct sockaddr_storage addr;

	ap = (addr_pool_t)calloc(1, sizeof(struct addr_pool));
	if (!ap)
		return NULL;

	/* initialize address pool */
	num_entry = num_addr * (MAX_PORT - MIN_PORT);
	ap->pool = (struct addr_entry *)calloc(num_entry, sizeof(struct addr_entry));
	if (!ap->pool) {
		free(ap);
		return NULL;
	}

	/* initialize address map */
	ap->mapper = (struct addr_map *)calloc(num_addr, sizeof(struct addr_map));
	if (!ap->mapper) {
		free(ap->pool);
		free(ap);
		return NULL;
	}

	TAILQ_INIT(&ap->free_list);
	TAILQ_INIT(&ap->used_list);

	if (pthread_mutex_init(&ap->lock, NULL)) {
		free(ap->pool);
		free(ap);
		return NULL;
	}

	pthread_mutex_lock(&ap->lock);

	socklen_t sockaddr_size = addr_base->sa_family == AF_INET6 ?
							sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	memcpy(&ap->addr_base, addr_base, sockaddr_size);
	memcpy(&addr, addr_base, sockaddr_size);
	/* sin_port and sin6_port are at the same place in struct sockaddr_in{4,6} */
	in_port_t* port = &((struct sockaddr_in*)&addr)->sin_port;
	in_addr_t* addr_addr = addr.ss_family == AF_INET6 ?
			&((struct sockaddr_in6*)&addr)->sin6_addr.s6_addr32[3] :
			&((struct sockaddr_in*)&addr)->sin_addr.s_addr;

	ap->num_addr = num_addr;

	cnt = 0;
	for (i = 0; i < num_addr; i++) {
		for (j = MIN_PORT; j < MAX_PORT; j++) {
			*port = htons(j);

			memcpy(&ap->pool[cnt].addr, &addr, sockaddr_size);

			ap->mapper[i].addrmap[j] = &ap->pool[cnt];
			TAILQ_INSERT_TAIL(&ap->free_list, &ap->pool[cnt], addr_link);

			if ((++cnt) >= num_entry)
				break;
		}
		*addr_addr = htonl(ntohl(*addr_addr) + 1);
	}
	ap->num_entry = cnt;
	ap->num_free = cnt;
	ap->num_used = 0;
	
	pthread_mutex_unlock(&ap->lock);

	return ap;
}
/*----------------------------------------------------------------------------*/
addr_pool_t 
CreateAddressPoolPerCore(int core, int num_queues, 
		const struct sockaddr* saddr_base, int num_addr, const struct sockaddr* daddr)
{
	struct addr_pool *ap;
	int num_entry;
	int i, j, cnt;
	int rss_core;
	struct sockaddr_storage saddr;
	uint8_t endian_check = (current_iomodule_func == &dpdk_module_func) ?
		0 : 1;

	ap = (addr_pool_t)calloc(1, sizeof(struct addr_pool));
	if (!ap)
		return NULL;

	/* initialize address pool */
	num_entry = (num_addr * (MAX_PORT - MIN_PORT)) / num_queues;
	ap->pool = (struct addr_entry *)calloc(num_entry, sizeof(struct addr_entry));
	if (!ap->pool) {
		free(ap);
		return NULL;
	}
	
	/* initialize address map */
	ap->mapper = (struct addr_map *)calloc(num_addr, sizeof(struct addr_map));
	if (!ap->mapper) {
		free(ap->pool);
		free(ap);
		return NULL;
	}

	TAILQ_INIT(&ap->free_list);
	TAILQ_INIT(&ap->used_list);

	if (pthread_mutex_init(&ap->lock, NULL)) {
		free(ap->pool);
		free(ap);
		return NULL;
	}

	pthread_mutex_lock(&ap->lock);

	socklen_t sockaddr_size = saddr_base->sa_family == AF_INET6 ?
							sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	memcpy(&ap->addr_base, saddr_base, sockaddr_size);
	memcpy(&saddr, saddr_base, sockaddr_size);
	/* sin_port and sin6_port are at the same place in struct sockaddr_in[6] */
	in_port_t* sport = &((struct sockaddr_in*)&saddr)->sin_port;
	in_addr_t* saddr_addr = saddr.ss_family == AF_INET6 ?
			&((struct sockaddr_in6*)&saddr)->sin6_addr.s6_addr32[3] :
			&((struct sockaddr_in*)&saddr)->sin_addr.s_addr;
	ap->num_addr = num_addr;

	/* search address space to get RSS-friendly addresses */
	cnt = 0;
	for (i = 0; i < num_addr; i++) {
		for (j = MIN_PORT; j < MAX_PORT; j++) {
			if (cnt >= num_entry)
				break;

			*sport = htons(j);
			rss_core = GetRSSCPUCore((struct sockaddr*)daddr, (struct sockaddr*)&saddr,
					num_queues, endian_check);
			if (rss_core != core)
				continue;

			memcpy(&ap->pool[cnt].addr, &saddr, sockaddr_size);
			ap->mapper[i].addrmap[j] = &ap->pool[cnt];
			TAILQ_INSERT_TAIL(&ap->free_list, &ap->pool[cnt], addr_link);
			cnt++;
		}
		*saddr_addr = htonl(ntohl(*saddr_addr) + 1);
	}

	ap->num_entry = cnt;
	ap->num_free = cnt;
	ap->num_used = 0;
	//fprintf(stderr, "CPU %d: Created %d address entries.\n", core, cnt);
	if (ap->num_entry < CONFIG.max_concurrency) {
		fprintf(stderr, "[WARINING] Available # addresses (%d) is smaller than"
				" the max concurrency (%d).\n", 
				ap->num_entry, CONFIG.max_concurrency);
	}
	
	pthread_mutex_unlock(&ap->lock);

	return ap;
}
/*----------------------------------------------------------------------------*/
void
DestroyAddressPool(addr_pool_t ap)
{
	if (!ap)
		return;

	if (ap->pool) {
		free(ap->pool);
		ap->pool = NULL;
	}

	if (ap->mapper) {
		free(ap->mapper);
		ap->mapper = NULL;
	}

	pthread_mutex_destroy(&ap->lock);

	free(ap);
}
/*----------------------------------------------------------------------------*/
int 
FetchAddress(addr_pool_t ap, int core, int num_queues, 
		const struct sockaddr *daddr, struct sockaddr *saddr)
{
	struct addr_entry *walk, *next;
	int rss_core;
	int ret = -1;
	uint8_t endian_check = (current_iomodule_func == &dpdk_module_func) ?
		0 : 1;

	if (!ap || !daddr || !saddr)
		return -1;

	pthread_mutex_lock(&ap->lock);

	walk = TAILQ_FIRST(&ap->free_list);
	while (walk) {
		next = TAILQ_NEXT(walk, addr_link);

		rss_core = GetRSSCPUCore(&walk->addr, daddr, num_queues, endian_check);

		if (core == rss_core)
			break;

		walk = next;
	}

	if (walk) {
		socklen_t sockaddr_size = walk->addr.sa_family == AF_INET6 ?
								sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
		memcpy(saddr, &walk->addr, sockaddr_size);
		TAILQ_REMOVE(&ap->free_list, walk, addr_link);
		TAILQ_INSERT_TAIL(&ap->used_list, walk, addr_link);
		ap->num_free--;
		ap->num_used++;
		ret = 0;
	}
	
	pthread_mutex_unlock(&ap->lock);

	return ret;
}
/*----------------------------------------------------------------------------*/
int 
FreeAddress(addr_pool_t ap, const struct sockaddr* addr)
{
	struct addr_entry *walk, *next;
	int ret = -1;

	if (!ap || !addr)
		return -1;

	pthread_mutex_lock(&ap->lock);

	if (ap->mapper) {
		in_port_t port = ((struct sockaddr_in*)addr)->sin_port;
		in_addr_t addr_addr = addr->sa_family == AF_INET6 ?
				((struct sockaddr_in6*)addr)->sin6_addr.s6_addr32[3] :
				((struct sockaddr_in*)addr)->sin_addr.s_addr;
		in_addr_t addr_base = ap->addr_base.ss_family == AF_INET6 ?
				((struct sockaddr_in6*)&ap->addr_base)->sin6_addr.s6_addr32[3] :
				((struct sockaddr_in*)&ap->addr_base)->sin_addr.s_addr;
		int index = ntohl(addr_addr) - ntohl(addr_base);

		if (index >= 0 || index < ap->num_addr) {
			walk = ap->mapper[index].addrmap[ntohs(port)];
		} else {
			walk = NULL;
		}

	} else {
		walk = TAILQ_FIRST(&ap->used_list);
		while (walk) {
			next = TAILQ_NEXT(walk, addr_link);
			socklen_t sockaddr_size = addr->sa_family == AF_INET6 ?
									sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
			if (!memcmp(walk, addr, sockaddr_size)) {
				break;
			}

			walk = next;
		}

	}

	if (walk) {
		TAILQ_REMOVE(&ap->used_list, walk, addr_link);
		TAILQ_INSERT_TAIL(&ap->free_list, walk, addr_link);
		ap->num_free++;
		ap->num_used--;
		ret = 0;
	}

	pthread_mutex_unlock(&ap->lock);

	return ret;
}
/*----------------------------------------------------------------------------*/
