#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/ipv6.h>
#include "rss.h"
#include "debug.h"

/*-------------------------------------------------------------*/ 
static void 
BuildKeyCache(uint32_t *cache, int cache_len)
{
#define NBBY 8 /* number of bits per byte */

	/* Keys for system testing */
	static const uint8_t key[] = {
		 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
		 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
		 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
		 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
		 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
	};

	uint32_t result = (((uint32_t)key[0]) << 24) | 
		(((uint32_t)key[1]) << 16) | 
		(((uint32_t)key[2]) << 8)  | 
		((uint32_t)key[3]);

	uint32_t idx = 32;
	int i;

	for (i = 0; i < cache_len; i++, idx++) {
		uint8_t shift = (idx % NBBY);
		uint32_t bit;

		cache[i] = result;
		bit = ((key[idx/NBBY] << shift) & 0x80) ? 1 : 0;
		result = ((result << 1) | bit);
	}
}
/*-------------------------------------------------------------*/ 
static uint32_t 
GetRSSHash(const struct sockaddr* saddr, const struct sockaddr* daddr)
{
#define MSB32 0x80000000
#define MSB16 0x8000
#define KEY_CACHE_LEN 288 /* (16+16+2+2)*8 */

	/* Reference: 82599-10-gbe-controller-datasheet.pdf, pp 297-301 */

	uint32_t res = 0;
	int i;
	int j = 0;
	static int first = 1;
	static uint32_t key_cache[KEY_CACHE_LEN] = {0};
	uint32_t ip; /* in host order */
	uint16_t sp = 0, dp = 0; /* in host order */
	
	if (first) {
		BuildKeyCache(key_cache, KEY_CACHE_LEN);
		first = 0;
	}

	if (saddr->sa_family == AF_INET) {
		struct sockaddr_in* saddr4 = (struct sockaddr_in*) saddr;
		struct sockaddr_in* daddr4 = (struct sockaddr_in*) daddr;
		sp = ntohs(saddr4->sin_port);
		dp = ntohs(daddr4->sin_port);

		ip = ntohl(saddr4->sin_addr.s_addr);
		for (i = 0; i < 32; i++, j++) {
			if (ip & MSB32)
				res ^= key_cache[j];
			ip <<= 1;
		}
		ip = ntohl(daddr4->sin_addr.s_addr);
		for (i = 0; i < 32; i++, j++) {
			if (ip & MSB32)
				res ^= key_cache[j];
			ip <<= 1;
		}
	} else if (saddr->sa_family == AF_INET6) {
		struct sockaddr_in6* saddr6 = (struct sockaddr_in6*) saddr;
		struct sockaddr_in6* daddr6 = (struct sockaddr_in6*) daddr;
		sp = ntohs(saddr6->sin6_port);
		dp = ntohs(daddr6->sin6_port);
		int k;
		for (k = 0; k < 4; k++) {
			ip = ntohl(saddr6->sin6_addr.s6_addr32[k]);
			for (i = 0; i < 32; i++, j++) {
				if (ip & MSB32)
					res ^= key_cache[j];
				ip <<= 1;
			}
		}
		for (k = 0; k < 4; k++) {
			ip = ntohl(daddr6->sin6_addr.s6_addr32[k]);
			for (i = 0; i < 32; i++, j++) {
				if (ip & MSB32)
					res ^= key_cache[j];
				ip <<= 1;
			}
		}
	} else {
		assert(0);
	}

	for (i = 0; i < 16; i++, j++) {
		if (sp & MSB16)
			res ^= key_cache[j];
		sp <<= 1;
	}
	for (i = 0; i < 16; i++, j++) {
		if (dp & MSB16)
			res ^= key_cache[j];
		dp <<= 1;
	}
	return res;
}
/*-------------------------------------------------------------------*/ 
/* RSS redirection table is in the little endian byte order (intel)  */
/*																   */
/* idx: 0 1 2 3 | 4 5 6 7 | 8 9 10 11 | 12 13 14 15 | 16 17 18 19 ...*/
/* val: 3 2 1 0 | 7 6 5 4 | 11 10 9 8 | 15 14 13 12 | 19 18 17 16 ...*/
/* qid = val % num_queues */
/*-------------------------------------------------------------------*/ 
int
GetRSSCPUCore(const struct sockaddr* saddr, const struct sockaddr* daddr,
		int num_queues, uint8_t endian_check)
{
	#define RSS_BIT_MASK 0x0000007F
	uint32_t masked = GetRSSHash(saddr, daddr) & RSS_BIT_MASK;

	if (endian_check) {
		static const uint32_t off[4] = {3, 1, -1, -3};
		masked += off[masked & 0x3];
	}

	return (masked % num_queues);
}
/*-------------------------------------------------------------------*/ 
