#ifndef __ND_H_
#define __ND_H_

#include <netinet/in.h>

#define MAX_ND_ENTRIES 1024
struct nshdr;
struct nahdr;

unsigned char*
GetDestinationHWaddrForIPv6(const struct in6_addr* dip);

int
InitNDTable();

void
RequestNeighborSolicitation(mtcp_manager_t mtcp, const struct in6_addr* dst,
		int nif);

int
ProcessNeighborSolicitation(mtcp_manager_t mtcp, const struct nshdr* ns,
		const struct in6_addr* src, int len, int nif);

int
ProcessNeighborAdvertisement(mtcp_manager_t mtcp, const struct nahdr* na,
		int len, int nif);

void NDTimer(mtcp_manager_t mtcp);

#endif /* __ND_H_ */
