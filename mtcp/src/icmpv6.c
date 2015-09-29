/*
 * IPv6 support for mTCP
 * Author: Yoann Desmouceaux
 */

#include "mtcp.h"
#include "nd.h"
#include "icmpv6.h"
#include "debug.h"

uint16_t
ICMPv6ComputeChecksum(const struct icmpv6hdr* icmp, const struct in6_addr* src,
		const struct in6_addr* dst, uint16_t len)
{
	uint32_t sum;
	uint16_t *w;
	int nleft;

	sum = 0;
	nleft = len;
	w = (uint16_t*)icmp;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	// add padding for odd length
	if (nleft) {
		sum += *w & ntohs(0xFF00);
	}

	// add pseudo header
	nleft = 16;
	w = (uint16_t*) src;
	while (nleft > 0) {
		sum += *w++;
		nleft -= 2;
	}
	nleft = 16;
	w = (uint16_t*) dst;
	while (nleft > 0) {
		sum += *w++;
		nleft -= 2;
	}

	sum += htons(len);
	sum += htons(IPPROTO_ICMPV6);

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	sum = ~sum;

	return (uint16_t)sum;
}

int
ProcessICMPv6Packet(mtcp_manager_t mtcp, const struct icmpv6hdr* icmp,
		const struct in6_addr* src, const struct in6_addr* dst, int len, int nif)
{
	if (ICMPv6ComputeChecksum(icmp, src, dst, len)) {
		TRACE_ERROR("Bad ICMPv6 checksum!\n");
		return FALSE;
	}

	int bodylen = len - sizeof(struct icmpv6hdr);

	switch(icmp->type) {
	case ICMPV6_NS:
		if (icmp->code != 0) {
			return FALSE;
		}
		return ProcessNeighborSolicitation(mtcp, (struct nshdr*)icmp->payload, src, bodylen, nif);
	case ICMPV6_NA:
		if (icmp->code != 0) {
			return FALSE;
		}
		return ProcessNeighborAdvertisement(mtcp, (struct nahdr*)icmp->payload, bodylen, nif);
	}

	return FALSE;
}
