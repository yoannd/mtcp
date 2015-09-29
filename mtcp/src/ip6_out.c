/*
 * IPv6 support for mTCP
 * Author: Yoann Desmouceaux
 */

#include "ip6_out.h"
#include "ip_out.h"
#include "eth_out.h"
#include "nd.h"
#include "debug.h"
#include <linux/ipv6.h>

inline int IPv6AddrMatchesPrefix(const struct in6_addr* addr,
		const struct in6_addr* net, int prefix)
{
	assert(prefix >= 0 && prefix <= 128);
	int i;
	uint32_t mask;

	for (i = 0; i < 4 && prefix > 0; i++, prefix -= 32) {
		mask = 0xffffffff;
		if (prefix < 32) {
			mask <<= 32 - prefix;
		}
		if ((addr->s6_addr32[i] ^ net->s6_addr32[i]) & mask) {
			return FALSE;
		}
	}

	return TRUE;
}

int
GetOutputInterfaceIPv6(const struct in6_addr* daddr)
{
	int nif = -1;
	int i;
	int prefix = -1;
	/* Longest prefix matching */
	for (i = 0; i < CONFIG.routes6; i++) {
		if (CONFIG.rtable6[i].prefix > prefix) {
			if (IPv6AddrMatchesPrefix(daddr, &CONFIG.rtable6[i].daddr, CONFIG.rtable6[i].prefix)) {
				nif = CONFIG.rtable6[i].nif;
				prefix = CONFIG.rtable6[i].prefix;
			}
		}
	}

	if (nif < 0) {
		const uint8_t *da = daddr->s6_addr;
		TRACE_ERROR("[WARNING] No route to %02x%02x:%02x%02x:%02x%02x:%02x%02x:"
				"%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				da[0], da[1], da[2], da[3], da[4], da[5], da[6], da[7],
				da[8], da[9], da[10], da[11], da[12], da[13], da[14], da[15]);
		assert(0);
	}
	return nif;
}

uint8_t*
IPv6OutputStandalone(struct mtcp_manager *mtcp, uint8_t protocol,
		const struct in6_addr* saddr, const struct in6_addr* daddr,
		uint16_t payloadlen)
{
	struct ipv6hdr* iph;
	int nif;
	unsigned char* haddr;

	nif = GetOutputInterfaceIPv6(daddr);
	if (nif < 0) {
		return NULL;
	}

	haddr = GetDestinationHWaddrForIPv6(daddr);
	if (!haddr) {
		RequestNeighborSolicitation(mtcp, daddr, nif);
		return NULL;
	}

	iph = (struct ipv6hdr*) EthernetOutput(mtcp, ETH_P_IPV6, nif, haddr,
			payloadlen + IPV6_HEADER_LEN);
	if (!iph) {
		return NULL;
	}

	iph->version = 6;
	iph->priority = 0;
	memset(&iph->flow_lbl, 0, sizeof(iph->flow_lbl));
	iph->payload_len = htons(payloadlen);
	iph->nexthdr = protocol;
	iph->hop_limit = (protocol == IPPROTO_ICMPV6) ? 255 : 64;
	iph->saddr = *saddr;
	iph->daddr = *daddr;


	return (uint8_t*)(iph + 1);
}

void
GetMulticastHWaddr(unsigned char* haddr, const struct in6_addr* dst)
{
	haddr[0] = 0x33;
	haddr[1] = 0x33;
	memcpy(haddr + 2, &dst->s6_addr32[3], sizeof(uint32_t));
}

uint8_t*
IPv6OutputMulticast(struct mtcp_manager *mtcp,
		const struct in6_addr* src, const struct in6_addr* dst,
		uint8_t protocol, uint16_t payloadlen, int nif)
{
	struct ipv6hdr* iph;
	unsigned char haddr[ETH_ALEN];

	GetMulticastHWaddr(haddr, dst);

	iph = (struct ipv6hdr*) EthernetOutput(mtcp, ETH_P_IPV6, nif, haddr,
			payloadlen + IPV6_HEADER_LEN);
	if (!iph) {
		return NULL;
	}

	iph->version = 6;
	iph->priority = 0;
	memset(&iph->flow_lbl, 0, sizeof(iph->flow_lbl));
	iph->payload_len = htons(payloadlen);
	iph->nexthdr = protocol;
	iph->hop_limit = 255;
	iph->saddr = *src;
	iph->daddr = *dst;

	return (uint8_t*)(iph + 1);
}

uint8_t*
IPv6Output(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen)
{
	struct ipv6hdr* iph;
	int nif;
	unsigned char* haddr;

	if (stream->sndvar->nif_out >= 0) {
		nif = stream->sndvar->nif_out;
	} else {
		nif = GetOutputInterfaceIPv6(&stream->daddr6.sin6_addr);
		stream->sndvar->nif_out = nif;
	}

	haddr = GetDestinationHWaddrForIPv6(&stream->daddr6.sin6_addr);
	if (!haddr) {
		RequestNeighborSolicitation(mtcp, &stream->daddr6.sin6_addr, nif);
		return NULL;
	}

	iph = (struct ipv6hdr*) EthernetOutput(mtcp, ETH_P_IPV6, nif, haddr,
			tcplen + IPV6_HEADER_LEN);
	if (!iph) {
		return NULL;
	}

	iph->version = 6;
	iph->priority = 0;
	memset(&iph->flow_lbl, 0, sizeof(iph->flow_lbl));
	iph->payload_len = htons(tcplen);
	iph->nexthdr = IPPROTO_TCP;
	iph->hop_limit = 64;
	memcpy(&iph->saddr, &stream->saddr6.sin6_addr, sizeof(struct in6_addr));
	memcpy(&iph->daddr, &stream->daddr6.sin6_addr, sizeof(struct in6_addr));

	return (uint8_t*)(iph + 1);
}
