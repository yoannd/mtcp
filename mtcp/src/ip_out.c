#include "ip_out.h"
#include "ip_in.h"
#include "eth_out.h"
#include "arp.h"
#include "ip6_out.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
inline int
GetOutputInterfaceIPv4(uint32_t ip)
{
	int nif = -1;
	int i;
	int prefix = 0;
	/* Longest prefix matching */
	for (i = 0; i < CONFIG.routes; i++) {
		if ((ip & CONFIG.rtable[i].mask) == CONFIG.rtable[i].masked) {
			if (CONFIG.rtable[i].prefix > prefix) {
				nif = CONFIG.rtable[i].nif;
				prefix = CONFIG.rtable[i].prefix;
			}
		}
	}

	if (nif < 0) {
		uint8_t *da = (uint8_t *)&ip;
		TRACE_ERROR("[WARNING] No route to %u.%u.%u.%u\n",
				da[0], da[1], da[2], da[3]);
		assert(0);
	}
	return nif;
}
/*----------------------------------------------------------------------------*/
inline int
GetOutputInterface(const struct sockaddr* daddr)
{
	if (daddr->sa_family == AF_INET) {
		return GetOutputInterfaceIPv4(((struct sockaddr_in*)daddr)->sin_addr.s_addr);

	} else if (daddr->sa_family == AF_INET6) {
		return GetOutputInterfaceIPv6(&((struct sockaddr_in6*)daddr)->sin6_addr);
	} else {
		assert(0);
		return -1;
	}
}
/*----------------------------------------------------------------------------*/
uint8_t *
IPOutputStandalone(struct mtcp_manager *mtcp, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t payloadlen)
{
	struct iphdr *iph;
	int nif;
	unsigned char * haddr;

	nif = GetOutputInterfaceIPv4(saddr);
	if (nif < 0)
		return NULL;

	haddr = GetDestinationHWaddr(daddr);
	if (!haddr) {
#if 0
		uint8_t *da = (uint8_t *)&daddr;
		TRACE_INFO("[WARNING] The destination IP %u.%u.%u.%u "
				"is not in ARP table!\n",
				da[0], da[1], da[2], da[3]);
#endif
		RequestARP(mtcp, daddr, nif, mtcp->cur_ts);
		return NULL;
	}
	
	iph = (struct iphdr *)EthernetOutput(mtcp, 
			ETH_P_IP, nif, haddr, payloadlen + IP_HEADER_LEN);
	if (!iph) {
		return NULL;
	}

	iph->ihl = IP_HEADER_LEN >> 2;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(IP_HEADER_LEN + payloadlen);
	iph->id = htons(ip_id);
	iph->frag_off = htons(IP_DF);	// no fragmentation
	iph->ttl = 64;
	iph->protocol = protocol;
	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	return (uint8_t *)(iph + 1);
}
/*----------------------------------------------------------------------------*/
uint8_t *
IPOutput(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen)
{
	struct iphdr *iph;
	int nif;
	unsigned char *haddr;

	if (stream->sndvar->nif_out >= 0) {
		nif = stream->sndvar->nif_out;
	} else {
		nif = GetOutputInterfaceIPv4(stream->daddr4.sin_addr.s_addr);
		stream->sndvar->nif_out = nif;
	}

	haddr = GetDestinationHWaddr(stream->daddr4.sin_addr.s_addr);
	if (!haddr) {
#if 0
		uint8_t *da = (uint8_t *)&stream->daddr;
		TRACE_INFO("[WARNING] The destination IP %u.%u.%u.%u "
				"is not in ARP table!\n",
				da[0], da[1], da[2], da[3]);
#endif
		/* if not found in the arp table, send arp request and return NULL */
		/* tcp will retry sending the packet later */
		RequestARP(mtcp, stream->daddr4.sin_addr.s_addr, stream->sndvar->nif_out, mtcp->cur_ts);
		return NULL;
	}
	
	iph = (struct iphdr *)EthernetOutput(mtcp, ETH_P_IP, 
			stream->sndvar->nif_out, haddr, tcplen + IP_HEADER_LEN);
	if (!iph) {
		return NULL;
	}

	iph->ihl = IP_HEADER_LEN >> 2;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(IP_HEADER_LEN + tcplen);
	iph->id = htons(stream->sndvar->ip_id++);
	iph->frag_off = htons(0x4000);	// no fragmentation
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = stream->saddr4.sin_addr.s_addr;
	iph->daddr = stream->daddr4.sin_addr.s_addr;
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	return (uint8_t *)(iph + 1);
}
