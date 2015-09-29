/*
 * IPv6 support for mTCP
 * Author: Yoann Desmouceaux
 */

#include "ip6_in.h"
#include "tcp_in.h"
#include "debug.h"
#include "icmpv6.h"
#include <linux/ipv6.h>
#include <netinet/in.h>

/*----------------------------------------------------------------------------*/
inline int 
ProcessIPv6Packet(mtcp_manager_t mtcp, uint32_t cur_ts,
				  const int ifidx, unsigned char* pkt_data, int len)
{
	struct ipv6hdr* iph = (struct ipv6hdr*)(pkt_data + sizeof(struct ethhdr));

	if (len < sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) {
		return ERROR;
	}

	if (iph->version != 6) {
		mtcp->iom->release_pkt(mtcp->ctx, ifidx, pkt_data, len);
		return FALSE;
	}
	
	if (iph->hop_limit == 0) {
		/* TODO send ICMPv6 hop limit exceeded */
		return FALSE;
	}



	switch (iph->nexthdr) {
		case IPPROTO_TCP:
		{
			struct tcphdr* tcph = (struct tcphdr*) ((char*)iph + sizeof(struct ipv6hdr));
			int tcplen = ntohs(iph->payload_len);
			struct sockaddr_in6 saddr, daddr;
			saddr.sin6_family = AF_INET6;
			saddr.sin6_addr = iph->saddr;
			daddr.sin6_family = AF_INET6;
			daddr.sin6_addr = iph->daddr;
			return ProcessTCPPacket(mtcp, cur_ts, tcph, tcplen,
					(struct sockaddr*)&saddr, (struct sockaddr*)&daddr);
		}
		case IPPROTO_ICMPV6:
		{
			struct icmpv6hdr* icmp = (struct icmpv6hdr*) ((char*)iph + sizeof(struct ipv6hdr));
			int icmplen = ntohs(iph->payload_len);
			return ProcessICMPv6Packet(mtcp, icmp, &iph->saddr, &iph->daddr, icmplen, ifidx);
		}
		default:
			/* currently drop other protocols */
			return FALSE;
	}
	return FALSE;
}
/*----------------------------------------------------------------------------*/
