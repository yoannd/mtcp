/*
 * IPv6 support for mTCP
 * Author: Yoann Desmouceaux
 */

#include "mtcp.h"
#include "icmpv6.h"
#include "nd.h"
#include "ip6_out.h"
#include "debug.h"

#define ICMPV6_OPT_SOURCE_LLADDR 1
struct nshdr {
	uint32_t reserved;
	struct in6_addr target;
	uint8_t opt_type;
	uint8_t opt_length;
	u_char source_lladdr[ETH_ALEN];
};

#define NA_ROUTER 0x80000000
#define NA_SOLICITED 0x40000000
#define NA_OVERRIDE 0x20000000
#define ICMPV6_OPT_TARGET_LLADDR 2
#define ND_TIMEOUT_MSEC 1000

struct nahdr {
	uint32_t flags;
	struct in6_addr target;
	uint8_t opt_type;
	uint8_t opt_length;
	u_char source_lladdr[ETH_ALEN];
};

struct ns_pending_solicitation {
	struct in6_addr ip;
	int nif;
	uint32_t ts;
	TAILQ_ENTRY(ns_pending_solicitation) link;
};
TAILQ_HEAD(,ns_pending_solicitation) ns_pending_queue;

void
RemoveFromNSPendingQueue(const struct in6_addr* ip, int nif)
{
	struct ns_pending_solicitation* pending;
	TAILQ_FOREACH(pending, &ns_pending_queue, link) {
		if (!memcmp(&pending->ip, ip, sizeof(struct in6_addr)) && pending->nif == nif) {
			TAILQ_REMOVE(&ns_pending_queue, pending, link);
			free(pending);
			break;
		}
	}
}

void
AddToNSPendingQueue(const struct in6_addr* ip, int nif, uint32_t ts)
{
	struct ns_pending_solicitation* pending =
			(struct ns_pending_solicitation*) calloc(1, sizeof(struct ns_pending_solicitation));
	if (pending == NULL) {
		TRACE_ERROR("Unable to allocate node in NSPendingQueue!\n");
		return;
	}
	pending->ip = *ip;
	pending->nif = nif;
	pending->ts = ts;
	TAILQ_INSERT_TAIL(&ns_pending_queue, pending, link);
}

int
InitNDTable()
{
	CONFIG.nd.entries = 0;

	CONFIG.nd.entry = (struct nd_entry *) calloc(MAX_ND_ENTRIES, sizeof(struct nd_entry));
	if (CONFIG.nd.entry == NULL) {
		perror("calloc");
		return -1;
	}

	TAILQ_INIT(&ns_pending_queue);

	return 0;
}

int
IsInNDTable(const struct in6_addr* dip)
{
	return (GetDestinationHWaddrForIPv6(dip) != NULL);
}

int
AddToNDTable(const struct in6_addr* dip, const unsigned char* haddr)
{
	if (CONFIG.nd.entries >= MAX_ND_ENTRIES) {
		TRACE_ERROR("[WARNING] ND table full!\n");
		return FALSE;
	}

	memcpy(CONFIG.nd.entry[CONFIG.nd.entries].haddr, haddr, ETH_ALEN);
	CONFIG.nd.entry[CONFIG.nd.entries].prefix = 128;
	CONFIG.nd.entry[CONFIG.nd.entries++].ip = *dip;

	return TRUE;
}

void
ReplaceInNDTable(const struct in6_addr* dip, const unsigned char* haddr)
{
	int i;

	for (i = 0; i < CONFIG.nd.entries; i++) {
		if (IN6_ARE_ADDR_EQUAL(&CONFIG.nd.entry[i].ip, dip)) {
			memcpy(CONFIG.nd.entry[i].haddr, haddr, ETH_ALEN);
			return;
		}
	}
}

unsigned char*
GetDestinationHWaddrForIPv6(const struct in6_addr* dip)
{
	unsigned char *d_haddr = NULL;
	int i;
	int prefix = -1;

	/* Longest prefix matching */
	for (i = 0; i < CONFIG.nd.entries; i++) {
		if (CONFIG.nd.entry[i].prefix > prefix) {
			if (IPv6AddrMatchesPrefix(dip, &CONFIG.nd.entry[i].ip, CONFIG.nd.entry[i].prefix)) {
				d_haddr = CONFIG.nd.entry[i].haddr;
				prefix = CONFIG.nd.entry[i].prefix;
			}
		}
	}

	return d_haddr;
}

void
GetSolicitiedMulticastAddr(struct in6_addr* multicast_dst, const struct in6_addr* dst)
{
	multicast_dst->s6_addr32[0] = htonl(0xff020000);
	multicast_dst->s6_addr32[1] = htonl(0x00000000);
	multicast_dst->s6_addr32[2] = htonl(0x00000001);
	multicast_dst->s6_addr32[3] = htonl(0xff000000 | ntohl(dst->s6_addr32[3]));
}

void
SendNeighborSolicitation(mtcp_manager_t mtcp, const struct in6_addr* dst, int nif)
{
	struct in6_addr* src = &CONFIG.eths[nif].ip6_addr;
	struct in6_addr multicast_dst;
	GetSolicitiedMulticastAddr(&multicast_dst, dst);

	uint16_t len = sizeof(struct icmpv6hdr) + sizeof(struct nshdr);
	struct icmpv6hdr* icmp = (struct icmpv6hdr*)
			IPv6OutputMulticast(mtcp, src, &multicast_dst, IPPROTO_ICMPV6, len, nif);

	if (!icmp) {
		return;
	}
	icmp->type = ICMPV6_NS;
	icmp->code = 0;

	struct nshdr* ns = (struct nshdr*) icmp->payload;
	ns->reserved = 0;
	ns->target = *dst;
	ns->opt_type = ICMPV6_OPT_SOURCE_LLADDR;
	ns->opt_length = 1;
	memcpy(ns->source_lladdr, CONFIG.eths[nif].haddr, ETH_ALEN);

	icmp->checksum = 0;
	icmp->checksum = ICMPv6ComputeChecksum(icmp, src, &multicast_dst, len);


}

void
RequestNeighborSolicitation(mtcp_manager_t mtcp, const struct in6_addr* dst, int nif)
{
	/* Check whether request is already in progress */
	struct ns_pending_solicitation* pending;
	TAILQ_FOREACH(pending, &ns_pending_queue, link) {
		if (!memcmp(&pending->ip, dst, sizeof(struct in6_addr)) && pending->nif == nif) {
			return;
		}
	}

	SendNeighborSolicitation(mtcp, dst, nif);

	/* Add request to pending queue */
	AddToNSPendingQueue(dst, nif, mtcp->cur_ts);
}


void SendNeighborAdvertisement(mtcp_manager_t mtcp, const struct in6_addr* dst, int nif)
{
	uint16_t len = sizeof(struct icmpv6hdr) + sizeof(struct nahdr);
	struct in6_addr* src = &CONFIG.eths[nif].ip6_addr;
	struct icmpv6hdr* icmp = (struct icmpv6hdr*)
			IPv6OutputStandalone(mtcp, IPPROTO_ICMPV6, src, dst, len);

	if (!icmp) {
		return;
	}
	icmp->type = ICMPV6_NA;
	icmp->code = 0;

	struct nahdr* na = (struct nahdr*) icmp->payload;
	na->flags = htonl(NA_SOLICITED | NA_OVERRIDE);
	na->target = *src;
	na->opt_type = ICMPV6_OPT_TARGET_LLADDR;
	na->opt_length = 1;
	memcpy(na->source_lladdr, CONFIG.eths[nif].haddr, ETH_ALEN);

	icmp->checksum = 0;
	icmp->checksum = ICMPv6ComputeChecksum(icmp, src, dst, len);
}

int ProcessNeighborSolicitation(mtcp_manager_t mtcp, const struct nshdr* ns,
		const struct in6_addr* src, int len, int nif)
{
	if (len < sizeof(struct nshdr)) {
		return FALSE;
	}
	if (ns->opt_type != ICMPV6_OPT_SOURCE_LLADDR || ns->opt_length != 1) {
		return FALSE;
	}

	if (!IN6_ARE_ADDR_EQUAL(&ns->target, &CONFIG.eths[nif].ip6_addr)) {
		return FALSE;
	}

	if (!IsInNDTable(src)) {
		if (!AddToNDTable(src, ns->source_lladdr)) {
			return FALSE;
		}
	}

	SendNeighborAdvertisement(mtcp, src, nif);

	return TRUE;
}



int ProcessNeighborAdvertisement(mtcp_manager_t mtcp, const struct nahdr* na,
		int len, int nif)
{
	if (len < sizeof(struct nahdr)) {
		return FALSE;
	}
	if (na->opt_type != ICMPV6_OPT_TARGET_LLADDR || na->opt_length != 1) {
		return FALSE;
	}


	if (IsInNDTable(&na->target) && (ntohl(na->flags) & NA_OVERRIDE)) {
		ReplaceInNDTable(&na->target, na->source_lladdr);
		RemoveFromNSPendingQueue(&na->target, nif);
		return TRUE;
	}

	if (!IsInNDTable(&na->target)) {
		if (AddToNDTable(&na->target, na->source_lladdr)) {
			RemoveFromNSPendingQueue(&na->target, nif);
			return TRUE;
		}
	}

	return FALSE;
}

/* Periodically retransmit pending requests */
void NDTimer(mtcp_manager_t mtcp)
{
	struct ns_pending_solicitation* pending;
	TAILQ_FOREACH(pending, &ns_pending_queue, link) {
		if (TCP_SEQ_GT(mtcp->cur_ts, pending->ts + ND_TIMEOUT_MSEC)) {
			pending->ts = mtcp->cur_ts;
			SendNeighborSolicitation(mtcp, &pending->ip, pending->nif);
		}
	}
}
