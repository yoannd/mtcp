#ifndef __IP6_OUT_H_
#define __IP6_OUT_H_

#include <stdint.h>
#include "tcp_stream.h"

#define IPV6_HEADER_LEN 40 //sizeof(struct ipv6hdr)

inline int IPv6AddrMatchesPrefix(const struct in6_addr* addr,
		const struct in6_addr* net, int prefix);

int
GetOutputInterfaceIPv6(const struct in6_addr* daddr);

uint8_t*
IPv6OutputStandalone(struct mtcp_manager *mtcp, uint8_t protocol,
		const struct in6_addr* saddr, const struct in6_addr* daddr,
		uint16_t payloadlen);

uint8_t*
IPv6OutputMulticast(struct mtcp_manager *mtcp,
		const struct in6_addr* src, const struct in6_addr* dst,
		uint8_t protocol, uint16_t payloadlen, int nif);

uint8_t*
IPv6Output(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen);

#endif /* __IP6_OUT_H_ */
