#ifndef __ICMPV6_H_
#define __ICMPV6_H_

#define ICMPV6_NS 135
#define ICMPV6_NA 136

struct icmpv6hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    u_char payload[0];
} __attribute__ ((packed));

uint16_t ICMPv6ComputeChecksum(const struct icmpv6hdr* icmp, const struct in6_addr* src,
        const struct in6_addr* dst, uint16_t len);

int ProcessICMPv6Packet(mtcp_manager_t mtcp, const struct icmpv6hdr* icmp,
        const struct in6_addr* src, const struct in6_addr* dst, int len, int nif);

#endif /* __ICMPV6_H_ */
