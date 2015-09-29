#ifndef __IP_OUT_H_
#define __IP_OUT_H_

#include <stdint.h>
#include "tcp_stream.h"

inline int 
GetOutputInterface(const struct sockaddr* daddr);

void
ForwardIPv4Packet(mtcp_manager_t mtcp, int nif_in, char *buf, int len);

uint8_t *
IPOutputStandalone(struct mtcp_manager *mtcp, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t payloadlen);

uint8_t *
IPOutput(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen);

#endif /* __IP_OUT_H_ */
