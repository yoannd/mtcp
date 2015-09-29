#ifndef __IP6_IN_H_
#define __IP6_IN_H_

#include "mtcp.h"

int
ProcessIPv6Packet(mtcp_manager_t mtcp, uint32_t cur_ts,
				  const int ifidx, unsigned char* pkt_data, int len);

#endif /* __IP6_IN_H_ */
