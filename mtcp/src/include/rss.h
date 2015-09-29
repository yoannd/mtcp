#ifndef __RSS_H_
#define __RSS_H_

#include <netinet/in.h>

int
GetRSSCPUCore(const struct sockaddr* saddr, const struct sockaddr* daddr,
		int num_queues, uint8_t endian_check);

#endif /* __RSS_H_ */
