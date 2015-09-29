#ifndef __ADDR_POOL_H_
#define __ADDR_POOL_H_

#include <netinet/in.h>
#include <sys/queue.h>

/*----------------------------------------------------------------------------*/
typedef struct addr_pool *addr_pool_t;
/*----------------------------------------------------------------------------*/
/* CreateAddressPool()														  */
/* Create address pool for given address range.							      */
/* addr_base: the base address in network order.							  */
/* num_addr: number of addresses to use as source IP						  */
/*----------------------------------------------------------------------------*/
addr_pool_t 
CreateAddressPool(const struct sockaddr* addr_base, int num_addr);
/*----------------------------------------------------------------------------*/
/* CreateAddressPoolPerCore()												  */
/* Create address pool only for the given core number.						  */
/* All addresses and port numbers should be in network order.				  */
/*----------------------------------------------------------------------------*/
addr_pool_t
CreateAddressPoolPerCore(int core, int num_queues,
		const struct sockaddr* saddr_base, int num_addr, const struct sockaddr* daddr);
/*----------------------------------------------------------------------------*/
void
DestroyAddressPool(addr_pool_t ap);
/*----------------------------------------------------------------------------*/
int
FetchAddress(addr_pool_t ap, int core, int num_queues,
		const struct sockaddr *daddr, struct sockaddr *saddr);
/*----------------------------------------------------------------------------*/
int 
FreeAddress(addr_pool_t ap, const struct sockaddr *addr);
/*----------------------------------------------------------------------------*/

#endif /* __ADDR_POOL_H_ */
