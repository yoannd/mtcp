/* Tap module for mTCP.
 * (c) 2016 Yoann Desmouceaux
 */
/* for io_module_func def'ns */
#include "io_module.h"
#define ENABLE_TAP
#ifdef ENABLE_TAP
/* for mtcp related def'ns */
#include "mtcp.h"
/* for errno */
#include <errno.h>
/* for logging */
#include "debug.h"
/* for num_devices_* */
#include "config.h"
/* for poll */
#include <sys/poll.h>

/* for if_indextoname */
#include <net/if.h>
/* for open */
#include <fcntl.h>
/* for write */
#include <unistd.h>
/* for tap */
#include <sys/ioctl.h>
#include <linux/if_tun.h>
/*----------------------------------------------------------------------------*/
#define MAX_RX_BURST			64
#define MAX_TX_BURST			4
#define ETHERNET_FRAME_SIZE		1514
/*----------------------------------------------------------------------------*/

struct tap_private_context {
	int fds[MAX_DEVICES];
	char sndbuf[MAX_DEVICES][MAX_RX_BURST][ETHERNET_FRAME_SIZE];
	int sndlen[MAX_DEVICES][MAX_RX_BURST];
	int sndcnt[MAX_DEVICES];
	char rcvbuf[MAX_DEVICES][MAX_TX_BURST][ETHERNET_FRAME_SIZE];
	int rcvlen[MAX_DEVICES][MAX_TX_BURST];
} __attribute__((aligned(__WORDSIZE)));
/*----------------------------------------------------------------------------*/
void
tap_init_handle(struct mtcp_thread_context *ctxt)
{
	char ifname[IFNAMSIZ];
	int j;
	struct tap_private_context *tpc;
	int tapfd;
	struct ifreq ifr = {.ifr_flags = IFF_TAP | IFF_NO_PI,};

	/* create and initialize private I/O module context */
	ctxt->io_private_context = calloc(1, sizeof(struct tap_private_context));
	if (ctxt->io_private_context == NULL) {
		TRACE_ERROR("Failed to initialize ctxt->io_private_context: "
			    "Can't allocate memory\n");
		exit(EXIT_FAILURE);
	}

	tpc = (struct tap_private_context*) ctxt->io_private_context;

	/* initialize per-thread tap interfaces  */
	for (j = 0; j < num_devices_attached; j++) {
		if (if_indextoname(devices_attached[j], ifname) == NULL) {
			TRACE_ERROR("Failed to initialize interface %s with ifidx: %d - "
				    "error string: %s\n",
				    ifname, devices_attached[j], strerror(errno));
			exit(EXIT_FAILURE);
		}


		TRACE_INFO("Opening tap interface %s\n", ifname);

		if ((tapfd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0) {
			TRACE_ERROR("Unable to open /dev/net/tun for %s: %s\n",
					ifname, strerror(errno));
			exit(EXIT_FAILURE);
		}

		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

		if (ioctl(tapfd, TUNSETIFF, (void*) &ifr) < 0) {
			TRACE_ERROR("Unable to perform ioctl on /dev/net/tun for %s: %s\n",
					ifname, strerror(errno));
			exit(EXIT_FAILURE);
		}

		tpc->fds[j] = tapfd;

	}
}
/*----------------------------------------------------------------------------*/
int
tap_link_devices(struct mtcp_thread_context *ctxt)
{
	/* linking takes place during mtcp_init() */

	return 0;
}
/*----------------------------------------------------------------------------*/
void
tap_release_pkt(struct mtcp_thread_context *ctxt, int ifidx, unsigned char *pkt_data, int len)
{
	/*
	 * do nothing over here - memory reclamation
	 * will take place in dpdk_recv_pkts
	 */
}
/*----------------------------------------------------------------------------*/
int
tap_send_pkts(struct mtcp_thread_context *ctxt, int nif)
{
	int pkt_size, j;
	struct tap_private_context *tpc;

	tpc = (struct tap_private_context *)ctxt->io_private_context;

	for (j = 0; j < tpc->sndcnt[nif]; j++) {
		pkt_size = tpc->sndlen[nif][j];
		if (pkt_size == 0) continue;

		if (write(tpc->fds[nif], tpc->sndbuf[nif][j], pkt_size) < 0) {
			TRACE_ERROR("Failed to send pkt of size %d on interface %d: %s\n",
					pkt_size, nif, strerror(errno));
			return j;
		}

		tpc->sndlen[nif][j] = 0;
	}

	tpc->sndcnt[nif] = 0;
	return j;
}
/*----------------------------------------------------------------------------*/
uint8_t *
tap_get_wptr(struct mtcp_thread_context *ctxt, int nif, uint16_t pktsize)
{
	struct tap_private_context *tpc;

	tpc = (struct tap_private_context *)ctxt->io_private_context;

	if (tpc->sndcnt[nif] == MAX_TX_BURST) {
		tap_send_pkts(ctxt, nif);
	}

	tpc->sndlen[nif][tpc->sndcnt[nif]] = pktsize;

	return (uint8_t *)tpc->sndbuf[nif][tpc->sndcnt[nif]++];
}
/*----------------------------------------------------------------------------*/
int32_t
tap_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx)
{
	struct tap_private_context *tpc;
	int rd, j;

	tpc = (struct tap_private_context *)ctxt->io_private_context;

	for (j = 0; j < MAX_RX_BURST; j++) {

		if ((rd = read(tpc->fds[ifidx], tpc->rcvbuf[ifidx][j], ETHERNET_FRAME_SIZE)) < 0) {
			if (errno == EAGAIN) {
				break;
			} else {
				TRACE_ERROR("Failed to read packet from interface %d: %s\n",
						ifidx, strerror(errno));
				return j;
			}
		}

		tpc->rcvlen[ifidx][j] = rd;
	}

	return j;
}
/*----------------------------------------------------------------------------*/
uint8_t *
tap_get_rptr(struct mtcp_thread_context *ctxt, int ifidx, int index, uint16_t *len)
{
	struct tap_private_context *tpc;
	tpc = (struct tap_private_context *)ctxt->io_private_context;

	*len = tpc->rcvlen[ifidx][index];
	return (unsigned char *)tpc->rcvbuf[ifidx][index];
}
/*----------------------------------------------------------------------------*/
int32_t
tap_select(struct mtcp_thread_context *ctxt)
{
	return 0;
}
/*----------------------------------------------------------------------------*/
void
tap_destroy_handle(struct mtcp_thread_context *ctxt)
{
}
/*----------------------------------------------------------------------------*/
void
tap_load_module(void)
{
	/* not needed - all initializations done in tap_init_handle() */
}
/*----------------------------------------------------------------------------*/
io_module_func tap_module_func = {
	.load_module		   = tap_load_module,
	.init_handle		   = tap_init_handle,
	.link_devices		   = tap_link_devices,
	.release_pkt		   = tap_release_pkt,
	.send_pkts		   = tap_send_pkts,
	.get_wptr   		   = tap_get_wptr,
	.recv_pkts		   = tap_recv_pkts,
	.get_rptr	   	   = tap_get_rptr,
	.select			   = tap_select,
	.destroy_handle		   = tap_destroy_handle
};
/*----------------------------------------------------------------------------*/
#else
io_module_func tap_module_func = {
	.load_module		   = NULL,
	.init_handle		   = NULL,
	.link_devices		   = NULL,
	.release_pkt		   = NULL,
	.send_pkts		   = NULL,
	.get_wptr   		   = NULL,
	.recv_pkts		   = NULL,
	.get_rptr	   	   = NULL,
	.select			   = NULL,
	.destroy_handle		   = NULL
};
/*----------------------------------------------------------------------------*/
#endif /* ENABLE_TAP */
