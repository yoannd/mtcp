/* ssvm module for mTCP.
 * (c) 2016 Yoann Desmouceaux
 */
/* for ppoll */
#define _GNU_SOURCE

/* for io_module_func def'ns */
#include "io_module.h"
#define ENABLE_ssvm
#ifdef ENABLE_ssvm
/* for mtcp related def'ns */
#include "mtcp.h"
/* for errno */
#include <errno.h>
/* for logging */
#include "debug.h"
/* for num_devices_* */
#include "config.h"
/* for if_indextoname */
#include <net/if.h>
/* for mmap */
#include <sys/mman.h>
/* for getpid */
#include <unistd.h>
/* for O_RDWR */
#include <fcntl.h>

#define __sync_synchronize() asm volatile ("" : : : "memory")
#include "ssvm_module.h"

/*----------------------------------------------------------------------------*/
#define MAX_TX_PKT_BURST 32
#define MAX_RX_PKT_BURST 32
#define SSVM_MAX_DEVICES 4
#define TRACE_SSVM(args...) //fprintf(stderr, args)
struct ssvm_private_context {
	ssvm_shared_header_t *sh[SSVM_MAX_DEVICES];
	uint32_t sndbuf[SSVM_MAX_DEVICES][MAX_TX_PKT_BURST]; //chunk indices
	int to_send[SSVM_MAX_DEVICES];
	uint32_t rcvbuf[SSVM_MAX_DEVICES][MAX_RX_PKT_BURST]; //chunk indices
	int rcvd[SSVM_MAX_DEVICES];
	int ssvm_is_master[SSVM_MAX_DEVICES];
	int pid;
} __attribute__((aligned(__WORDSIZE)));
/*----------------------------------------------------------------------------*/
static inline int
ssvm_allocate_chunks(struct mtcp_thread_context *ctxt, int nif, uint32_t to_allocate)
{
	struct ssvm_private_context *spc;
	ssvm_shared_header_t *sh;
	uint32_t *elt_indices;
	uint32_t available;

	spc = (struct ssvm_private_context *)ctxt->io_private_context;
	sh = spc->sh[nif];

	ssvm_lock(sh, spc->pid, 1);
	elt_indices = (uint32_t *) (sh->opaque[CHUNK_POOL_FREELIST_INDEX]);
	available = (uint32_t) (uint64_t) (sh->opaque[CHUNK_POOL_NFREE]);

	if (available < to_allocate || to_allocate > MAX_TX_PKT_BURST) {
		TRACE_ERROR("Failed to allocate %d chunks on ssvm device %d!\n",
			    to_allocate, nif);
		ssvm_unlock(sh);
		exit(EXIT_FAILURE);
	}

	/* grab the to_allocate last available chunks and put them in the send buffer */
	memcpy(spc->sndbuf[nif], elt_indices + (available - to_allocate),
			to_allocate * sizeof(uint32_t));


	sh->opaque[CHUNK_POOL_NFREE] = (void *) (uint64_t) (available - to_allocate);
	ssvm_unlock(sh);

	TRACE_SSVM("allocate(nif=%d): to_allocate=%d, available_old=%d, available_new=%d\n",
			nif, to_allocate, available, (available - to_allocate));


	return to_allocate;
}
/*----------------------------------------------------------------------------*/
static inline int
ssvm_release_chunks(struct mtcp_thread_context *ctxt, int nif, uint32_t to_release,
				    uint32_t* buf)
{
	struct ssvm_private_context *spc;
	ssvm_shared_header_t *sh;
	uint32_t *elt_indices;
	uint32_t available;

	spc = (struct ssvm_private_context *)ctxt->io_private_context;
	sh = spc->sh[nif];

	ssvm_lock(sh, spc->pid, 1);
	elt_indices = (uint32_t *) (sh->opaque[CHUNK_POOL_FREELIST_INDEX]);
	available = (uint32_t) (uint64_t) (sh->opaque[CHUNK_POOL_NFREE]);

	/* grab the to_release first chunks from the rcvbuf and give them back */
	memcpy(elt_indices + available, buf, to_release * sizeof(uint32_t));


	sh->opaque[CHUNK_POOL_NFREE] = (void *) (uint64_t) (available + to_release);
	ssvm_unlock(sh);

	TRACE_SSVM("release(nif=%d): to_release=%d, available_old=%d, available_new=%d\n",
			nif, to_release, available, (available + to_release));


	return to_release;
}
/*----------------------------------------------------------------------------*/
void
ssvm_init_handle(struct mtcp_thread_context *ctxt)
{
	char ifname[IFNAMSIZ];
	char shm_name[IFNAMSIZ];
	char* seek;
	int nif;
	int ssvmfd;
	struct ssvm_private_context *spc;
	ssvm_shared_header_t *sh;

	/* create and initialize private I/O module context */
	ctxt->io_private_context = calloc(1, sizeof(struct ssvm_private_context));
	if (ctxt->io_private_context == NULL) {
		TRACE_ERROR("Failed to initialize ctxt->io_private_context: "
			    "Can't allocate memory\n");
		exit(EXIT_FAILURE);
	}

	spc = (struct ssvm_private_context*) ctxt->io_private_context;
	spc->pid = getpid();

	/* initialize per-thread ssvm interfaces  */
	for (nif = 0; nif < num_devices_attached; nif++) {
		if (nif > SSVM_MAX_DEVICES) {
			TRACE_ERROR("Failed to initialize interface %s with ifidx: %d - "
				    "too many ssvm devices\n",
				    ifname, devices_attached[nif]);
			exit(EXIT_FAILURE);
		}

		if (if_indextoname(devices_attached[nif], ifname) == NULL) {
			TRACE_ERROR("Failed to initialize interface %s with ifidx: %d - "
				    "error string: %s\n",
				    ifname, devices_attached[nif], strerror(errno));
			exit(EXIT_FAILURE);
		}
		/* Determine the shared memory file name based on the interface name.
		 * If the interface name ends up with -xyz, don't take xyz into account.
		 * This way, we can run a server app on tap0-0 and a client app on tap0-1,
		 * both will communicate over the shared memory /dev/shm/tap0 while relying
		 * on different tap interfaces to get configured.
		 * Furthermore, we take -0 as a hint the the interface is master.
		 */
		memcpy(shm_name, ifname, IFNAMSIZ);
		if ((seek = memchr(shm_name, '-', IFNAMSIZ))) {
			*seek = '\0';
			if (seek + 1 < shm_name + IFNAMSIZ && *(seek + 1) == '0') {
				spc->ssvm_is_master[nif] = 1;
			}
		}

		TRACE_INFO("Opening ssvm interface %s\n", ifname);

		if (spc->ssvm_is_master[nif]) {
#define SSVM_MEM_SIZE (8 << 21)
#define SSVM_BASE_ADDR 0x600000000ULL
#define SSVM_Q_SIZE 512
#define SSVM_NB_CHUNKS 1024
			/* master ssvm initialization */
		    char* heap_ptr;
		    unix_shared_memory_queue_t *q;
		    uint32_t *chunk_indices;
		    int i;
		    spc->ssvm_is_master[nif] = 1;

			/* open shared memory file */
			if (shm_unlink(shm_name) < 0) {
				perror("unlink");
			}
			if ((ssvmfd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0777)) < 0) {
				TRACE_ERROR("Failed to open shared memory file for interface %s: %s\n",
					    ifname, strerror(errno));
				exit(EXIT_FAILURE);
			}

			/* setting file size */
			if (ftruncate(ssvmfd, SSVM_MEM_SIZE) < 0) {
				TRACE_ERROR("Failed to set size of shared memory file for interface %s: %s\n",
					    ifname, strerror(errno));
			}

			/* memory mapping */
			if ((sh = mmap((void*)SSVM_BASE_ADDR, SSVM_MEM_SIZE,
					            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
								ssvmfd, 0)) == MAP_FAILED) {
				TRACE_ERROR("Failed to map shared memory for interface %s: %s\n",
					    ifname, strerror(errno));
				exit(EXIT_FAILURE);
			}

			/* initialization of variables and heap */
			sh->master_pid = spc->pid;
		    sh->ssvm_va = SSVM_BASE_ADDR;
		    sh->ssvm_size = SSVM_MEM_SIZE;
		    heap_ptr = sh->heap = (char*)sh + MMAP_PAGESIZE;

		    /* creation of slave-to-master queue */
		    q = (unix_shared_memory_queue_t*)heap_ptr;
		    q->head = q->tail = q->cursize = 0;
		    q->elsize = sizeof(uint32_t);
		    q->maxsize = SSVM_Q_SIZE;
		    sh->opaque[TO_MASTER_Q_INDEX] = (void *)q;
		    heap_ptr += sizeof(unix_shared_memory_queue_t) + SSVM_Q_SIZE*sizeof(uint32_t);

		    /* creation of slave-to-master queue */
		    q = (unix_shared_memory_queue_t*)heap_ptr;
		    q->head = q->tail = q->cursize = 0;
		    q->elsize = sizeof(uint32_t);
		    q->maxsize = SSVM_Q_SIZE;
		    sh->opaque[TO_SLAVE_Q_INDEX] = (void *)q;
		    heap_ptr += sizeof(unix_shared_memory_queue_t) + SSVM_Q_SIZE*sizeof(uint32_t);

		    /* creation of chunk pool */
		    sh->opaque[CHUNK_POOL_INDEX] = heap_ptr;
		    heap_ptr += SSVM_NB_CHUNKS*sizeof(ssvm_eth_queue_elt_t);

		    /* creation of free chunk pool (referenced by indices) */
		    sh->opaque[CHUNK_POOL_FREELIST_INDEX] = heap_ptr;
		    chunk_indices = (uint32_t*)heap_ptr;
		    for (i = 0; i < SSVM_NB_CHUNKS; i++) {
		    	chunk_indices[i] = i;
		    }
		    sh->opaque [CHUNK_POOL_NFREE] = (void *)(uint64_t) SSVM_NB_CHUNKS;
		    heap_ptr += SSVM_NB_CHUNKS*sizeof(uint32_t);

		    /* setting interface up */
		    sh->opaque[SLAVE_ADMIN_STATE_INDEX] = (void *)(uint64_t) 0;
		    sh->opaque[MASTER_ADMIN_STATE_INDEX] = (void *)(uint64_t) 1;
		    __sync_synchronize();
		    sh->ready = 1;

		    TRACE_INFO("Waiting for slave to come up...\n");
		    while ((uint64_t)(sh->opaque[SLAVE_ADMIN_STATE_INDEX]) == 0) {
		    	usleep(1000);
		    }

		} else {
			/* slave initialization */
			/* open shared memory file */
			if ((ssvmfd = shm_open(shm_name, O_RDWR, 0777)) < 0) {
				TRACE_ERROR("Failed to open shared memory file for interface %s: %s\n",
						ifname, strerror(errno));
				exit(EXIT_FAILURE);
			}

			/* first mmap to learn relevant addresses/sizes */
			if ((sh = mmap (0, MMAP_PAGESIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
					ssvmfd, 0)) == MAP_FAILED) {
				TRACE_ERROR("Failed to map shared memory for interface %s: %s\n",
						ifname, strerror(errno));
				exit(EXIT_FAILURE);
			}

		    TRACE_INFO("Waiting for master to come up...\n");
			while (!sh->ready) {
				usleep(1000);
			}

			/* actual mmap */
			if ((sh = mmap((void*)sh->ssvm_va, sh->ssvm_size,
					PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
					ssvmfd, 0)) == MAP_FAILED) {
				TRACE_ERROR("Failed to map actual shared memory for interface %s: %s\n",
						ifname, strerror(errno));
				exit(EXIT_FAILURE);
			}

			sh->slave_pid = spc->pid;
			sh->opaque[SLAVE_ADMIN_STATE_INDEX] = (void *)(uint64_t) 1;
		}

		spc->sh[nif] = sh;

		/* allocate chunk for send buffer */
		ssvm_allocate_chunks(ctxt, nif, MAX_TX_PKT_BURST);

	}
}
/*----------------------------------------------------------------------------*/
int
ssvm_link_devices(struct mtcp_thread_context *ctxt)
{
	/* linking takes place during mtcp_init() */

	return 0;
}
/*----------------------------------------------------------------------------*/
void
ssvm_release_pkt(struct mtcp_thread_context *ctxt, int ifidx, unsigned char *pkt_data, int len)
{
	/*
	 * do nothing over here - memory reclamation
	 * will take place in ssvm_recv_pkts
	 */
}
/*----------------------------------------------------------------------------*/
int
ssvm_send_pkts(struct mtcp_thread_context *ctxt, int nif)
{
	struct ssvm_private_context *spc;
	ssvm_shared_header_t *sh;
	unix_shared_memory_queue_t *q;
	volatile uint32_t *queue_lock;
	int snt;

	TRACE_SSVM("send(nif=%d): ts=%d\n", nif, ctxt->mtcp_manager->cur_ts);

	spc = (struct ssvm_private_context *)ctxt->io_private_context;
	sh = spc->sh[nif];

	if (unlikely((!spc->ssvm_is_master[nif] && (uint64_t)(sh->opaque[MASTER_ADMIN_STATE_INDEX]) == 0)
			|| (spc->ssvm_is_master[nif] && (uint64_t)(sh->opaque[SLAVE_ADMIN_STATE_INDEX]) == 0))) {
		TRACE_ERROR("Peer is down when sending to interface: %d\n", nif);
		return 0;
	}

	if (spc->to_send[nif] == 0) {
		return 0;
	}

	q = spc->ssvm_is_master[nif] ? (unix_shared_memory_queue_t *)sh->opaque[TO_SLAVE_Q_INDEX] :
			(unix_shared_memory_queue_t *)sh->opaque[TO_MASTER_Q_INDEX];
	queue_lock = (uint32_t *) q;

	/* send the packets */
	TRACE_SSVM("send(nif=%d): to_send=%d\n", nif, spc->to_send[nif]);

	for (snt = 0; snt < spc->to_send[nif]; snt++) {
		uint32_t chunk_idx = spc->sndbuf[nif][snt];

		TRACE_SSVM("send(nif=%d): snt=%d, chunk_idx=%d\n", nif, snt, chunk_idx);
		if (q->cursize == q->maxsize) {
			break;
		}
	    while (__sync_lock_test_and_set (queue_lock, 1));
	    unix_shared_memory_queue_add_raw (q, (uint8_t *)&chunk_idx);
	    __sync_synchronize();
	    *queue_lock = 0;
	}


	/* allocate free chunks for subsequent calls to get_wptr() */
	ssvm_allocate_chunks(ctxt, nif, snt);

	spc->to_send[nif] = 0;

	return snt;
}
/*----------------------------------------------------------------------------*/
uint8_t *
ssvm_get_wptr(struct mtcp_thread_context *ctxt, int nif, uint16_t pktsize)
{
	struct ssvm_private_context *spc;
	ssvm_shared_header_t *sh;
	ssvm_eth_queue_elt_t *elts, *elt;

	spc = (struct ssvm_private_context *)ctxt->io_private_context;
	if (spc->to_send[nif] == MAX_TX_PKT_BURST) {
		ssvm_send_pkts(ctxt, nif);
	}


	sh = spc->sh[nif];
	elts = (ssvm_eth_queue_elt_t *) (sh->opaque[CHUNK_POOL_INDEX]);
	elt = elts + spc->sndbuf[nif][spc->to_send[nif]];


    elt->type = SSVM_PACKET_TYPE;
    elt->flags = 0;
    elt->total_length_not_including_first_buffer = 0;
    elt->length_this_buffer = pktsize;
    elt->current_data_hint = 0;
    elt->owner = 1;
    elt->tag = 1;



#ifdef NETSTAT
	ctxt->mtcp_manager->nstat.tx_packets[nif]++;
	ctxt->mtcp_manager->nstat.tx_bytes[nif] += pktsize + 24;
#endif
	TRACE_SSVM("get_wptr(nif=%d): to_send=%d, chunk_idx=%d, elt=%p\n",
			nif, spc->to_send[nif], spc->sndbuf[nif][spc->to_send[nif]], elt);

    spc->to_send[nif]++;

	return elt->data;
}
/*----------------------------------------------------------------------------*/
int32_t
ssvm_recv_pkts(struct mtcp_thread_context *ctxt, int nif)
{
	struct ssvm_private_context *spc;
	ssvm_shared_header_t *sh;
	unix_shared_memory_queue_t *q;
	uint32_t *queue_lock;
	uint32_t elt_index;

	TRACE_SSVM("recv(nif=%d): ts=%d\n", nif, ctxt->mtcp_manager->cur_ts);

	spc = (struct ssvm_private_context *)ctxt->io_private_context;
	sh = spc->sh[nif];

	if (unlikely((!spc->ssvm_is_master[nif] && (uint64_t)(sh->opaque[MASTER_ADMIN_STATE_INDEX]) == 0)
			|| (spc->ssvm_is_master[nif] && (uint64_t)(sh->opaque[SLAVE_ADMIN_STATE_INDEX]) == 0))) {
		TRACE_ERROR("Peer is down when sending to interface: %d\n", nif);
		return 0;
	}

	/* give back buffers from the previous batch */
	if (spc->rcvd[nif] > 0) {
		ssvm_release_chunks(ctxt, nif, spc->rcvd[nif], spc->rcvbuf[nif]);
		spc->rcvd[nif] = 0;
	}

	q = spc->ssvm_is_master[nif] ? (unix_shared_memory_queue_t *)sh->opaque[TO_MASTER_Q_INDEX] :
			(unix_shared_memory_queue_t *)sh->opaque[TO_SLAVE_Q_INDEX];
	if (q->cursize == 0) {
		return 0;
	}


	while (spc->rcvd[nif] < MAX_RX_PKT_BURST) {
		if (unlikely(q->cursize == 0)) {
			break;
		}
		queue_lock = (uint32_t *) q;
		while (__sync_lock_test_and_set (queue_lock, 1));
		unix_shared_memory_queue_sub_raw (q, (uint8_t *)&elt_index);
		 __sync_synchronize();
		*queue_lock = 0;
		TRACE_SSVM("recv_pkts(nif=%d): rcvd=%d, chunk_idx=%d\n",
				nif, spc->rcvd[nif], elt_index);
		spc->rcvbuf[nif][spc->rcvd[nif]++] = elt_index;
	}


	return spc->rcvd[nif];
}
/*----------------------------------------------------------------------------*/
uint8_t *
ssvm_get_rptr(struct mtcp_thread_context *ctxt, int nif, int index, uint16_t *len)
{
	struct ssvm_private_context *spc;
	ssvm_shared_header_t *sh;
	ssvm_eth_queue_elt_t *elts, *elt;

	spc = (struct ssvm_private_context *)ctxt->io_private_context;
	if (index == spc->rcvd[nif]) {
		return NULL;
	}


	sh = spc->sh[nif];
	elts = (ssvm_eth_queue_elt_t *) (sh->opaque[CHUNK_POOL_INDEX]);
	elt = elts + spc->rcvbuf[nif][index];

	TRACE_SSVM("get_rptr(nif=%d): index=%d, rcvd=%d, chunk_idx=%d, elt=%p\n",
			nif, index, spc->rcvd[nif], spc->rcvbuf[nif][index], elt);

	*len = elt->length_this_buffer;

	return elt->data;
}
/*----------------------------------------------------------------------------*/
int32_t
ssvm_select(struct mtcp_thread_context *ctxt)
{
	return 0;
}
/*----------------------------------------------------------------------------*/
void
ssvm_destroy_handle(struct mtcp_thread_context *ctxt)
{
	struct ssvm_private_context *spc;
	ssvm_shared_header_t *sh;
	int nif;

	spc = (struct ssvm_private_context *)ctxt->io_private_context;

	for (nif = 0; nif < num_devices_attached; nif++) {
		sh = spc->sh[nif];
		ssvm_release_chunks(ctxt, nif, spc->rcvd[nif], spc->rcvbuf[nif]);
		ssvm_release_chunks(ctxt, nif, MAX_TX_PKT_BURST, spc->sndbuf[nif]);
	    if (spc->ssvm_is_master[nif]) {
	    	sh->opaque[MASTER_ADMIN_STATE_INDEX] = (void *)(uint64_t) 0;
	    } else {
	    	sh->opaque[SLAVE_ADMIN_STATE_INDEX] = (void *)(uint64_t) 0;
	    }
	}

}
/*----------------------------------------------------------------------------*/
void
ssvm_load_module(void)
{
	/* not needed - all initializations done in ssvm_init_handle() */
}
/*----------------------------------------------------------------------------*/
io_module_func ssvm_module_func = {
	.load_module		   = ssvm_load_module,
	.init_handle		   = ssvm_init_handle,
	.link_devices		   = ssvm_link_devices,
	.release_pkt		   = ssvm_release_pkt,
	.send_pkts		   = ssvm_send_pkts,
	.get_wptr   		   = ssvm_get_wptr,
	.recv_pkts		   = ssvm_recv_pkts,
	.get_rptr	   	   = ssvm_get_rptr,
	.select			   = ssvm_select,
	.destroy_handle		   = ssvm_destroy_handle
};
/*----------------------------------------------------------------------------*/
#else
io_module_func ssvm_module_func = {
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
#endif /* ENABLE_ssvm */
