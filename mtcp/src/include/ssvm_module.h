/*------------------------------VPP STRUCTURES ------------------------------*/
#define MMAP_PAGESIZE (4<<10)
#define SSVM_N_OPAQUE 7
#define always_inline static inline __attribute__ ((__always_inline__))

typedef struct {
	/* Spin-lock */
	volatile uint32_t lock;
	volatile uint32_t owner_pid;
	int recursion_count;
	uint32_t tag;                      /* for debugging */

	/* The allocation arena */
	void * heap;

	/* Segment must be mapped at this address, or no supper */
	uint64_t ssvm_va;
	/* The actual mmap size */
	uint64_t ssvm_size;
	uint32_t master_pid;
	uint32_t slave_pid;
	uint8_t *name;
	void *opaque [SSVM_N_OPAQUE];

	/* Set when the master application thinks it's time to make the donuts */
	volatile uint32_t ready;

	/* Needed to make unique MAC addresses, etc. */
	uint32_t master_index;
} ssvm_shared_header_t;

typedef enum {
  CHUNK_POOL_FREELIST_INDEX = 0,
  CHUNK_POOL_INDEX,
  CHUNK_POOL_NFREE,
  TO_MASTER_Q_INDEX,
  TO_SLAVE_Q_INDEX,
  MASTER_ADMIN_STATE_INDEX,
  SLAVE_ADMIN_STATE_INDEX,
} ssvm_eth_opaque_index_t;

#define SSVM_BUFFER_SIZE 2176
#define CLIB_CACHE_LINE_BYTES (1<<6)
#define SSVM_PACKET_TYPE 1
typedef struct {
  /* Type of queue element */
  uint8_t type;
  uint8_t flags;
#define SSVM_BUFFER_NEXT_PRESENT (1<<0)
  uint8_t owner;
  uint8_t tag;
  int16_t current_data_hint;
  uint16_t length_this_buffer;
  uint16_t total_length_not_including_first_buffer;
  uint16_t pad;
  uint32_t next_index;
  /* offset 16 */
  uint8_t data [SSVM_BUFFER_SIZE];
  /* pad to an even multiple of 64 octets */
  uint8_t pad2[CLIB_CACHE_LINE_BYTES - 16];
} ssvm_eth_queue_elt_t;

always_inline void ssvm_lock (ssvm_shared_header_t *h, uint32_t my_pid, uint32_t tag)
{
	if (h->owner_pid == my_pid)
	{
		h->recursion_count++;
		return;
	}

	while (__sync_lock_test_and_set (&h->lock, 1))
		;

	h->owner_pid = my_pid;
	h->recursion_count = 1;
	h->tag = tag;
}

always_inline void ssvm_unlock (ssvm_shared_header_t *h)
{
	if (--h->recursion_count == 0)
	{
		h->owner_pid = 0;
		h->tag = 0;
		__sync_synchronize();
		h->lock = 0;
	}
}


typedef struct _unix_shared_memory_queue {
    pthread_mutex_t mutex;      /* 8 bytes */
    pthread_cond_t condvar;     /* 8 bytes */
    int head;
    int tail;
    int cursize;
    int maxsize;
    int elsize;
    int consumer_pid;
    int signal_when_queue_non_empty;
    char data[0];
} unix_shared_memory_queue_t;

#define unlikely(x) __builtin_expect(!!(x), 0)
always_inline int unix_shared_memory_queue_add_raw (unix_shared_memory_queue_t *q,
                                      uint8_t *elem)
{
    int8_t *tailp;

    if (unlikely(q->cursize == q->maxsize)) {
        while(q->cursize == q->maxsize)
            ;
    }

    tailp = (int8_t *)(&q->data[0] + q->elsize*q->tail);
    memcpy(tailp, elem, q->elsize);

    q->tail++;
    q->cursize++;

    if (q->tail == q->maxsize)
        q->tail = 0;
    return 0;
}

always_inline int unix_shared_memory_queue_sub_raw (unix_shared_memory_queue_t *q,
                                      uint8_t *elem)
{
    int8_t *headp;

    if (unlikely(q->cursize == 0)) {
        while (q->cursize == 0)
            ;
    }

    headp = (int8_t *)(&q->data[0] + q->elsize*q->head);
    memcpy(elem, headp, q->elsize);

    q->head++;
    q->cursize--;

    if(q->head == q->maxsize)
        q->head = 0;
    return 0;
}
