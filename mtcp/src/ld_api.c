#define _GNU_SOURCE
#include "mtcp.h"
#include "mtcp_api.h"
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <poll.h>
#include <unistd.h>

static mctx_t mctx = NULL;

/* This array maps kernel fds to mtcp sockfds */
#define MAX_FDS 1024
static int sockmap[MAX_FDS];

static int (*__close)(int fd) = NULL;
static int (*__socket)(int domain, int type, int protocol) = NULL;
static ssize_t (*__read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*__write)(int fd, const void *buf, size_t count) = NULL;
static int (*__poll)(struct pollfd *fds, nfds_t nfds, int timeout) = NULL;
static int (*__select)(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout) = NULL;

static int mtcp_init_ld()
{
	int i;
	for (i = 0; i < MAX_FDS; i++) {
		sockmap[i] = -1;
	}

	if ((__close = dlsym(RTLD_NEXT, "close")) == NULL) {
		perror("dlsym");
		return -1;
	}

	if ((__socket = dlsym(RTLD_NEXT, "socket")) == NULL) {
		perror("dlsym");
		return -1;
	}

	if ((__read = dlsym(RTLD_NEXT, "read")) == NULL) {
		perror("dlsym");
		return -1;
	}

	if ((__write = dlsym(RTLD_NEXT, "write")) == NULL) {
		perror("dlsym");
		return -1;
	}

	if ((__poll = dlsym(RTLD_NEXT, "poll")) == NULL) {
		perror("dlsym");
		return -1;
	}

	if ((__select = dlsym(RTLD_NEXT, "select")) == NULL) {
		perror("dlsym");
		return -1;
	}

	return 0;
}


static int mtcp_init_runtime()
{
	struct mtcp_conf mcfg;

	mtcp_getconf(&mcfg);
	mcfg.num_cores = 1;
	mtcp_setconf(&mcfg);

	if (mtcp_init("epwget.conf")) {
		fprintf(stderr, "Failed to initialize mtcp.\n");
		return -1;
	}

	mctx = mtcp_create_context(0); //FIXME provide a config option for the cpu to be pinned to
	if (!mctx) {
		fprintf(stderr, "Failed to create mtcp context.\n");
		return -1;
	}
	return 0;
}

__attribute__((constructor)) void start()
{
	fprintf(stderr, "Starting mtcp module\n");
	mtcp_init_ld();
	mtcp_init_runtime();
}

__attribute__((destructor)) void fini()
{
	fprintf(stderr, "Waiting for mtcp thread to terminate\n");
	mtcp_destroy();
}

int socket(int domain, int type, int protocol)
{
	int fd, sockfd;

	if (type != SOCK_STREAM) {
		return __socket(domain, type, protocol);
	}

	/* grab a valid file descriptor from the kernel, so that there is no clash
	 * between mtcp/kernel fd space */
	if ((fd = open("/dev/null", O_RDONLY)) < 0) {
		errno = ENFILE;
		return -1;
	}

	if ((sockfd = mtcp_socket(mctx, domain, type, protocol)) < 0) {
		__close(fd);
		return -1;
	}

	sockmap[fd] = sockfd;
	return fd;
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
	return mtcp_getsockopt(mctx, sockmap[fd], level, optname, optval, optlen);
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
	return mtcp_setsockopt(mctx, sockmap[fd], level, optname, optval, optlen);
}

#define MIN(x, y) ((x) < (y) ? (x) : (y))
int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	mtcp_manager_t mtcp;
	socket_map_t socket;
    int sockfd;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	sockfd = sockmap[fd];
	if (sockfd < 0 || sockfd >= CONFIG.max_concurrency) {
		errno = EBADF;
		return -1;
	}

	socket = &mtcp->smap[sockfd];
	if (socket->socktype == MTCP_SOCK_UNUSED) {
		errno = EBADF;
		return -1;
	}

	if (socket->socktype != MTCP_SOCK_LISTENER && socket->socktype != MTCP_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}

	memcpy(addr, &socket->saddr, MIN(*addrlen, sizeof(struct sockaddr_in)));
	*addrlen = sizeof(struct sockaddr_in);
	return 0;
}


int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (mtcp_connect(mctx, sockmap[fd], addr, addrlen) < 0) {
		return -1;
	}
	mtcp_setsock_nonblock(mctx, sockmap[fd]);
	return 0;
}


int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	return mtcp_bind(mctx, sockmap[fd], addr, addrlen);
}

int listen(int fd, int backlog)
{
	return mtcp_listen(mctx, sockmap[fd], backlog);
}

int accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int newsockfd, newfd;

	mtcp_setsock_nonblock(mctx, sockmap[fd]);
	while ((newsockfd = mtcp_accept(mctx, sockmap[fd], addr, addrlen)) < 0) {
		if (errno == EAGAIN) {
			usleep(1);
			continue;
		}
		return -1;
	}
	mtcp_setsock_nonblock(mctx, newsockfd);


	/* grab a valid file descriptor from the kernel, so that there is no clash
	 * between mtcp/kernel fd space */
	if ((newfd = open("/dev/null", O_RDONLY)) < 0) {
		errno = ENFILE;
		mtcp_close(mctx, newsockfd);
		return -1;
	}

	sockmap[newfd] = newsockfd;

	return newfd;
}


int close(int fd)
{
	int ret;

	ret = __close(fd);
	if (sockmap[fd] >= 0) {
		ret = mtcp_close(mctx, sockmap[fd]);
		sockmap[fd] = -1;
	}

	return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
	if (sockmap[fd] >= 0) {
		return mtcp_read(mctx, sockmap[fd], buf, count);
	}

	return __read(fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	if (sockmap[fd] >= 0) {
		return mtcp_write(mctx, sockmap[fd], (void*)buf, count);
	}

	return __write(fd, buf, count);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	return mtcp_write(mctx, sockmap[fd], (void*)buf, len);
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	return mtcp_read(mctx, sockmap[fd], (void*)buf, len);
}

/* fixme: this implementation is incomplete */
int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	if (nfds > 0 && sockmap[fds[0].fd] >= 0) {
		int i;
		for (i = 0; i < nfds; i++) {
			fds[i].revents = fds[i].events;
		}
		return nfds;
	}

	return __poll(fds, nfds, timeout);
}

/* fixme: not implemented */
int select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout)
{
	return 1;
}
