#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <endian.h>
#include <linux/sockios.h>

#define SIOCGINSEQ	0x89b1		/* get copied_seq */
#define SIOCGOUTSEQS	0x89b2		/* get seqs for pending tx pkts */
#define SIOCSOUTSEQ	0x89b3		/* set write_seq */
#define SIOCPEEKOUTQ	0x89b4		/* peek output queue */
#define SIOCFORCEOUTBD	0x89b5		/* force output packet boundary */

static const struct timespec ts1ms = { .tv_nsec = 1000000 };
static uint64_t contaminant = 0;
static int do_peek_outq;

static void sigaction_handler(int signo, siginfo_t *si, void *uctx)
{
	printf("signal %d si_code=%#x\n", signo, si->si_code);
	if (signo == SIGUSR1)
		contaminant = 0xdeadbeefbeefdeadLLU;
	else
		do_peek_outq = 1;
}

static void peek_outq(int sock, uint64_t cur)
{
	uint32_t seq_buf[1024];
	int size, ret;
	char *buf, *p;
	int i, nr_contaminants = 0;
	uint64_t val;

	seq_buf[0] = sizeof(seq_buf);
	assert((ret = ioctl(sock, SIOCGOUTSEQS, seq_buf)) >= 0);
	ret = ret <= sizeof(seq_buf) ? ret : sizeof(seq_buf);

	printf("SIOCGOUTSEQS:");
	for (i = 0; i < ret / sizeof(uint32_t); i++)
		printf(" %08x", seq_buf[i]);
	printf("\n");

	assert(!(ioctl(sock, SIOCOUTQ, &size)));
	buf = malloc(size);
	assert(buf);

	memcpy(buf, &size, sizeof(size));
	ret = ioctl(sock, SIOCPEEKOUTQ, buf);
	if (ret < 0) {
		perror("SIOCPEEKOUTQ");
		return;
	}
	assert(ret <= size);

	printf("peek_outq %d bytes: ", ret);
	cur--;

	printf("[%08llx", (unsigned long long)cur);

	for (p = buf + ret - sizeof(val); p > buf; p -= sizeof(val)) {
		memcpy(&val, p, sizeof(val));
		val = be64toh(val);

		if (val == cur) {
			cur--;
		} else {
			printf(" #%08llx", (unsigned long long)cur + 1);
			nr_contaminants++;
		}
	}

	printf(" %08llx]", (unsigned long long)cur + 1);
	printf(" nr_contaminants=%d\n", nr_contaminants);
}

static void *send_thread_fn(void *arg)
{
	int sock = (long)arg;
	uint64_t cur = 0, buf;
	int ret;

	while (1) {
		int bytes = 0;

		if (do_peek_outq) {
			peek_outq(sock, cur);
			do_peek_outq = 0;
		}

		if (!contaminant) {
			buf = htobe64(cur++);
		} else {
			printf("inserting contaminant @%#08llx\n",
			       (unsigned long long)cur);
			buf = htobe64(contaminant);
			contaminant = 0;
		}

		while (bytes < sizeof(buf)) {
			ret = send(sock, (void *)&buf + bytes,
				   sizeof(buf) - bytes, 0);
			bytes += ret;
			assert(ret > 0 && bytes <= sizeof(buf));
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	struct sigaction sa = { .sa_sigaction = sigaction_handler,
				.sa_flags = SA_SIGINFO | SA_RESTART };
	struct sockaddr_in in = { .sin_family = AF_INET,
				  .sin_addr.s_addr = INADDR_ANY };
	unsigned long rx_kbps = 128;
	uint64_t next = 0;
	socklen_t slen;
	pthread_t pth;
	char *p;
	int i, ret, v, sock;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: net-host [IP:]PORT [RX_KPBS]\n");
		return 1;
	}

	if (argc == 3) {
		rx_kbps = strtoul(argv[2], &p, 0);
		assert(p && *p == '\0');
	}

	if ((p = strchr(argv[1], ':'))) {
		*p++ = '\0';
		assert(inet_aton(argv[1], &in.sin_addr));
	} else {
		p = argv[1];
	}
	in.sin_port = htons(strtoul(p, &p, 0));
	assert(p && *p == '\0');

	assert((sock = socket(AF_INET, SOCK_STREAM, 0)) >= 0);

	v = 1;
	assert(!setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)));

	if (in.sin_addr.s_addr != INADDR_ANY) {
		assert(!connect(sock, (struct sockaddr *)&in, sizeof(in)));
	} else {
		assert(!bind(sock, (struct sockaddr *)&in, sizeof(in)));
		assert(!listen(sock, 5));
		sock = accept(sock, NULL, NULL);
	}

	slen = sizeof(in);
	assert(!getpeername(sock, (struct sockaddr *)&in, &slen));
	printf("Connected to %s:%u\n",
	       inet_ntoa(in.sin_addr), ntohs(in.sin_port));

	assert(!sigaction(SIGUSR1, &sa, NULL));
	assert(!sigaction(SIGUSR2, &sa, NULL));

	assert(!pthread_create(&pth, NULL, send_thread_fn, (void *)(long)sock));

	while (1) {
		uint64_t buf;
		int cnt = rx_kbps / 64 ?: 1;

		for (i = 0; i < cnt; i++) {
			int bytes = 0;

			while (bytes < sizeof(buf)) {
				ret = recv(sock, (void *)&buf + bytes,
					   sizeof(buf) - bytes, 0);
				bytes += ret;
				assert(ret > 0 && bytes <= sizeof(buf));
			}

			if (be64toh(buf) != next) {
				printf("foreign data @%#08llx : %#08llx\n",
				       (unsigned long long)next,
				       (unsigned long long)be64toh(buf));
				continue;
			}
			next++;
		}

		nanosleep(&ts1ms, NULL);
	}

	return 0;
}
