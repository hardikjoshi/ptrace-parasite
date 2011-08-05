/* GPLv2, read README for info */
#define _GNU_SOURCE

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <wait.h>
#include <assert.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <libgen.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* kernel constants which aren't in libc yet */
#define PTRACE_SEIZE		0x4206
#define PTRACE_INTERRUPT	0x4207
#define PTRACE_LISTEN		0x4208

#define PTRACE_SEIZE_DEVEL	0x80000000 /* temp flag for development */

#define PTRACE_EVENT_STOP	7

#define SIOCGINSEQ	0x89b1		/* get copied_seq */
#define SIOCGOUTSEQS	0x89b2		/* get seqs for pending tx pkts */
#define SIOCSOUTSEQ	0x89b3		/* set write_seq */
#define SIOCPEEKOUTQ	0x89b4		/* peek output queue */
#define SIOCFORCEOUTBD	0x89b5		/* force output packet boundary */

/* params pulled out of my ass */
#define MAX_THREADS		1024
#define MSS			1400

/* this defines the protocol to talk to parasite */
#include "parasite.h"

/* for ptracing the target process and talking to the parasite */
static pid_t tids[MAX_THREADS];
static int nr_threads;
static int listen_sock, pcmd_port, pcmd_sock;

/* for TCP connection hijacking */
static int target_sock_fd = -1;
static int raw_sock, remote_sock;
struct psockinfo psockinfo;
static char *in_buf, *out_buf;

/* parasite nfqueue stuff */
static const char setup_pnfq_cmd_base[] = "setup-nfqueue";
static const char flush_pnfq_cmd_base[] = "flush-nfqueue";
static char setup_pnfq_cmd[PATH_MAX];
static char flush_pnfq_cmd[PATH_MAX];

static struct nfq_handle *pnfq_h;
static struct nfq_q_handle *pnfq_qh;
static char pnfq_buf[4096] __attribute__((aligned));

/* commands for pnfq_wait_pkt() */
enum {
	PNFQ_WAIT_SYN,		/* wait SYN from local */
	PNFQ_WAIT_ACK,		/* wait ACK of certain seq from local */
	PNFQ_WAIT_PASS,		/* pass queued packets through */
};

/* for pnfq packet diddling */
static int pnfq_cmd;
static uint32_t pnfq_wait_ack_seq;
static unsigned char waited_pkt[4096];
static int waited_pkt_len;
static struct iphdr *waited_iph;
static struct tcphdr *waited_tcph;

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

/*
 * Naive and racy implementation for seizing all threads in a process.
 * Doing it properly requires verify and retry loop.  Eh well...
 */
static int seize_process(pid_t pid)
{
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *ent;

	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	dir = opendir(path);
	if (!dir) {
		perror("opendir");
		return -errno;
	}

	while ((ent = readdir(dir))) {
		pid_t tid;
		char *eptr;
		int status;
		siginfo_t si;

		tid = strtoul(ent->d_name, &eptr, 0);
		if (*eptr != '\0')
			continue;

		if (nr_threads >= MAX_THREADS) {
			fprintf(stderr, "too many threads\n");
			return -EINVAL;
		}

		printf("Seizing %d\n", tid);

		assert(!ptrace(PTRACE_SEIZE, tid, NULL,
			       (void *)(unsigned long)PTRACE_SEIZE_DEVEL));
		assert(!ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
		assert(wait4(tid, &status, __WALL, NULL) == tid);
		assert(WIFSTOPPED(status));
		assert(!ptrace(PTRACE_GETSIGINFO, tid, NULL, &si));
		assert(si.si_code >> 8 == PTRACE_EVENT_STOP);
		assert(!ptrace(PTRACE_SETOPTIONS, tid, NULL,
			       (void *)(unsigned long)PTRACE_O_TRACEEXIT));

		tids[nr_threads++] = tid;
	}
	return 0;
}

/*
 * Various blobs we're gonna inject into the host process.  parasite-blob.h
 * is generated from parasite.c and is the code parasite thread executes.
 * Other blobs are injected into one of the existing threads to make the
 * parasite thread happen.
 */
#include "parasite-blob.h"

extern char test_blob[], sigprocmask_blob[], mmap_blob[], clone_blob[], munmap_blob[];
extern int test_blob_size, sigprocmask_blob_size, mmap_blob_size, clone_blob_size, munmap_blob_size;

static void __attribute__((used)) insertion_blob_container(void)
{
	/*
	 * Upon completion, each blob triggers debug trap to pass the
	 * control back to the main program.
	 */

	/* this one just says hi to stdout for testing blob execution */
	asm volatile("test_blob:			\n\t"
		     "movq $1, %rax			\n\t" /* write */
		     "movq $1, %rdi			\n\t" /* @fd */
		     "leaq 1f(%rip), %rsi		\n\t" /* @buf: "hello..." */
		     "movq $20, %rdx			\n\t" /* @count */
		     "syscall				\n\t"
		     "int $0x03				\n\t"
		     "1: .ascii \"BLOB: hello, world!\\n\"\n\t"
		     "test_blob_size:			\n\t"
		     ".int test_blob_size - test_blob	\n\t");

	/* rt_sigprocmask(), expects pointer to area for masks in %r15 */
	asm volatile("sigprocmask_blob:			\n\t"
		     "movq $14, %%rax			\n\t" /* rt_sigprocmask */
		     "movq %0, %%rdi			\n\t" /* @how */
		     "movq %%r15, %%rsi			\n\t" /* @nset */
		     "addq $8, %%r15			\n\t"
		     "movq %%r15, %%rdx			\n\t" /* @oset */
		     "movq $8, %%r10			\n\t" /* @sigsetsize */
		     "syscall				\n\t"
		     "movq (%%r15), %%r15		\n\t" /* *@oset */
		     "int $0x03				\n\t"
		     "sigprocmask_blob_size:		\n\t"
		     ".int sigprocmask_blob_size - sigprocmask_blob \n\t"
		     :: "i" (SIG_SETMASK));

	/* mmaps anon area for parasite_blob */
	asm volatile("mmap_blob:			\n\t"
		     "movq $9, %%rax			\n\t" /* mmap */
		     "movq $0, %%rdi			\n\t" /* @addr */
		     "movq %0, %%rsi			\n\t" /* @len */
		     "movq %1, %%rdx			\n\t" /* @prot */
		     "movq %2, %%r10			\n\t" /* @flags */
		     "movq $-1, %%r8			\n\t" /* @fd */
		     "movq $0, %%r9			\n\t" /* @off */
		     "syscall				\n\t"
		     "int $0x03				\n\t"
		     "mmap_blob_size:			\n\t"
		     ".int mmap_blob_size - mmap_blob	\n\t"
		     :: "i" (sizeof(parasite_blob)),
		        "i" (PROT_EXEC | PROT_READ | PROT_WRITE),
		        "i" (MAP_ANONYMOUS | MAP_PRIVATE));

	/* clones parasite, expects parasite address in %r15 */
	asm volatile("clone_blob:			\n\t"
		     "movq $56, %%rax			\n\t" /* clone */
		     "movq %0, %%rdi			\n\t" /* @flags */
		     "movq $0, %%rsi			\n\t" /* @newsp */
		     "movq $0, %%rdx			\n\t" /* @parent_tid */
		     "movq $0, %%r10			\n\t" /* @child_tid */
		     "syscall				\n\t"
		     "test %%rax, %%rax			\n\t"
		     "jnz 1f				\n\t"
		     "jmp *%%r15			\n\t" /* jmp parasite */
		     "1: int $0x03			\n\t"
		     "clone_blob_size:			\n\t"
		     ".int clone_blob_size - clone_blob	\n\t"
		     :: "i" (CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_SIGHAND |
			     CLONE_SYSVSEM | CLONE_THREAD | CLONE_VM |
			     CLONE_PTRACE));

	/* munmaps anon area for parasite_blob, expects mmap address in %r15 */
	asm volatile("munmap_blob:			\n\t"
		     "movq $11, %%rax			\n\t" /* munmap */
		     "movq %%r15, %%rdi			\n\t" /* @addr */
		     "movq %0, %%rsi			\n\t" /* @len */
		     "syscall				\n\t"
		     "int $0x03				\n\t"
		     "munmap_blob_size:			\n\t"
		     ".int munmap_blob_size - munmap_blob\n\t"
		     :: "i" (sizeof(parasite_blob)));
}

static unsigned long execute_blob(pid_t tid, unsigned long *pc,
				  const char *blob, size_t size,
				  unsigned long *r15)
{
	struct user_regs_struct uregs, saved_uregs;
	siginfo_t si;
	int i, status;

	/* inject blob into the host */
	for (i = 0; i < DIV_ROUND_UP(size, sizeof(unsigned long)); i++)
		assert(!ptrace(PTRACE_POKEDATA, tid, pc + i,
			       (void *)*((unsigned long *)blob + i)));
retry:
	assert(!ptrace(PTRACE_GETREGS, tid, NULL, &uregs));
	saved_uregs = uregs;

	uregs.orig_rax = -1;		/* avoid end-of-syscall processing */
	uregs.rip = (unsigned long)pc;	/* point to the injected blob */
	if (r15)
		uregs.r15 = *r15;	/* used as parameter to blob */

	assert(!ptrace(PTRACE_SETREGS, tid, NULL, &uregs));

	/* let the blob run, upon completion it will trigger debug trap */
	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));
	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_GETSIGINFO, tid, NULL, &si));

	if (WSTOPSIG(status) != SIGTRAP || si.si_code != SI_KERNEL) {
		/*
		 * The only other thing which can happen is signal
		 * delivery.  Restore registers so that signal frame
		 * preparation operates on the original state, schedule
		 * INTERRUPT and let the delivery happen.
		 *
		 * If the signal has user handler, signal code will
		 * schedule handler by modifying userland memory and
		 * registers and return to jobctl trap.  STOP handling will
		 * modify jobctl state and also return to jobctl trap and
		 * there isn't much we can do about KILL handling.
		 *
		 * So, regardless of signo, we can simply retry after
		 * control returns to jboctl trap.
		 *
		 * Note that if signal is delivered between syscall and
		 * int3 in the blob, the syscall might be executed again.
		 * Block signals first before doing any operation with side
		 * effects.
		 */
	retry_signal:
		printf("** delivering signal %d si_code=%d\n",
		       si.si_signo, si.si_code);
		assert(si.si_code <= 0);
		assert(!ptrace(PTRACE_SETREGS, tid, NULL, (void *)&saved_uregs));
		assert(!ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
		assert(!ptrace(PTRACE_CONT, tid, NULL,
			       (void *)(unsigned long)si.si_signo));

		/* wait for trap */
		assert(wait4(tid, &status, __WALL, NULL) == tid);
		assert(WIFSTOPPED(status));
		assert(!ptrace(PTRACE_GETSIGINFO, tid, NULL, &si));

		/* are we back at jobctl trap or are there more signals? */
		if (si.si_code >> 8 != PTRACE_EVENT_STOP)
			goto retry_signal;

		/* otherwise, retry */
		goto retry;
	}

	/*
	 * Okay, this is the SIGTRAP delivery from int3.  Steer the thread
	 * back to jobctl trap by raising INTERRUPT and squashing SIGTRAP.
	 */
	assert(!ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));

	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_GETSIGINFO, tid, NULL, &si));
	assert(si.si_code >> 8 == PTRACE_EVENT_STOP);

	/* retrieve return value and restore registers */
	assert(!ptrace(PTRACE_GETREGS, tid, NULL, &uregs));
	assert(!ptrace(PTRACE_SETREGS, tid, NULL, &saved_uregs));
	if (r15)
		*r15 = uregs.r15;
	return uregs.rax;
}

/*
 * Tell the pararsite to execute a PCMD_* command, wait for completion, and
 * record and return the response.
 */
static long parasite_cmd(int sock, int opcode,
			 unsigned long arg0, unsigned long arg1,
			 void *data, unsigned long *data_len)
{
	struct parasite_cmd cmd = { .opcode = opcode,
				    .arg0 = arg0, .arg1 = arg1,
				    .data_len = data_len ? *data_len : 0 };

	assert(send(sock, &cmd, sizeof(cmd), 0) == sizeof(cmd));
	if (data_len && *data_len) {
		assert(*data_len <= PCMD_MAX_DATA && data);
		assert(send(sock, data, *data_len, 0) == *data_len);
	}

	assert(recv(sock, &cmd, sizeof(cmd), MSG_WAITALL) == sizeof(cmd));
	if (data_len) {
		*data_len = cmd.data_len;
		if (*data_len) {
			assert(*data_len <= PCMD_MAX_DATA && data);
			assert(recv(sock, data, *data_len,
				    MSG_WAITALL) == *data_len);
		}
	}
	return cmd.opcode;
}

static void setup_pnfq(void)
{
	struct psockinfo *si = &psockinfo;
	struct in_addr lin = { .s_addr = si->local_ip };
	struct in_addr rin = { .s_addr = si->remote_ip };
	char lstr[INET_ADDRSTRLEN], rstr[INET_ADDRSTRLEN];
	char buf[512];

	printf("target socket: %s:%d -> %s:%d in %u@%#08x out %u@%#08x\n",
	       inet_ntop(AF_INET, &lin, lstr, sizeof(lstr)), ntohs(si->local_port),
	       inet_ntop(AF_INET, &rin, rstr, sizeof(rstr)), ntohs(si->remote_port),
	       si->in_qsz, si->in_seq, si->out_qsz, si->out_seqs[0]);

	snprintf(buf, sizeof(buf), "%s %s:%d %s:%d", setup_pnfq_cmd,
		 inet_ntop(AF_INET, &lin, lstr, sizeof(lstr)), ntohs(si->local_port),
		 inet_ntop(AF_INET, &rin, rstr, sizeof(rstr)), ntohs(si->remote_port));
	assert(!system(buf));
}

static void flush_pnfq(void)
{
	assert(!system(flush_pnfq_cmd));
}

static void parasite_sequencer(void)
{
	const char hello[] = "ah ah! mic test!\n";
	struct psockinfo *si = &psockinfo;
	unsigned long data_len;
	unsigned long len;
	int ret;

	printf("waiting for connection...");
	fflush(stdout);
	assert((pcmd_sock = accept(listen_sock, NULL, NULL)) >= 0);
	printf(" connected\n");

	/* let's see whether it works */
	data_len = sizeof(hello);
	assert(!parasite_cmd(pcmd_sock, PCMD_SAY, 0, 0,
			     (void *)hello, &data_len));

	/* if connection hijacking wasn't requested, nothing more to do */
	if (target_sock_fd < 0)
		goto exit;

	/*
	 * Acquire socket info and setup nfqueue such that packets
	 * belonging to the connection is sent to pnfq.
	 */
	len = 0;
	assert(!parasite_cmd(pcmd_sock, PCMD_SOCKINFO,
			     target_sock_fd, 0, si, &len));
	setup_pnfq();

	/*
	 * Acquire socket info again.  TCP sequence numbers need to be
	 * sampled after blocking packets, so we need to do this again
	 * after setup_pnfq().
	 */
	len = 0;
	assert(!parasite_cmd(pcmd_sock, PCMD_SOCKINFO,
			     target_sock_fd, 0, si, &len));
	assert(si->in_qsz <= PCMD_MAX_DATA && si->out_qsz <= PCMD_MAX_DATA);

	/* peek and save rx and tx queues */
	if (si->in_qsz) {
		assert((in_buf = malloc(si->in_qsz)));
		data_len = 0;
		assert((ret = parasite_cmd(pcmd_sock, PCMD_PEEK_INQ,
					   target_sock_fd, si->in_qsz,
					   in_buf, &data_len)) >= 0);
		si->in_qsz = data_len;
	}
	if (si->out_qsz) {
		assert((out_buf = malloc(si->out_qsz)));
		data_len = 0;
		assert((ret = parasite_cmd(pcmd_sock, PCMD_PEEK_OUTQ,
					   target_sock_fd, si->out_qsz,
					   out_buf, &data_len)) >= 0);
		si->out_qsz = data_len;
	}
	printf("peeked socket buffer in %d out %d\n", si->in_qsz, si->out_qsz);

	/*
	 * We have all information we need to hijack the connection.  Tell
	 * the parasite to replace the fd with the command socket which
	 * will act as proxy.
	 */
	assert(parasite_cmd(pcmd_sock, PCMD_DUP_CSOCK,
			    target_sock_fd, 0, NULL, NULL) >= 0);
exit:
	assert(!parasite_cmd(pcmd_sock, PCMD_QUIT, 0, 0, NULL, NULL));
}

static void insert_parasite(pid_t tid)
{
	struct user_regs_struct uregs;
	unsigned long *pc, *sp, *saved_code, saved_stack[16];
	unsigned long r15, saved_sigmask, ret, *src, *dst;
	pid_t parasite;
	int i, count, status;

	/* allocate space to save original code */
	count = DIV_ROUND_UP(max(test_blob_size,
			     max(sigprocmask_blob_size,
			     max(mmap_blob_size,
			     max(clone_blob_size,
				 munmap_blob_size)))),
			     sizeof(unsigned long));
	saved_code = malloc(sizeof(unsigned long) * count);
	assert(saved_code);

	assert(!ptrace(PTRACE_GETREGS, tid, NULL, &uregs));

	/*
	 * The page %rip is on gotta be executable.  If we inject from the
	 * beginning of the page, there should be at least one page of
	 * space.  Determine the position and save the original code.
	 */
	pc = (void *)round_down(uregs.rip, 4096);
	for (i = 0; i < count; i++)
		saved_code[i] = ptrace(PTRACE_PEEKDATA, tid, pc + i, NULL);

	/*
	 * Save and restore some bytes below %rsp so that blobs can use it
	 * as writeable scratch area.  This wouldn't be necessary if mmap
	 * is done earlier.
	 */
	sp = (void *)uregs.rsp - sizeof(saved_stack);
	for (i = 0; i < sizeof(saved_stack) / sizeof(saved_stack[0]); i++)
		saved_stack[i] = ptrace(PTRACE_PEEKDATA, tid, sp + i, NULL);

	/* say hi! */
	printf("executing test blob\n");
	execute_blob(tid, pc, test_blob, test_blob_size, NULL);

	/* block all signals */
	printf("blocking all signals");
	assert(!ptrace(PTRACE_POKEDATA, tid, sp, (void *)-1LU));
	r15 = (unsigned long)sp;
	ret = execute_blob(tid, pc,
			   sigprocmask_blob, sigprocmask_blob_size, &r15);
	printf(" = %#lx, prev_sigmask %#lx\n", ret, r15);
	saved_sigmask = r15;
	assert(!ret);

	/* mmap space for parasite */
	printf("executing mmap blob");
	ret = execute_blob(tid, pc, mmap_blob, mmap_blob_size, NULL);
	printf(" = %#lx\n", ret);
	assert(ret < -4096LU);

	/* copy parasite_blob into the mmapped area */
	dst = (void *)ret;
	src = (void *)parasite_blob;
	for (i = 0; i < DIV_ROUND_UP(sizeof(parasite_blob),
				     sizeof(unsigned long)); i++)
		if (src[i])
			assert(!ptrace(PTRACE_POKEDATA, tid, dst + i, src[i]));

	/* clone parasite which will trap and wait for instruction */
	printf("executing clone blob");
	r15 = (unsigned long)dst;
	parasite = execute_blob(tid, pc, clone_blob, clone_blob_size, &r15);
	printf(" = %d\n", parasite);
	assert(parasite >= 0);

	/* let the parasite run and wait for completion */
	assert(wait4(parasite, &status, __WALL, NULL) == parasite);
	assert(WIFSTOPPED(status));
	printf("executing parasite\n");
	assert(!ptrace(PTRACE_CONT, parasite, NULL, NULL));

	parasite_sequencer();

	/* wait for termination */
	assert(wait4(parasite, &status, __WALL, NULL) == parasite);
	assert(!ptrace(PTRACE_CONT, parasite, NULL, NULL));
	assert(wait4(parasite, &status, __WALL, NULL) == parasite);
	printf("stats=%x\n", status);
	assert(WIFEXITED(status));

	/* parasite is done, munmap parasite_blob area */
	printf("executing munmap blob");
	r15 = (unsigned long)dst;
	ret = execute_blob(tid, pc, munmap_blob, munmap_blob_size, &r15);
	printf(" = %ld\n", ret);
	assert(!ret);

	/* restore the original sigmask */
	printf("restoring sigmask");
	assert(!ptrace(PTRACE_POKEDATA, tid, sp, (void *)saved_sigmask));
	r15 = (unsigned long)sp;
	ret = execute_blob(tid, pc,
			   sigprocmask_blob, sigprocmask_blob_size, &r15);
	printf(" = %#lx, prev_sigmask %#lx\n", ret, r15);
	assert(!ret);

	/* restore the original code and stack area */
	for (i = 0; i < count; i++)
		assert(!ptrace(PTRACE_POKEDATA, tid, pc + i,
			       (void *)saved_code[i]));

	for (i = 0; i < sizeof(saved_stack) / sizeof(saved_stack[0]); i++)
		assert(!ptrace(PTRACE_POKEDATA, tid, sp + i,
			       (void *)saved_stack[i]));

	free(saved_code);
}

/*
 * nfq callback used to block the target connection and fake connection
 * sequence while restoring it.
 */
static int pnfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		   struct nfq_data *nfa, void *data)
{
	uint32_t id = 0, done = 0;
	int indev = nfq_get_indev(nfa);
	int verdict = NF_DROP;
	unsigned char *pkt;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct nfqnl_msg_packet_hdr *ph;
	int from_local, size;
	char ifname[IFNAMSIZ] = "";

	if ((ph = nfq_get_msg_packet_hdr(nfa)))
		id = ntohl(ph->packet_id);

	size = nfq_get_payload(nfa, &pkt);
	if (size < sizeof(*iph)) {
		printf("pkt: size=%d\n", size);
		goto drop;
	}
	iph = (void *)pkt;

	if (size < iph->ihl * 4 + sizeof(*tcph)) {
		printf("pkt: short, size=%d ihl=%d\n", size, iph->ihl);
		goto drop;
	}
	tcph = (void *)pkt + (iph->ihl * 4);

	from_local = iph->saddr == psockinfo.local_ip;

	/*
	 * *grumble* For now, let's assume the remote peer is on another
	 * machine and we aren't talking through lo and so we can assume
	 * packets coming from lo are the injected ones from @raw_sock.  If
	 * xt_owner could do pid or socket ino match, this can be done much
	 * better.
	 */
	if (indev) {
		if_indextoname(indev, ifname);
		if (ifname[0] == 'l' && ifname[1] == 'o')
			verdict = NF_ACCEPT;
	}

	/* is this the packet we're told to wait for? */
	switch (pnfq_cmd) {
	case PNFQ_WAIT_SYN:
		done = from_local && tcph->syn;
		break;

	case PNFQ_WAIT_ACK:
		done = from_local && tcph->ack &&
			ntohl(tcph->ack_seq) == pnfq_wait_ack_seq;
		break;
	case PNFQ_WAIT_PASS:
		verdict = NF_ACCEPT;
		break;
	}

	/* if so, copy it out */
	if (!waited_pkt_len && done) {
		memcpy(waited_pkt, pkt, size);
		waited_pkt_len = size;
		waited_iph = iph;
		waited_tcph = tcph;
	} else
		done = 0;

	printf("pkt: %s S %08x A %08x D %05u %s%s%s%s %s%s\n",
	       from_local ? "L->R" : "R->L",
	       ntohl(tcph->seq), ntohl(tcph->ack_seq),
	       ntohs(iph->tot_len) - (iph->ihl + tcph->doff) * 4,
	       tcph->ack ? "a" : "_", tcph->syn ? "s" : "_", 
	       tcph->fin ? "f" : "_", tcph->rst ? "r" : "_",
	       verdict == NF_ACCEPT ? "ACPT" : "DROP", done ? " DONE" : "");
drop:
	return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

/*
 * Iterate through packets being queued on nfqueue until the condition
 * specified by @cmd and @seq is met.  Read comments on PNFQ_* enums.
 */
static int pnfq_wait_pkt(int cmd, uint32_t seq)
{
	int fd = nfq_fd(pnfq_h);
	int ret, cnt = 0;

	pnfq_cmd = cmd;
	pnfq_wait_ack_seq = seq;
	waited_pkt_len = 0;

	do {
		ret = recv(fd, pnfq_buf, sizeof(pnfq_buf),
			   cmd == PNFQ_WAIT_PASS ? MSG_DONTWAIT : 0);
		if (ret < 0 && errno == EAGAIN)
			break;
		assert(ret > 0);
		nfq_handle_packet(pnfq_h, pnfq_buf, ret);
		cnt++;
	} while (!waited_pkt_len);

	return cnt;
}

uint16_t tcp_csum(uint32_t saddr, uint32_t daddr, void *data, int len)
{
	uint8_t *p = data;
	uint16_t *sap = (void *)&saddr;
	uint16_t *dap = (void *)&daddr;
	uint32_t sum = 0;
	int i;

	sum += ntohs(sap[0]);
	sum += ntohs(sap[1]);
	sum += ntohs(dap[0]);
	sum += ntohs(dap[1]);
	sum += len;
	sum += IPPROTO_TCP;

	for (i = 0; i < len; i += 2) {
		unsigned int hb = p[i];
		unsigned int lb = i + 1 < len ? p[i + 1] : 0;

		sum += hb << 8 | lb;
	}

	sum = (sum & 0xffff) + (sum >> 16);
	sum += sum >> 16;
	sum = ~sum;
	return htons(sum);
}

/*
 * Connection information was gleaned from the target socket which is dead
 * now, and pnfq is still blocking all traffic from the connection.  Try to
 * re-establish the connection.
 *
 * Fake connection works by intercepting outging packets with nfqueue and
 * injecting packets using a raw socket.  It currently doesn't handle
 * timeout or retries.  We'll probably need a retry/timeout wrapper around
 * sendto()/pnfq_wait_pkt() pairs.
 */
static void restore_connection(void)
{
	struct psockinfo *si = &psockinfo;
	struct sockaddr_in lsin = { .sin_family = AF_INET,
				    .sin_addr.s_addr = si->local_ip,
				    .sin_port = si->local_port, };
	struct sockaddr_in rsin = { .sin_family = AF_INET,
				    .sin_addr.s_addr = si->remote_ip,
				    .sin_port = si->remote_port, };
	uint32_t lseq = si->out_seqs[0] - si->out_qsz - 1;	/* -1 for SYN */
	uint32_t rseq = si->in_seq - 1;				/* ditto */
	uint32_t seq;
	uint8_t data_pkt[4096];
	struct iphdr *iph;
	struct tcphdr *tcph;
	const int hlen = sizeof(*iph) + sizeof(*tcph);
	int sock, xfer, i, v;

	printf("restoring connection, connecting...\n");

	/*
	 * Send out connection request w/ the matching sequence number.  It
	 * probably would be better to do this in the other direction -
	 * ie. accept() here and inject SYN via raw socket to restore 1-N
	 * port mappings.  Eh well, that shouldn't be too different from
	 * this anyway.
	 */
	assert((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) >= 0);
	assert(!bind(sock, (struct sockaddr *)&lsin, sizeof(lsin)));
	assert(!ioctl(sock, SIOCSOUTSEQ, &lseq));
	assert(connect(sock, (struct sockaddr *)&rsin, sizeof(rsin)) < 0 &&
	       errno == EINPROGRESS);
	lseq++;

	pnfq_wait_pkt(PNFQ_WAIT_SYN, 0);

	/*
	 * Got SYN on pnfq, fake SYN/ACK.  We construct the SYN/ACK packet
	 * by simply copying the SYN packet and modifying necessary parts,
	 * which of course isn't correct.  We need to record more
	 * information from the original socket and advertise the correct
	 * options.
	 *
	 * Another weird thing below is blowing up tcph->window.  This is
	 * done so that the new socket sends out all the packets when the
	 * send queue is restored so that the socket considers all of them
	 * in flight and accepts acks for them.  This works but I'm not
	 * sure whether this is a guaranteed behavior.  Maybe having a way
	 * to adjust tp->snd_nxt is better?
	 */
	printf("got SYN, replying with SYN/ACK\n");

	iph = waited_iph;
	tcph = waited_tcph;

	assert(ntohl(tcph->seq) == lseq - 1);
	iph->saddr = si->remote_ip;
	iph->daddr = si->local_ip;
	tcph->source = si->remote_port;
	tcph->dest = si->local_port;
	tcph->syn = 1;
	tcph->ack = 1;
	tcph->seq = htonl(rseq);
	tcph->ack_seq = htonl(lseq);
	tcph->window = htons(0xffff);
	tcph->check = 0;
	tcph->check = tcp_csum(iph->saddr, iph->daddr, tcph, tcph->doff * 4);

	assert(sendto(raw_sock, iph, ntohs(iph->tot_len), 0,
		      (struct sockaddr *)&lsin, sizeof(lsin)) == ntohs(iph->tot_len));
	rseq++;

	/* save the headers for later data packets */
	memcpy(data_pkt, iph, hlen);

	pnfq_wait_pkt(PNFQ_WAIT_ACK, rseq);

	/*
	 * Ensure rcv and snd bufs are large enough for restoration.
	 * SO_RCV/SNDUFFORCE achieve this but it would nice if there's a
	 * way to tell the kernel that it can return to normal queue sizing
	 * behavior afterwards - ie. turn off SOCK_RCVSNDBUF_LOCK.
	 */
	v = 2 * si->in_qsz;
	assert(!setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &v, sizeof(v)));
	v = 2 * si->out_qsz + 1024;
	assert(!setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &v, sizeof(v)));

	/*
	 * Let's restore rx queue by feeding data packets to the socket.
	 */
	printf("connection established, repopulating rx/tx queues\n");

	iph = (void *)data_pkt;
	tcph = (void *)data_pkt + sizeof(*iph);
	tcph->syn = 0;
	tcph->doff = sizeof(*tcph) / 4;

	xfer = 0;
	while (xfer < si->in_qsz) {
		int sz = min((int)si->in_qsz - xfer, MSS - hlen);

		memcpy(data_pkt + hlen, in_buf + xfer, sz);

		iph->tot_len = htons(hlen + sz);
		tcph->seq = htonl(rseq);
		tcph->ack_seq = htonl(lseq);
		tcph->check = 0;
		tcph->check = tcp_csum(iph->saddr, iph->daddr, tcph,
				       sizeof(*tcph) + sz);
		xfer += sz;
		rseq += sz;

		assert(sendto(raw_sock, iph, hlen + sz, 0,
			      (struct sockaddr *)&lsin, sizeof(lsin)) == hlen + sz);
		pnfq_wait_pkt(PNFQ_WAIT_ACK, rseq);
	}

	/*
	 * Now to tx queue.  We need to preserve the original packet
	 * boundaries to make make receiving ack and retransmission work.
	 * e.g. if some acks were in flight when the connection was
	 * hijacked and restoration results in different packet boundaries,
	 * ack may end up pointing to middle of a packet and our
	 * retransmissions may fall across the sequence the remote side is
	 * expecting.
	 *
	 * si->out_seqs[] has all the sequence numbers we need.  Force
	 * packet separation by SIOCFORCEOUTBD and send in the same sizes.
	 */
	seq = lseq;
	for (i = si->nr_out_seqs - 1; i >= 0; i--) {
		int off = seq - lseq;
		int sz = si->out_seqs[i] - seq;

		assert(!ioctl(sock, SIOCFORCEOUTBD));
		printf("snd: ---- S %08x A -------- D %05u\n", seq, sz);
		assert(send(sock, out_buf + off, sz, 0) == sz);
		seq += sz;
	}

	/*
	 * Alright, the new socket should be ready now, hopefully.  Let's
	 * drop the barrier and watch the fireworks.  At this point, all
	 * packets which could be on pnfq are valid.  Pass them through.
	 */
	printf("connection restored\n");
	pnfq_wait_pkt(PNFQ_WAIT_PASS, 0);
	flush_pnfq();

	/* turn off O_NONBLOCK for later data redirection accesses */
	assert(!fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & ~O_NONBLOCK));
	remote_sock = sock;
}

/*
 * Function for data redirection threads.  Nothing fancy.  Read from one
 * side and pass it over to the other.
 */
static void *forward_thread_fn(void *arg)
{
	int dir = (long)arg;
	int src = dir ? pcmd_sock : remote_sock;
	int dst = dir ? remote_sock : pcmd_sock;
	char buf[4096];
	int sz, ret;

	while (1) {
		sz = recv(src, buf, sizeof(buf), 0);
		if (sz <= 0)
			break;
		ret = send(dst, buf, sz, 0);
		if (ret != sz)
			break;
	}

	printf("shutting down %s -> %s\n",
	       dir ? "local" : "remote", dir ? "remote" : "local");
	shutdown(src, SHUT_RD);
	shutdown(dst, SHUT_WR);
	return NULL;
}

int main(int argc, char **argv)
{
	struct sockaddr_in sin = { .sin_family = AF_INET,
				   .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
				   .sin_port = 0, };
	pid_t pid, tid;
	socklen_t len;
	int i, ret, v;
	pthread_t pth[2];

	if (argc < 2) {
		fprintf(stderr, "Usage: parasite PID [sockfd]\n");
		return 1;
	}
	pid = strtoul(argv[1], NULL, 0);

	if (argc >= 3) {
		char path_buf[PATH_MAX], *dir;

		/*
		 * User requested TCP connection hijacking.  Set up pnfq,
		 * raw socket and construct paths for pnfq scripts.
		 */
		target_sock_fd = strtoul(argv[2], NULL, 0);
		assert((pnfq_h = nfq_open()));
		nfq_unbind_pf(pnfq_h, AF_INET);
		assert(!nfq_bind_pf(pnfq_h, AF_INET));
		assert((pnfq_qh = nfq_create_queue(pnfq_h, 0, pnfq_cb, NULL)));
		assert(!nfq_set_mode(pnfq_qh, NFQNL_COPY_PACKET, 0xffff));
		assert((raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) >= 0);
		v = 1;
		assert(!setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &v, sizeof(int)));

		/* assume scripts are in the same directory as this binary */
		ret = readlink("/proc/self/exe", path_buf, sizeof(path_buf));
		assert(ret >= 0 && ret < sizeof(path_buf) - 1);
		path_buf[ret] = '\0';

		assert(ret >= 0 && ret < PATH_MAX - sizeof(setup_pnfq_cmd_base));
		setup_pnfq_cmd[ret] = '\0';
		dir = dirname(path_buf);

		snprintf(setup_pnfq_cmd, sizeof(setup_pnfq_cmd),
			 "%s/%s", dir, setup_pnfq_cmd_base);
		snprintf(flush_pnfq_cmd, sizeof(flush_pnfq_cmd),
			 "%s/%s", dir, flush_pnfq_cmd_base);
	}

	/* verify signature at port offset in parasite blob */
	memcpy(&v, parasite_blob + PCMD_PORT_OFFSET, sizeof(v));
	assert(v == 0xdeadbeef);

	/* create control socket and record port number in the parasite blob */
	assert((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) >= 0);
	assert(!bind(listen_sock, (struct sockaddr *)&sin, sizeof(sin)));
	assert(!listen(listen_sock, 1));

	len = sizeof(sin);
	assert(!getsockname(listen_sock, (struct sockaddr *)&sin, &len));
	assert(len == sizeof(sin));
	pcmd_port = sin.sin_port;
	memcpy(parasite_blob + PCMD_PORT_OFFSET, &pcmd_port, sizeof(pcmd_port));

	/* seize and insert parasite */
	seize_process(pid);
	assert(nr_threads);
	tid = tids[0];

	insert_parasite(tid);

	/* parasite is done, detach from target process */
	for (i = 0; i < nr_threads; i++)
		assert(!ptrace(PTRACE_DETACH, tids[i], NULL, NULL));

	/* if TCP connection hijacking wasn't requested nothing more to do */
	if (target_sock_fd < 0)
		return 0;

	/* restore remote connection */
	restore_connection();

	nfq_destroy_queue(pnfq_qh);
	nfq_close(pnfq_h);

	/* forward the data */
	assert(!pthread_create(&pth[0], NULL, forward_thread_fn, (void *)(long)0));
	assert(!pthread_create(&pth[1], NULL, forward_thread_fn, (void *)(long)1));
	assert(!pthread_join(pth[0], NULL));
	assert(!pthread_join(pth[1], NULL));

	return 0;
}
