#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <wait.h>
#include <assert.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "parasite.h"

#define PTRACE_SEIZE		0x4206
#define PTRACE_INTERRUPT	0x4207
#define PTRACE_LISTEN		0x4208

#define PTRACE_SEIZE_DEVEL	0x80000000 /* temp flag for development */

#define PTRACE_EVENT_STOP	7

#define MAX_THREADS	1024
static pid_t tids[MAX_THREADS];
static int nr_threads;
static int ctrl_sock, ctrl_port;

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
		     "movq $14, %rdx			\n\t" /* @count */
		     "syscall				\n\t"
		     "int $0x03				\n\t"
		     "1: .ascii \"hello, world!\\n\"	\n\t"
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
		assert(!ptrace(PTRACE_POKEDATA, tid, dst + i, *(src + i)));

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
	do {
		assert(!ptrace(PTRACE_CONT, parasite, NULL, NULL));
		assert(wait4(parasite, &status, __WALL, NULL) == parasite);
	} while (!WIFEXITED(status));

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

int main(int argc, char **argv)
{
	struct sockaddr_in in = { .sin_family = AF_INET,
				  .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
				  .sin_port = 0, };
	pid_t pid, tid;
	socklen_t len;

	if (argc < 2) {
		fprintf(stderr, "Usage: parasite PID\n");
		return 1;
	}
	pid = strtoul(argv[1], NULL, 0);

	/* verify signature at port offset in parasite blob */
	memcpy(&ctrl_port, parasite_blob + CTRL_PORT_OFFSET, sizeof(ctrl_port));
	assert(ctrl_port == 0xdeadbeef);

	/* create control socket and record port number in the parasite blob */
	assert((ctrl_sock = socket(AF_INET, SOCK_STREAM, 0)) >= 0);
	assert(!bind(ctrl_sock, (struct sockaddr *)&in, sizeof(in)));
	assert(!listen(ctrl_sock, 1));

	len = sizeof(in);
	assert(!getsockname(ctrl_sock, (struct sockaddr *)&in, &len));
	assert(len == sizeof(in));
	ctrl_port = in.sin_port;
	memcpy(parasite_blob + CTRL_PORT_OFFSET, &ctrl_port, sizeof(ctrl_port));

	/* seize and insert parasite */
	seize_process(pid);
	assert(nr_threads);
	tid = tids[0];

	insert_parasite(tid);
	return 0;
}
