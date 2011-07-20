#define _GNU_SOURCE

#include <sys/types.h>
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

#define PTRACE_SEIZE		0x4206
#define PTRACE_INTERRUPT	0x4207
#define PTRACE_LISTEN		0x4208
#define PTRACE_GETSIGMASK	0x4209
#define PTRACE_SETSIGMASK	0x4210

#define PTRACE_SEIZE_DEVEL	0x80000000 /* temp flag for development */

#define PTRACE_EVENT_STOP	7

#define MAX_THREADS	1024
static pid_t tids[MAX_THREADS];
static int nr_threads;

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

extern char test_blob[], mmap_blob[], clone_blob[], munmap_blob[];
extern int test_blob_size, mmap_blob_size, clone_blob_size, munmap_blob_size;

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

static unsigned long execute_blob(pid_t tid, struct user_regs_struct uregs,
				  unsigned long *pc, const char *blob,
				  size_t size, unsigned long r15)
{
	siginfo_t si;
	int i, status;

	/* inject blob into the host */
	for (i = 0; i < DIV_ROUND_UP(size, sizeof(unsigned long)); i++)
		assert(!ptrace(PTRACE_POKEDATA, tid, pc + i,
			       (void *)*((unsigned long *)blob + i)));

	uregs.orig_rax = -1;		/* avoid end-of-syscall processing */
	uregs.rip = (unsigned long)pc;	/* point to the injected blob */
	uregs.r15 = r15;		/* used as parameter to blob */
	assert(!ptrace(PTRACE_SETREGS, tid, NULL, &uregs));

	/*
	 * Let the blob run, upon completion it will trigger debug trap.
	 * After debug trap is reached, put it back to jobctl trap using
	 * INTERRUPT.
	 */
	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));
	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));
	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_GETSIGINFO, tid, NULL, &si));
	assert(si.si_code >> 8 == PTRACE_EVENT_STOP);

	/* retrieve return value */
	assert(!ptrace(PTRACE_GETREGS, tid, NULL, &uregs));
	return uregs.rax;
}

static void insert_parasite(pid_t tid)
{
	struct user_regs_struct orig_uregs;
	sigset_t orig_sigset, sigset;
	unsigned long *pc, *saved_code, count;
	unsigned long ret, *src, *dst;
	pid_t parasite;
	int i, status;

	/* save registers and sigmask, and block all signals */
	assert(!ptrace(PTRACE_GETREGS, tid, NULL, &orig_uregs));
	assert(!ptrace(PTRACE_GETSIGMASK, tid, NULL, &orig_sigset));
	assert(!sigfillset(&sigset));
	assert(!ptrace(PTRACE_SETSIGMASK, tid, NULL, &sigset));

	/* allocate space to save original code */
	count = DIV_ROUND_UP(max(test_blob_size, max(mmap_blob_size,
			     max(clone_blob_size, munmap_blob_size))),
			     sizeof(unsigned long));
	saved_code = malloc(sizeof(unsigned long) * count);
	assert(saved_code);

	/*
	 * The page %rip is on gotta be executable.  If we inject from the
	 * beginning of the page, there should be at least one page of
	 * space.  Determine the position and save the original code.
	 */
	pc = (void *)round_down(orig_uregs.rip, 4096);
	for (i = 0; i < count; i++)
		saved_code[i] = ptrace(PTRACE_PEEKDATA, tid, pc + i, NULL);

	/* say hi! */
	printf("executing test blob\n");
	execute_blob(tid, orig_uregs, pc, test_blob, test_blob_size, 0);

	/* mmap space for parasite */
	printf("executing mmap blob");
	ret = execute_blob(tid, orig_uregs, pc, mmap_blob, mmap_blob_size, 0);
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
	parasite = execute_blob(tid, orig_uregs, pc, clone_blob,
				clone_blob_size, (unsigned long)dst);
	printf(" = %d\n", parasite);
	assert(parasite >= 0);

	/* let the parasite run and wait for completion */
	assert(wait4(parasite, &status, __WALL, NULL) == parasite);
	assert(WIFSTOPPED(status));
	printf("executing parasite\n");
	assert(!ptrace(PTRACE_CONT, parasite, NULL, NULL));
	assert(wait4(parasite, &status, __WALL, NULL) == parasite);
	assert(WIFEXITED(status));

	/* parasite is done, munmap parasite_blob area */
	printf("executing munmap blob");
	ret = execute_blob(tid, orig_uregs, pc, munmap_blob, munmap_blob_size,
			   (unsigned long)dst);
	printf(" = %ld\n", ret);
	assert(!ret);

	/* restore the original code */
	for (i = 0; i < count; i++)
		assert(!ptrace(PTRACE_POKEDATA, tid, pc + i,
			       (void *)saved_code[i]));
	free(saved_code);

	/* restore the original sigmask and registers */
	assert(!ptrace(PTRACE_SETSIGMASK, tid, NULL, &orig_sigset));
	assert(!ptrace(PTRACE_SETREGS, tid, NULL, &orig_uregs));
}

int main(int argc, char **argv)
{
	pid_t pid, tid;

	if (argc < 2) {
		fprintf(stderr, "Usage: parasite PID\n");
		return 1;
	}
	pid = strtoul(argv[1], NULL, 0);

	seize_process(pid);
	assert(nr_threads);
	tid = tids[0];

	insert_parasite(tid);
	return 0;
}
