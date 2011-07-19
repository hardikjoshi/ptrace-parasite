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

#include "parasite-blob.h"

extern char test_blob[], mmap_blob[], clone_blob[];
extern int test_blob_size, mmap_blob_size, clone_blob_size;

static void __attribute__((used)) insertion_blob_container(void)
{
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
		     ".int mmap_blob_size - mmap_blob	\n\t" ::
		     "i" (sizeof(parasite_blob)),
		     "i" (PROT_EXEC | PROT_READ | PROT_WRITE),
		     "i" (MAP_ANONYMOUS | MAP_PRIVATE));

	/* expects parasite address in %r15 */
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
		     ".int clone_blob_size - clone_blob	\n\t" ::
		     "i" (CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_SIGHAND |
			  CLONE_SYSVSEM | CLONE_THREAD | CLONE_VM));
}

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

static unsigned long execute_blob(pid_t tid, const char *name, const char *blob,
				  size_t size, unsigned long r15)
{
	struct user_regs_struct uregs;
	size_t len = DIV_ROUND_UP(size, sizeof(unsigned long));
	unsigned long *buf;
	unsigned long *pc;
	int i, status;

	printf("executing %zu byte %s_blob on %d\n", size, name, tid);

	buf = malloc(sizeof(buf[0]) * len);
	assert(buf);

	assert(!ptrace(PTRACE_GETREGS, tid, NULL, &uregs));
	pc = (void *)round_down(uregs.rip, 4096);

	for (i = 0; i < len; i++) {
		buf[i] = ptrace(PTRACE_PEEKDATA, tid, pc + i, NULL);
		assert(!ptrace(PTRACE_POKEDATA, tid, pc + i,
			       (void *)*((unsigned long *)blob + i)));
	}

	uregs.orig_rax = -1;
	uregs.rip = (unsigned long)pc;
	uregs.r15 = r15;
	assert(!ptrace(PTRACE_SETREGS, tid, NULL, &uregs));

	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));
	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));
	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));

	assert(!ptrace(PTRACE_GETREGS, tid, NULL, &uregs));

	for (i = 0; i < len; i++)
		assert(!ptrace(PTRACE_POKEDATA, tid, pc + i, (void *)buf[i]));
	free(buf);

	printf("ret = %#lx\n", uregs.rax);
	return uregs.rax;
}

static void insert_parasite(pid_t tid)
{
	struct user_regs_struct orig_uregs;
	sigset_t orig_sigset, sigset;
	unsigned long ret, *src, *dst;
	int i;

	assert(!ptrace(PTRACE_GETREGS, tid, NULL, &orig_uregs));
	assert(!ptrace(PTRACE_GETSIGMASK, tid, NULL, &orig_sigset));
	assert(!sigfillset(&sigset));
	assert(!ptrace(PTRACE_SETSIGMASK, tid, NULL, &sigset));

	execute_blob(tid, "test", test_blob, test_blob_size, 0);
	ret = execute_blob(tid, "mmap", mmap_blob, mmap_blob_size, 0);
	assert(ret < -4096LU);

	dst = (void *)ret;
	src = (void *)parasite_blob;
	for (i = 0; i < DIV_ROUND_UP(sizeof(parasite_blob),
				     sizeof(unsigned long)); i++)
		assert(!ptrace(PTRACE_POKEDATA, tid, dst + i, *(src + i)));

	execute_blob(tid, "clone", clone_blob, clone_blob_size,
		     (unsigned long)dst);

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
