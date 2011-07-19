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
#include <signal.h>

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

extern char insertion_blob[];
extern int insertion_blob_size;

static void __attribute__((used)) insertion_blob_container(void)
{
	asm __volatile__(".globl insertion_blob		\n\t"
			 "insertion_blob:		\n\t"
			 "movq $1, %rax			\n\t"
			 "movq $1, %rdi			\n\t"
			 "1:leaq 1f(%rip), %rsi		\n\t"
			 "movq $14, %rdx		\n\t"
			 "syscall			\n\t"
			 "int $0x03			\n\t"
			 "1: .ascii \"hello, world!\\n\"\n\t"
			 "2:				\n\t"
			 ".globl insertion_blob_size	\n\t"
			 "insertion_blob_size:		\n\t"
			 ".int 2b - insertion_blob	\n\t");
}

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

static void insert_parasite(pid_t tid)
{
	size_t len = DIV_ROUND_UP(insertion_blob_size, sizeof(unsigned long));
	unsigned long *buf;
	struct user_regs_struct orig_uregs, uregs;
	sigset_t orig_sigset, sigset;
	unsigned long *pc;
	int i, status;

	printf("insertion_blob_size=%d\n", insertion_blob_size);

	buf = malloc(sizeof(buf[0]) * len);
	assert(buf);

	assert(!ptrace(PTRACE_GETREGS, tid, NULL, &orig_uregs));
	assert(!ptrace(PTRACE_GETSIGMASK, tid, NULL, &orig_sigset));

	assert(!sigfillset(&sigset));
	assert(!ptrace(PTRACE_SETSIGMASK, tid, NULL, &sigset));

	uregs = orig_uregs;
	pc = (void *)uregs.rip;

	for (i = 0; i < len; i++) {
		buf[i] = ptrace(PTRACE_PEEKDATA, tid, pc + i, NULL);
		assert(!ptrace(PTRACE_POKEDATA, tid, pc + i,
			       (void *)*((unsigned long *)insertion_blob + i)));
	}

	uregs.orig_rax = -1;
	assert(!ptrace(PTRACE_SETREGS, tid, NULL, &uregs));

	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));
	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));
	assert(!ptrace(PTRACE_INTERRUPT, tid, NULL, NULL));
	assert(!ptrace(PTRACE_CONT, tid, NULL, NULL));
	assert(wait4(tid, &status, __WALL, NULL) == tid);
	assert(WIFSTOPPED(status));

	for (i = 0; i < len; i++)
		assert(!ptrace(PTRACE_POKEDATA, tid, pc + i, (void *)buf[i]));

	assert(!ptrace(PTRACE_SETSIGMASK, tid, NULL, &orig_sigset));
	assert(!ptrace(PTRACE_SETREGS, tid, NULL, &orig_uregs));

	free(buf);
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
