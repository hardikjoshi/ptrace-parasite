/* GPLv2, read README for info */
#define _GNU_SOURCE

#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <assert.h>

static const struct timespec ts1s = { .tv_sec = 1 };

#define __NR_gettid				186

static long sys_gettid(void)
{
	long ret;

	asm volatile("syscall" : "=a" (ret) : "a" (__NR_gettid));
	return ret;
}

static void *thread_fn(void *arg)
{
	int id = (unsigned long)arg;
	pid_t tid = sys_gettid();

	while (1) {
		nanosleep(&ts1s, NULL);
		printf("thread %02d(%u): alive\n", id, tid);
	}
	return NULL;
}

static void sigaction_handler(int signo, siginfo_t *si, void *uctx)
{
	printf("signal %d si_code=%#x\n", signo, si->si_code);
}

int main(void)
{
	struct sigaction sa = { .sa_sigaction = sigaction_handler,
				.sa_flags = SA_SIGINFO };
	pthread_t pth;
	int i;

	assert(!sigaction(SIGUSR1, &sa, NULL));
	assert(!sigaction(SIGUSR2, &sa, NULL));

	for (i = 1; i < 5; i++)
		pthread_create(&pth, NULL, thread_fn, (void *)(unsigned long)i);

	thread_fn(0);
	return 0;
}
