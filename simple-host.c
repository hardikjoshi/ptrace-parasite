#define _GNU_SOURCE

#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>

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

int main(void)
{
	int i;
	pthread_t pth;

	for (i = 1; i < 5; i++)
		pthread_create(&pth, NULL, thread_fn, (void *)(unsigned long)i);

	thread_fn(0);
	return 0;
}
