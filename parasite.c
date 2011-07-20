#include <sys/types.h>
#include <time.h>

#define STACK_SIZE	16384

static unsigned long __attribute__((used)) stack_area[STACK_SIZE / sizeof(unsigned long)];

#define __NR_write	1
#define __NR_exit	60
#define __NR_gettid	186
#define __NR_time	201

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

static ssize_t sys_write(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (__NR_write), "D" (fd), "S" (buf), "d" (count));
	return ret;
}

static long sys_exit(int error_code)
{
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (__NR_exit), "D" (error_code));
	return ret;
}

static long sys_gettid(void)
{
	long ret;

	asm volatile("syscall" : "=a" (ret) : "a" (__NR_gettid));
	return ret;
}

static long sys_time(void)
{
	long ret;

	asm volatile("syscall" : "=a" (ret) : "a" (__NR_time), "D" (NULL));
	return ret;
}

static char *simple_long_to_str(long v, int *len)
{
	static char buf[128];
	char *p = &buf[128];

	*len = 0;
	while (v) {
		*--p = '0' + (v % 10);
		(*len)++;
		v /= 10;
	}
	return p;
}

static void __attribute__((used)) parasite(void)
{
	static const char str0[] = "parasite: hello, world!\n";
	static const char str1[] = "parasite: tid / time = ";
	pid_t tid = sys_gettid();
	time_t time = sys_time();
	char *p;
	int len;

	sys_write(1, str0, sizeof(str0));
	sys_write(1, str1, sizeof(str1));

	p = simple_long_to_str(tid, &len);
	sys_write(1, p, len);
	sys_write(1, " / ", 3);
	p = simple_long_to_str(time, &len);
	sys_write(1, p, len);
	sys_write(1, "\n", 1);

	sys_exit(0);
}

static void __attribute__((used)) parasite_entry_container(void)
{
	/*
	 * Entry code sets up stack frame and calls parasite which
	 * shouldn't return.  This is put inside .entry.text section which
	 * will be linked at the head of the blob by linker script.
	 */
	asm volatile(".pushsection .entry.text, \"ax\"			\n\t"
		     "leaq stack_area + "__stringify(STACK_SIZE)"(%rip), %rsp\n\t"
		     "pushq $0						\n\t"
		     "movq %rsp, %rbp					\n\t"
		     "call parasite					\n\t"
		     "int $0x03						\n\t"
		     ".popsection					\n\t");
}
