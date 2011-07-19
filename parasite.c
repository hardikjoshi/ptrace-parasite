#include <sys/types.h>
#include <time.h>

#define STACK_SIZE	16384

static unsigned long __attribute__((used)) stack_area[STACK_SIZE / sizeof(unsigned long)];

#define __NR_write	1
#define __NR_nanosleep	35
#define __NR_exit	60
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

static void __attribute__((used)) parasite(void)
{
	static const char str[] = "parasite: hello, world!\n";

	sys_write(1, str, sizeof(str));
	sys_exit(0);
}

static void __attribute__((used)) parasite_entry_container(void)
{
	asm volatile(".pushsection .entry.text, \"ax\"			\n\t"
		     "leaq stack_area + "__stringify(STACK_SIZE)"(%rip), %rsp\n\t"
		     "pushq $0						\n\t"
		     "movq %rsp, %rbp					\n\t"
		     "call parasite					\n\t"
		     "int $0x03						\n\t"
		     ".popsection					\n\t");
}
