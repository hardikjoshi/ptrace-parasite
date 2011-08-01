#define __used __attribute__((__used__)) 

static long __used syscall0(int nr)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr)
		     : "memory");
	return ret;
}

static long __used syscall1(int nr, unsigned long arg0)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0)
		     : "memory");
	return ret;
}

static long __used syscall2(int nr, unsigned long arg0, unsigned long arg1)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1)
		     : "memory");
	return ret;
}

static long __used syscall3(int nr, unsigned long arg0, unsigned long arg1,
			    unsigned long arg2)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

static long __used syscall4(int nr, unsigned long arg0, unsigned long arg1,
			    unsigned long arg2, unsigned long arg3)
{
	register unsigned long r10 asm("r10") = r10;
	long ret;

	r10 = arg3;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

static long __used syscall5(int nr, unsigned long arg0, unsigned long arg1,
			    unsigned long arg2, unsigned long arg3,
			    unsigned long arg4)
{
	register unsigned long r10 asm("r10") = r10;
	register unsigned long r8 asm("r8") = r8;
	long ret;

	r10 = arg3;
	r8 = arg4;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>

#define __NR_write	1
#define __NR_close	3
#define __NR_exit	60
#define __NR_gettid	186
#define __NR_time	201
#define __NR_socket	41
#define __NR_connect	42
#define __NR_sendmsg	46
#define __NR_recvmsg	47

static ssize_t __used sys_write(int fd, const void *buf, size_t count)
{
	return syscall3(__NR_write, fd, (unsigned long)buf, count);
}

static int __used sys_close(int fd)
{
	return syscall1(__NR_close, fd);
}

static int __used sys_exit(int error_code)
{
	return syscall1(__NR_exit, error_code);
}

static long __used sys_gettid(void)
{
	return syscall0(__NR_gettid);
}

static time_t __used sys_time(void)
{
	return syscall0(__NR_time);
}

static int __used sys_socket(int family, int type, int protocol)
{
	return syscall3(__NR_socket, family, type, protocol);
}

static int __used sys_connect(int fd, struct sockaddr *addr, socklen_t addrlen)
{
	return syscall3(__NR_connect, fd, (unsigned long)addr, addrlen);
}

static ssize_t __used sys_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	return syscall3(__NR_sendmsg, fd, (unsigned long)msg, flags);
}

static ssize_t __used sys_recvmsg(int fd, struct msghdr *msg, int flags)
{
	return syscall3(__NR_recvmsg, fd, (unsigned long)msg, flags);
}
