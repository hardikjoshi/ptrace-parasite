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

static long __used syscall6(int nr, unsigned long arg0, unsigned long arg1,
			    unsigned long arg2, unsigned long arg3,
			    unsigned long arg4, unsigned long arg5)
{
	register unsigned long r10 asm("r10") = r10;
	register unsigned long r8 asm("r8") = r8;
	register unsigned long r9 asm("r9") = r9;
	long ret;

	r10 = arg3;
	r8 = arg4;
	r9 = arg5;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <time.h>

#define __NR_write		1
#define __NR_close		3
#define __NR_mmap		9
#define __NR_munmap		11
#define __NR_ioctl		16
#define __NR_dup2		33
#define __NR_socket		41
#define __NR_connect		42
#define __NR_sendmsg		46
#define __NR_recvmsg		47
#define __NR_getsockname	51
#define __NR_getpeername	52
#define __NR_setsockopt		54

#define __NR_exit		60
#define __NR_gettid		186
#define __NR_time		201

#define SIOCGINSEQ	0x89b1		/* get copied_seq */
#define SIOCGOUTSEQS	0x89b2		/* get seqs for pending tx pkts */
#define SIOCSOUTSEQ	0x89b3		/* set write_seq */
#define SIOCPEEKOUTQ	0x89b4		/* peek output queue */
#define SIOCFORCEOUTBD	0x89b5		/* force output packet boundary */

static ssize_t __used sys_write(int fd, const void *buf, size_t count)
{
	return syscall3(__NR_write, fd, (unsigned long)buf, count);
}

static int __used sys_close(int fd)
{
	return syscall1(__NR_close, fd);
}

static unsigned long __used sys_mmap(void *addr, size_t len, int prot,
				     int flags, int fd, off_t offset)
{
	return syscall6(__NR_mmap, (unsigned long)addr, len, prot, flags,
			fd, offset);
}

static unsigned long __used sys_munmap(void *addr, size_t len)
{
	return syscall2(__NR_munmap, (unsigned long)addr, len);
}

static int __used sys_ioctl(int fd, int req, void *arg)
{
	return syscall3(__NR_ioctl, fd, req, (unsigned long)arg);
}

static int __used sys_dup2(int ofd, int nfd)
{
	return syscall2(__NR_dup2, ofd, nfd);
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

static int __used sys_getsockname(int fd, struct sockaddr *addr,
				  socklen_t *addrlen)
{
	int len = *addrlen, ret;

	ret = syscall3(__NR_getsockname, fd, (unsigned long)addr,
		       (unsigned long)&len);
	*addrlen = len;
	return ret;
}

static int __used sys_getpeername(int fd, struct sockaddr *addr,
				  socklen_t *addrlen)
{
	int len = *addrlen, ret;

	ret = syscall3(__NR_getpeername, fd, (unsigned long)addr,
		       (unsigned long)&len);
	*addrlen = len;
	return ret;
}

static int __used sys_setsockopt(int fd, int level, int optname,
				 char *optval, int optlen)
{
	return syscall5(__NR_setsockopt, fd, level, optname,
			(unsigned long)optval, optlen);
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
