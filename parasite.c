#include <inttypes.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "parasite.h"
#include "syscall.h"

#define STACK_SIZE	16384

static unsigned long __attribute__((used)) stack_area[STACK_SIZE / sizeof(unsigned long)];
extern const int ctrl_port;

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

static char *long_to_str(long v)
{
	static char buf[128];
	char *p = &buf[128];
	int minus = 0;

	if (v < 0) {
		minus = 1;
		v = -v;
	}

	while (v) {
		*--p = '0' + (v % 10);
		v /= 10;
	}
	if (minus)
		*--p = '-';

	return p;
}

static void print_msg(const char *msg)
{
	int sz;

	for (sz = 0; msg[sz] != '\0'; sz++)
		;
	sys_write(1, msg, sz);
}

static int get_sockinfo(int fd, struct psockinfo *si)
{
	const char *emsg;
	struct sockaddr_in sin;
	socklen_t slen;
	int ret;

	slen = sizeof(sin);
	emsg = "getsockname";
	if ((ret = sys_getsockname(fd, (struct sockaddr *)&sin, &slen)))
		goto out;

	emsg = "getsockname invalid";
	ret = -EINVAL;
	if (slen != sizeof(sin) || sin.sin_family != AF_INET)
		goto out;

	si->local_ip = sin.sin_addr.s_addr;
	si->local_port = sin.sin_port;

	slen = sizeof(sin);
	emsg = "getpeername";
	if ((ret = sys_getpeername(fd, (struct sockaddr *)&sin, &slen)))
		goto out;

	emsg = "getpeername invalid";
	ret = -EINVAL;
	if (slen != sizeof(sin) || sin.sin_family != AF_INET)
		goto out;

	si->remote_ip = sin.sin_addr.s_addr;
	si->remote_port = sin.sin_port;

	emsg = "SIOCINQ";
	if ((ret = sys_ioctl(fd, SIOCINQ, &si->in_qsz)))
		goto out;

	emsg = "SIOCOUTQ";
	if ((ret = sys_ioctl(fd, SIOCOUTQ, &si->out_qsz)))
		goto out;

	emsg = "SIOCGINSEQ";
	if ((ret = sys_ioctl(fd, SIOCGINSEQ, &si->in_seq)))
		goto out;

	emsg = "SIOCGOUTSEQS";
	si->out_seqs[0] = sizeof(si->out_seqs);
	ret = sys_ioctl(fd, SIOCGOUTSEQS, si->out_seqs);
	if (ret > sizeof(si->out_seqs))
		ret = -EOVERFLOW;
	if (ret < 0)
		goto out;
	si->nr_out_seqs = ret / sizeof(uint32_t);
	ret = 0;
out:
	if (ret < 0) {
		print_msg("PARASITE get_sockinfo failed: ");
		print_msg(emsg);
		print_msg("\n");
	}
	return ret;
}

static void __attribute__((used)) parasite(int cmd_port)
{
	struct sockaddr_in in = { .sin_family = AF_INET,
				  .sin_addr.s_addr = 0x0100007f,
				  .sin_port = cmd_port };
	const char *emsg = NULL;
	struct parasite_cmd cmd = { };
	struct iovec cmd_iov = { .iov_base = &cmd, .iov_len = sizeof(cmd) };
	struct msghdr cmd_mh = { .msg_iov = &cmd_iov, .msg_iovlen = 1 };
	struct iovec data_iov = { .iov_len = PCMD_MAX_DATA };
	struct msghdr data_mh = { .msg_iov = &data_iov, .msg_iovlen = 1 };
	char *data = NULL;
	int sock = -1;
	long ret;

	/* say hi, prepare data buffer and connect to mothership */
	print_msg("PARASITE STARTED\n");

	ret = sys_mmap(NULL, PCMD_MAX_DATA, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ret < 0 && ret >= -4096) {
		emsg = "mmap";
		goto exit;
	}
	data = (void *)ret;
	data_iov.iov_base = data;

	if ((ret = sys_socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		emsg = "socket";
		goto exit;
	}
	sock = ret;

	if ((ret = sys_connect(sock, (struct sockaddr *)&in, sizeof(in))) < 0) {
		emsg = "connect";
		goto exit;
	}

	/* receive instructions from mothership and execute them */
	while ((ret = sys_recvmsg(sock, &cmd_mh, MSG_WAITALL)) == sizeof(cmd)) {
		long opcode = cmd.opcode;
		unsigned long arg0 = cmd.arg0, arg1 = cmd.arg1;
		unsigned long data_len = cmd.data_len;
		int quit = 0;

		/*
		 * Command info is available through the above variables.
		 * @cmd is cleared and used for response data from now on.
		 */
		cmd = (struct parasite_cmd){};

		data_iov.iov_len = data_len;
		if (data_len &&
		    (ret = sys_recvmsg(sock, &data_mh, MSG_WAITALL)) != data_len) {
			emsg = "data recvmsg";
			goto exit;
		}

		ret = 0;
		switch (opcode) {
		case PCMD_SAY:
			print_msg("PARASITE SAY: ");
			sys_write(arg0, data, data_len);
			break;

		case PCMD_QUIT:
			quit = 1;
			break;

		case PCMD_SOCKINFO:
			ret = get_sockinfo(arg0, (void *)data);
			cmd.data_len = sizeof(struct psockinfo);
			break;

		case PCMD_PEEK_INQ: {
			struct iovec iov = { .iov_base = data, .iov_len = arg1 };
			struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1 };

			ret = sys_recvmsg(arg0, &mh, MSG_WAITALL | MSG_PEEK);
			cmd.data_len = ret > 0 ? ret : 0;
			break;
		}

		case PCMD_PEEK_OUTQ:
			*(volatile uint32_t *)data = arg1;
			ret = sys_ioctl(arg0, SIOCPEEKOUTQ, data);
			cmd.data_len = ret > 0 ? ret : 0;
			break;

		case PCMD_DUP_CSOCK: {
			struct linger lg = { .l_onoff = 1, .l_linger = 0 };

			/* try to set LINGER */
			ret = sys_setsockopt(arg0, SOL_SOCKET, SO_LINGER,
					     (void *)&lg, sizeof(lg));
			if (ret)
				print_msg("PARASITE SO_LINGER failed\n");

			ret = sys_dup2(sock, arg0);
			break;
		}

		default:
			print_msg("PARASITE unknown command ");
			print_msg(long_to_str(opcode));
			print_msg("\n");
			ret = -EINVAL;
			break;
		}

		cmd.opcode = ret;
		if ((ret = sys_sendmsg(sock, &cmd_mh, 0)) != sizeof(cmd)) {
			emsg = "cmd sendmsg";
			goto exit;
		}
		data_iov.iov_len = cmd.data_len;
		if (cmd.data_len &&
		    (ret = sys_sendmsg(sock, &data_mh, 0)) != cmd.data_len) {
			emsg = "data sendmsg";
			goto exit;
		}

		if (quit)
			goto exit;
	}
	emsg = "cmd recvmsg";
exit:
	if (emsg) {
		print_msg("PARASITE ERROR: ");
		print_msg(emsg);
		print_msg(" ret=");
		print_msg(long_to_str(ret));
		print_msg("\n");
	}
	if (data)
		sys_munmap(data, PCMD_MAX_DATA);
	if (sock >= 0)
		sys_close(sock);
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
		     "movl cmd_port(%rip), %edi				\n\t"
		     "call parasite					\n\t"
		     "int $0x03						\n\t"
		     ".align "__stringify(PCMD_PORT_OFFSET)"		\n\t"
		     "cmd_port: .int 0xdeadbeef				\n\t"
		     ".popsection					\n\t");
}
