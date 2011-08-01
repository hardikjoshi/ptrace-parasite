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

	while ((ret = sys_recvmsg(sock, &cmd_mh, MSG_WAITALL)) == sizeof(cmd)) {
		long opcode = cmd.opcode;
		unsigned long arg0 = cmd.arg0, arg1 = cmd.arg1;
		unsigned long data_len = cmd.data_len;
		int quit = 0;

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
