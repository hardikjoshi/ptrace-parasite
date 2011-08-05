#ifndef __PARASITE_H__
#define __PARASITE_H__

#include <inttypes.h>

#define PCMD_PORT_OFFSET	64
#define PCMD_MAX_DATA		(8 << 20)

struct parasite_cmd {
	long		opcode;
	unsigned long	arg0;
	unsigned long	arg1;
	unsigned long	data_len;
};

enum {
	PCMD_SAY,		/* @data is the string to pring */
	PCMD_QUIT,		/* tell parasite to die */
	PCMD_SOCKINFO,		/* @arg0 is fd, returns struct psockinfo */
	PCMD_PEEK_INQ,		/* @arg0 is fd, @arg1 bytes to peek */
	PCMD_PEEK_OUTQ,		/* @arg0 is fd, @arg1 bytes to peek */
	PCMD_DUP_CSOCK,		/* @arg0 is fd to dup over w/ cmd socket */
};

struct psockinfo {
	uint32_t	local_ip;
	uint32_t	remote_ip;
	uint16_t	local_port;
	uint16_t	remote_port;
	uint32_t	in_seq;
	uint32_t	out_seq;
	uint32_t	in_qsz;
	uint32_t	out_qsz;
};

#endif
