#ifndef __PARASITE_H__
#define __PARASITE_H__

#define PCMD_PORT_OFFSET		64
#define PCMD_MAX_DATA			8192

struct parasite_cmd {
	long		opcode;
	unsigned long	arg;
	unsigned long	data_len;
};

enum {
	PCMD_SAY,
	PCMD_QUIT,
};

#endif
