#ifndef __PARASITE_H__
#define __PARASITE_H__

#include <inttypes.h>

#define PCMD_PORT_OFFSET		64
#define PCMD_MAX_DATA			(8 << 20)

struct parasite_cmd {
	long		opcode;
	unsigned long	arg0;
	unsigned long	arg1;
	unsigned long	data_len;
};

enum {
	PCMD_SAY,	/* @data is the string to pring */
	PCMD_QUIT,	/* tell parasite to die */
};

#endif
