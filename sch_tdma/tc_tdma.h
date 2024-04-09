#include <linux/types.h>

struct tc_tdma_qopt {
	__u32		limit;

	__s64		t_frame;
	__s64		t_slot;
	__s64		t_offset;
};


enum {
	TCA_TDMA_UNSPEC,
	TCA_TDMA_PARMS,
	__TCA_TDMA_MAX,
};

#define TCA_TDMA_MAX (__TCA_TDMA_MAX - 1)
