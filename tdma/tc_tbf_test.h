#include <linux/types.h>
#include <linux/pkt_sched.h>

struct tc_tbf_test_qopt {
	struct tc_ratespec rate;
	struct tc_ratespec peakrate;
	__u32		limit;
	__u32		buffer;
	__u32		mtu;

	__u32		param;
};

enum {
	TCA_TBF_TEST_UNSPEC,
	TCA_TBF_TEST_PARMS,
	TCA_TBF_TEST_RTAB,
	TCA_TBF_TEST_PTAB,
	TCA_TBF_TEST_RATE64,
	TCA_TBF_TEST_PRATE64,
	TCA_TBF_TEST_BURST,
	TCA_TBF_TEST_PBURST,
	TCA_TBF_TEST_PAD,
	__TCA_TBF_TEST_MAX,
};

#define TCA_TBF_TEST_MAX (__TCA_TBF_TEST_MAX - 1)
