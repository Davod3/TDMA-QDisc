//#pragma once

#include <linux/types.h>
#include <linux/pkt_sched.h>

// custom NETLINK 'family name' to bind socket to
#define NETLINK_FAMILY_NAME "raTDMA"

enum genl_ratdma_ops
{
    GNL_RATDMA_RECV_MSG,
    /* add more operations for different request types */
};

enum genl_ratdma_attr_ids
{
    GNL_RATDMA_DEVNAME = 1,
    GNL_RATDMA_T_ON_S,
    GNL_RATDMA_T_OFF_S,
    GNL_RATDMA_T_ON_NS,
    GNL_RATDMA_T_OFF_NS,
    GNL_RATDMA_TX_WINDOW_WIDTH,
    GNL_RATDMA_TUN_WIDTH,
    GNL_RATDMA_OFFSET_DELAY,
    /* include additional variables here */
    __GNL_RATDMA_COUNT
};

enum
{
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

#define GNL_RATDMA_MAX (__GNL_RATDMA_COUNT - 1)
#define TCA_TBF_TEST_MAX (__TCA_TBF_TEST_MAX - 1)

#ifdef NETLINK_SOCK
extern char devname[64];
extern u64 t_on_s;
extern u64 t_on_ns;
extern u64 t_off_s;
extern u64 t_off_ns;

struct tc_tdma_qopt
{
    struct tc_ratespec rate;
    struct tc_ratespec peakrate;
    u32 limit;
    u32 buffer;
    u32 mtu;
    s64 frame;
    s64 slot;
};
#endif

int handle_nl_recv_msg(struct sk_buff *skb, struct genl_info *info);
