//#pragma once

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

#define GNL_RATDMA_MAX (__GNL_RATDMA_COUNT - 1)

#ifdef NETLINK_SOCK
extern char devname[64];
extern long unsigned int t_on_s;
extern long unsigned int t_on_ns;
extern long unsigned int t_off_s;
extern long unsigned int t_off_ns;
#endif

int handle_nl_recv_msg(struct sk_buff *skb, struct genl_info *info);
