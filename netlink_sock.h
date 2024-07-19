//#pragma once

#include <linux/types.h>
#include <linux/pkt_sched.h>

// custom NETLINK 'family name' to bind socket to
// ra = reconfigurable and adaptive
#define NETLINK_FAMILY_NAME "raTDMA"
#define NETLINK_FAMILY_MC "raTDMA-group" // multicast group

enum genl_ratdma_ops
{
    GNL_RATDMA_RECV_MSG,
    GNL_RATDMA_REPLY_MSG,
    /* add more operations for different request types */
};

enum genl_ratdma_attr_ids
{
    GNL_RATDMA_DEVNAME = 1,
    GNL_RATDMA_LIMIT,
    GNL_RATDMA_OFFSET,
    GNL_RATDMA_FRAME,
    GNL_RATDMA_SLOT,
    GNL_RATDMA_OFFSET_FUTURE,
    GNL_RATDMA_OFFSET_RELATIVE,
    GNL_RATDMA_GRAPH,
    /* include additional variables here */
    __GNL_RATDMA_COUNT
};

enum
{
    TCA_TDMA_UNSPEC,
	TCA_TDMA_PARMS,
    TCA_TDMA_OFFSET_FUTURE,
    TCA_TDMA_OFFSET_RELATIVE,
	__TCA_TDMA_MAX,
};

#define GNL_RATDMA_MAX (__GNL_RATDMA_COUNT - 1)
#define TCA_TDMA_MAX (__TCA_TDMA_MAX - 1)

#ifdef NETLINK_SOCK

extern char devname[64];
extern u32 limit;
extern s64 t_frame;
extern s64 t_slot;
extern s64 t_offset;
extern u32 offset_future;
extern u32 offset_relative;

#endif

// imports for kernel-land
#ifdef TDMA_K

struct tc_tdma_qopt
{
    u32 limit;
    s64 t_frame;
    s64 t_slot;
    s64 t_offset;
};

#endif 

int handle_nl_recv_msg(struct sk_buff *skb, struct genl_info *info);
int handle_nl_send_msg(struct sk_buff *skb, struct genl_info *info);
