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
    GNL_RATDMA_NODE_ID,
    GNL_RATDMA_N_NODES,
    GNL_RATDMA_SLOT_SIZE,
    GNL_RATDMA_USE_GUARD,
    GNL_RATDMA_SELF_CONFIGURED,
    GNL_RATDMA_BROADCAST_PORT,
    GNL_RATDMA_CLOCKLESS_SYNC,
    /* include additional variables here */
    __GNL_RATDMA_COUNT
};

enum
{
    TCA_TDMA_UNSPEC,
	TCA_TDMA_PARMS,
	__TCA_TDMA_MAX,
};

#define GNL_RATDMA_MAX (__GNL_RATDMA_COUNT - 1)
#define TCA_TDMA_MAX (__TCA_TDMA_MAX - 1)

#ifdef NETLINK_SOCK

extern char devname[64];
extern u32 limit;
extern s64 n_nodes;
extern s64 slot_size;
extern s64 node_id;
extern s64 use_guard;
extern s64 self_configured;
extern s64 broadcast_port;
extern s64 clockless_sync;

#endif

// imports for kernel-land
#ifdef TDMA_K

struct tc_tdma_qopt
{
    u32 limit;
    s64 n_nodes;
    s64 slot_size;
    s64 node_id;
    s64 use_guard;
    s64 self_configured;
    s64 broadcast_port;
    s64 clockless_sync;
};

#endif 

int handle_nl_recv_msg(struct sk_buff *skb, struct genl_info *info);
int handle_nl_send_msg(struct sk_buff *skb, struct genl_info *info);
