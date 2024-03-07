#include "netlink_sock.h"
#include <linux/genetlink.h>
#include <linux/netdevice.h>
#include <linux/printk.h>

#define NETLINK_FAMILY_NAME "raTDMA"

enum genl_ratdma_attributes {
    RATDMA_ATTR_UNSPEC,
    RATDMA_ATTR_MSG,
    __RATDMA_ATTR_MAX
};
#define RATDMA_ATTR_MAX (__RATDMA_ATTR_MAX - 1)

static struct nla_policy genl_tdma_policy[RATDMA_ATTR_MAX + 1] = {
    [RATDMA_ATTR_MSG] = { .type = NLA_U64 },
};

static int echo(struct sk_buff *skb, struct genl_info *info)
{
    printk(KERN_ALERT "ECHO!\n");
    return 0;
}
enum {
    RATDMA_COMMAND_UNSPEC,
    RATDMA_COMMAND_ECHO,
    __RATDMA_COMMAND_MAX,
};
#define RATDMA_COMMAND_MAX (__RATDMA_COMMAND_MAX - 1)

static struct genl_ops tdma_op_echo = {
    .cmd = RATDMA_COMMAND_ECHO,
    .flags = 0,
    .policy = genl_tdma_policy,
    .doit = echo,
    .dumpit = NULL,
};

int init_netlink() 
{
    struct genl_family generic_netlink_family = {
        .hdrsize = 0,
        .name = NETLINK_FAMILY_NAME,
        .version = 0,
        .maxattr = RATDMA_ATTR_MAX,
        // netnsok = ,
        // parallel_ops = ,
        .n_ops = 1,
        // n_small_ops = ,
        // n_split_ops = ,
        // n_mcgrps = ,
        // resv_start_op = ,
        .policy = genl_tdma_policy,
        // pre_doit = ,
        // post_doit = ,
        .ops = &tdma_op_echo,
        // small_ops = ,
        // split_ops = ,
        // mcgrps = ,
        .module = THIS_MODULE
    };
    return 0;
}

