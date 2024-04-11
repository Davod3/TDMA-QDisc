#ifndef NETLINK_SOCK
#define NETLINK_SOCK

#include <linux/genetlink.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "netlink_sock.h"

struct nla_policy const ratdma_policy[__GNL_RATDMA_COUNT] = {
    [GNL_RATDMA_DEVNAME]            = { .type = NLA_STRING },
    [GNL_RATDMA_T_ON_S]             = { .type = NLA_U64 },
    [GNL_RATDMA_T_OFF_S]            = { .type = NLA_U64 },
    [GNL_RATDMA_T_ON_NS]            = { .type = NLA_U64 },
    [GNL_RATDMA_T_OFF_NS]           = { .type = NLA_U64 },
    [GNL_RATDMA_TX_WINDOW_WIDTH]    = { .type = NLA_U32 },
    [GNL_RATDMA_TUN_WIDTH]          = { .type = NLA_U32 },
    [GNL_RATDMA_OFFSET_DELAY]       = { .type = NLA_S32 },
};

static const struct genl_ops ops[] = {
    {
        .cmd = GNL_RATDMA_RECV_MSG,
        .doit = handle_nl_recv_msg,
        .policy = ratdma_policy,
    },
    {
        .cmd = GNL_RATDMA_REPLY_MSG,
        .doit = handle_nl_send_msg,
        .policy = ratdma_policy,
    },
    /* define more operations here */
};

static struct genl_family raTDMA_family = {
    .name = NETLINK_FAMILY_NAME,
    .version = 1,
    .maxattr = GNL_RATDMA_MAX,
    .policy = ratdma_policy,
    .module = THIS_MODULE,
    .ops = ops,
    .n_ops = ARRAY_SIZE(ops),
};

/*******************************************************************************/
/* Netlink Operation Declarations */
/*******************************************************************************/

int handle_nl_recv_msg(struct sk_buff *skb, struct genl_info *info)
{
    // update kernel variables with values from message
    if (info->attrs[GNL_RATDMA_DEVNAME])
    {
        strncpy(devname, (const char *)nla_data(info->attrs[GNL_RATDMA_DEVNAME]), sizeof(devname)-1);
        devname[sizeof(devname)-1] = '\0'; // null-terminate string
        printk(KERN_INFO "[raTDMA]: devname set to %s\n", devname);
    }

    if (info->attrs[GNL_RATDMA_T_ON_S])
    {
        t_on_s = nla_get_u64(info->attrs[GNL_RATDMA_T_ON_S]);
        printk(KERN_INFO "[raTDMA]: t_on_s set to %lu\n", t_on_s);
    }

    if (info->attrs[GNL_RATDMA_T_OFF_S])
    {
        t_off_s = nla_get_u64(info->attrs[GNL_RATDMA_T_OFF_S]);
        printk(KERN_INFO "[raTDMA]: t_off_s set to %lu\n", t_off_s);
    }

    if (info->attrs[GNL_RATDMA_T_ON_NS])
    {
        t_on_ns = nla_get_u64(info->attrs[GNL_RATDMA_T_ON_NS]);
        printk(KERN_INFO "[raTDMA]: t_on_ns set to %lu\n", t_on_ns);
    }

    if (info->attrs[GNL_RATDMA_T_OFF_NS])
    {
        t_off_ns = nla_get_u64(info->attrs[GNL_RATDMA_T_OFF_NS]);
        printk(KERN_INFO "[raTDMA]: t_off_ns set to %lu\n", t_off_ns);
    }

    // variables not yet used...
    // tx_window_width = nla_get_u64(info->attrs[GNL_RATDMA_TX_WINDOW_WIDTH]);
    // tun_width = nla_get_u64(info->attrs[GNL_RATDMA_TUN_WIDTH]);
    // offset_delay = nla_get_u64(info->attrs[GNL_RATDMA_OFFSET_DELAY]);

    return 0;
}

int handle_nl_send_msg(struct sk_buff *skb, struct genl_info *info)
{
    // TODO handle sending replies back to user-land
    return 0;
}

/*******************************************************************************/

int __init init_netlink(void)
{
    printk(KERN_INFO "[raTDMA]: Starting raTDMA netlink socket...\n");
    return genl_register_family(&raTDMA_family);
}

void __exit remove_netlink(void)
{
    printk(KERN_INFO "[raTDMA]: releasing raTDMA Netlink socket...\n");
    genl_unregister_family(&raTDMA_family);
}

module_init(init_netlink);
module_exit(remove_netlink);

MODULE_LICENSE("GPL");
#endif