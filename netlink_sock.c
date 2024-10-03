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
    [GNL_RATDMA_LIMIT]              = { .type = NLA_U32 },
    [GNL_RATDMA_NODE_ID]             = { .type = NLA_S64 },
    [GNL_RATDMA_N_NODES]              = { .type = NLA_S64 },
    [GNL_RATDMA_SLOT_SIZE]               = { .type = NLA_S64 },
};

static const struct genl_ops ops[] = {
    {
        .cmd = GNL_RATDMA_RECV_MSG, // message type
        .doit = handle_nl_recv_msg, // callback function
        .policy = ratdma_policy,    // policy to use
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

    printk(KERN_DEBUG "NETLINK MESSAGE RECEIVED!!!!\n");

    // update kernel variables with values from message
    if (info->attrs[GNL_RATDMA_DEVNAME])
    {
        strncpy(devname, (const char *)nla_data(info->attrs[GNL_RATDMA_DEVNAME]), sizeof(devname)-1);
        devname[sizeof(devname)-1] = '\0'; // null-terminate string
        printk(KERN_INFO "[raTDMA]: devname set to %s\n", devname);
    }

    if (info->attrs[GNL_RATDMA_LIMIT])
    {
        limit = nla_get_u32(info->attrs[GNL_RATDMA_LIMIT]);
        printk(KERN_INFO "[raTDMA]: limit set to %ld\n", limit);
    }


    if (info->attrs[GNL_RATDMA_NODE_ID])
    {
        node_id = nla_get_s64(info->attrs[GNL_RATDMA_NODE_ID]);
        printk(KERN_INFO "[raTDMA]: t_offset set to %ld\n", node_id);
    }

    if (info->attrs[GNL_RATDMA_N_NODES])
    {
        n_nodes = nla_get_s64(info->attrs[GNL_RATDMA_N_NODES]);
        printk(KERN_INFO "[raTDMA]: t_frame set to %ld\n", n_nodes);
    }

    if (info->attrs[GNL_RATDMA_SLOT_SIZE])
    {
        slot_size = nla_get_s64(info->attrs[GNL_RATDMA_SLOT_SIZE]);
        printk(KERN_INFO "[raTDMA]: t_slot set to %ld\n", slot_size);
    }

    return 0;
}

int handle_nl_send_msg(struct sk_buff *skb, struct genl_info *info)
{
    void *hdr;
    int ret = 0;
    struct sk_buff *msg;

out:
    return ret;
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