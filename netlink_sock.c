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
    [GNL_RATDMA_OFFSET]             = { .type = NLA_S64 },
    [GNL_RATDMA_FRAME]              = { .type = NLA_S64 },
    [GNL_RATDMA_SLOT]               = { .type = NLA_s64 },
    [GNL_RATDMA_OFFSET_FUTURE]      = { .type = NLA_U32 },
    [GNL_RATDMA_OFFSET_RELATIVE]    = { .type = NLA_U32 },
    [GNL_RATDMA_GRAPH]              = { .type = NLA_FLAG },
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

    if (info->attrs[GNL_RATDMA_OFFSET])
    {
        t_offset = nla_get_s64(info->attrs[GNL_RATDMA_OFFSET]);
        printk(KERN_INFO "[raTDMA]: t_offset set to %ld\n", t_offset);
    }

    if (info->attrs[GNL_RATDMA_FRAME])
    {
        t_frame = nla_get_s64(info->attrs[GNL_RATDMA_FRAME]);
        printk(KERN_INFO "[raTDMA]: t_frame set to %ld\n", t_frame);
    }

    if (info->attrs[GNL_RATDMA_SLOT])
    {
        t_slot = nla_get_s64(info->attrs[GNL_RATDMA_SLOT]);
        printk(KERN_INFO "[raTDMA]: t_slot set to %ld\n", t_slot);
    }

    if (info->attrs[GNL_RATDMA_OFFSET_FUTURE])
    {
        offset_future = nla_get_u32(info->attrs[GNL_RATDMA_OFFSET_FUTURE]);
        printk(KERN_INFO "[raTDMA]: offset_future set to %u\n", offset_future);
    }

    if (info->attrs[GNL_RATDMA_OFFSET_RELATIVE])
    {
        offset_relative = nla_get_u32(info->attrs[GNL_RATDMA_OFFSET_RELATIVE]);
        printk(KERN_INFO "[raTDMA]: offset_relative set to %u\n", offset_relative);
    }

    if (info->attrs[GNL_RATDMA_GRAPH])
    {
        printk(KERN_INFO "[raTDMA]: starting plot capture...\n");
        handle_nl_send_msg(skb,info);
    }

    return 0;
}

int handle_nl_send_msg(struct sk_buff *skb, struct genl_info *info)
{
    void *hdr;
    int ret = 0;
    struct sk_buff *msg;

    // msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    // if (!msg)
    // {
    //     printk(KERN_ALERT "[raTDMA]: failed to allocate message buffer\n");
    //     return -ENOMEM;
    // }

    // hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq, &raTDMA_family, 0, GNL_RATDMA_REPLY_MSG);
    // if (!hdr)
    // {
    //     printk(KERN_ALERT "[raTDMA]: failed to create netlink header\n");
    //     nlmsg_free(msg);
    //     return -EMSGSIZE;
    // }

    // if ((ret = nla_put_string(msg, GNL_RATDMA_DEVNAME, devname)))
    // {
    //     printk(KERN_ALERT "[raTDMA]: failed to create test message\n");
    //     genlmsg_cancel(msg, hdr);
    //     nlmsg_free(msg);
    //     goto out;
    // }

    // genlmsg_end(msg, hdr);
    // ret = genlmsg_reply(msg, info);
    // printk(KERN_INFO "[raTDMA]: message sent %s", __FUNCTION__);

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