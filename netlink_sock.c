#include <linux/genetlink.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/printk.h>

#include "netlink_sock.h"

// struct nla_policy const ratdma_policy[__GNL_RATDMA_COUNT] = {
//     [GNL_RATDMA_DEVNAME]            = { .type = NLA_STRING },
//     [GNL_RATDMA_T_ON_S]             = { .type = NLA_U64 },
//     [GNL_RATDMA_T_OFF_S]            = { .type = NLA_U64 },
//     [GNL_RATDMA_T_ON_NS]            = { .type = NLA_U64 },
//     [GNL_RATDMA_T_OFF_NS]           = { .type = NLA_U64 },
//     [GNL_RATDMA_TX_WINDOW_WIDTH]    = { .type = NLA_U32 },
//     [GNL_RATDMA_TUN_WIDTH]          = { .type = NLA_U32 },
//     [GNL_RATDMA_OFFSET_DELAY]       = { .type = NLA_S32 },
// };

// static int handle_nl_recv_msg(struct sk_buff *skb, struct genl_info *info)
// {
//     // handle incorrect message format
//     if (!info->attrs[GNL_RATDMA_DEVNAME])
//     {
//         printk(KERN_ALERT "Invalid request: Missing devname attribute\n");
//         return -EINVAL;
//     }
//     if (!info->attrs[GNL_RATDMA_T_ON_S])
//     {
//         printk(KERN_ALERT "Invalid request: Missing t_on_s attribute\n");
//         return -EINVAL;        
//     }
//     if (!info->attrs[GNL_RATDMA_T_OFF_S])
//     {
//         printk(KERN_ALERT "Invalid request: Missing t_off_s attribute\n");
//         return -EINVAL;        
//     }
//     if (!info->attrs[GNL_RATDMA_T_ON_NS])
//     {
//         printk(KERN_ALERT "Invalid request: Missing t_on_ns attribute\n");
//         return -EINVAL;        
//     }
//     if (!info->attrs[GNL_RATDMA_T_OFF_NS])
//     {
//         printk(KERN_ALERT "Invalid request: Missing t_off_ns attribute\n");
//         return -EINVAL;        
//     }
//     if (!info->attrs[GNL_RATDMA_TX_WINDOW_WIDTH])
//     {
//         printk(KERN_ALERT "Invalid request: Missing tx_window_width attribute\n");
//         return -EINVAL;        
//     }
//     if (!info->attrs[GNL_RATDMA_TUN_WIDTH])
//     {
//         printk(KERN_ALERT "Invalid request: Missing tun_width attribute\n");
//         return -EINVAL;        
//     }
//     if (!info->attrs[GNL_RATDMA_OFFSET_DELAY])
//     {
//         printk(KERN_ALERT "Invalid request: Missing offset_delay attribute\n");
//         return -EINVAL;        
//     }

//     // update kernel variables with values from message
//     devname = (unsigned char *)nla_data(info->attrs[GNL_RATDMA_DEVNAME]);
//     printk(KERN_INFO "[TDMA]: devname set to %s\n", devname);

//     t_on_s = nla_get_u64(info->attrs[GNL_RATDMA_T_ON_S]);
//     printk(KERN_INFO "[TDMA]: t_on_s set to %lu\n", t_on_s);

//     t_off_s = nla_get_u64(info->attrs[GNL_RATDMA_T_OFF_S]);
//     printk(KERN_INFO "[TDMA]: t_off_s set to %lu\n", t_off_s);

//     t_on_ns = nla_get_u64(info->attrs[GNL_RATDMA_T_ON_NS]);
//     printk(KERN_INFO "[TDMA]: t_on_ns set to %lu\n", t_on_ns);

//     t_off_ns = nla_get_u64(info->attrs[GNL_RATDMA_T_OFF_NS]);
//     printk(KERN_INFO "[TDMA]: t_off_ns set to %lu\n", t_off_ns);

//     // not yet used...
//     // tx_window_width = nla_get_u64(info->attrs[GNL_RATDMA_TX_WINDOW_WIDTH]);
//     // tun_width = nla_get_u64(info->attrs[GNL_RATDMA_TUN_WIDTH]);
//     // offset_delay = nla_get_u64(info->attrs[GNL_RATDMA_OFFSET_DELAY]);
//     return 0;
// }

// static const struct genl_ops ops[] = {
//     {
//         .cmd = GNL_RATDMA_RECV_MSG,
//         .doit = handle_nl_recv_msg,
//         .policy = ratdma_policy,
//     },
//     /* define more operations here */
// };

// static struct genl_family raTDMA_family = {
//     .name = NETLINK_FAMILY_NAME,
//     .version = 1,
//     .maxattr = GNL_RATDMA_MAX,
//     .policy = ratdma_policy,
//     .module = THIS_MODULE,
//     .ops = ops,
//     .n_ops = ARRAY_SIZE(ops),
// };

// int init_netlink(void)
// {
//     return genl_register_family(&raTDMA_family);
// }

// int remove_netlink(void)
// {
//     return genl_unregister_family(&raTDMA_family);
// }


// enum genl_ratdma_attributes {
//     RATDMA_ATTR_UNSPEC,
//     RATDMA_ATTR_MSG,
//     __RATDMA_ATTR_MAX
// };
// #define RATDMA_ATTR_MAX (__RATDMA_ATTR_MAX - 1)

// static struct nla_policy genl_tdma_policy[RATDMA_ATTR_MAX + 1] = {
//     [RATDMA_ATTR_MSG] = { .type = NLA_U64 },
// };

// static int echo(struct sk_buff *skb, struct genl_info *info)
// {
//     printk(KERN_ALERT "ECHO!\n");
//     return 0;
// }
// enum {
//     RATDMA_COMMAND_UNSPEC,
//     RATDMA_COMMAND_ECHO,
//     __RATDMA_COMMAND_MAX,
// };
// #define RATDMA_COMMAND_MAX (__RATDMA_COMMAND_MAX - 1)

// static struct genl_ops tdma_op_echo = {
//     .cmd = RATDMA_COMMAND_ECHO,
//     .flags = 0,
//     .policy = genl_tdma_policy,
//     .doit = echo,
//     .dumpit = NULL,
// };

// int init_netlink() 
// {
//     struct genl_family generic_netlink_family = {
//         .hdrsize = 0,
//         .name = NETLINK_FAMILY_NAME,
//         .version = 0,
//         .maxattr = RATDMA_ATTR_MAX,
//         // netnsok = ,
//         // parallel_ops = ,
//         .n_ops = 1,
//         // n_small_ops = ,
//         // n_split_ops = ,
//         // n_mcgrps = ,
//         // resv_start_op = ,
//         .policy = genl_tdma_policy,
//         // pre_doit = ,
//         // post_doit = ,
//         .ops = &tdma_op_echo,
//         // small_ops = ,
//         // split_ops = ,
//         // mcgrps = ,
//         .module = THIS_MODULE
//     };
//     return 0;
// }

MODULE_LICENSE("GPL");