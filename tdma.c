#include <linux/module.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/moduleparam.h>
#include <linux/hrtimer.h>
#include <net/genetlink.h>

#include "netlink_sock.h"

typedef struct _Cycle 
{
    unsigned long T; // Cycle duration in ms
    unsigned int n_slots; // Number of slots
} TDMACycle;

// Holds the device info for the device we are controlling
static struct net_device *device = NULL;

// The name of the device we want to control
static char *devname = "enp0s2";

static long t_on_s = 0;             //s
static long t_on_ns = 200000000UL;  //ns
static long t_off_s = 0;            //s
static long t_off_ns = 800000000UL; //ns

module_param(t_on_ns, long, 0);
MODULE_PARM_DESC(t_on_ns, "Time spent tx in nanoseconds");
module_param(t_off_ns, long, 0);
MODULE_PARM_DESC(t_off, "Time spent not tx in nanoseconds");

static struct hrtimer on_timer;
static struct hrtimer off_timer;

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

static int handle_nl_recv_msg(struct sk_buff *skb, struct genl_info *info)
{
    // handle incorrect message format
    if (!info->attrs[GNL_RATDMA_DEVNAME])
    {
        printk(KERN_ALERT "Invalid request: Missing devname attribute\n");
        return -EINVAL;
    }
    if (!info->attrs[GNL_RATDMA_T_ON_S])
    {
        printk(KERN_ALERT "Invalid request: Missing t_on_s attribute\n");
        return -EINVAL;        
    }
    if (!info->attrs[GNL_RATDMA_T_OFF_S])
    {
        printk(KERN_ALERT "Invalid request: Missing t_off_s attribute\n");
        return -EINVAL;        
    }
    if (!info->attrs[GNL_RATDMA_T_ON_NS])
    {
        printk(KERN_ALERT "Invalid request: Missing t_on_ns attribute\n");
        return -EINVAL;        
    }
    if (!info->attrs[GNL_RATDMA_T_OFF_NS])
    {
        printk(KERN_ALERT "Invalid request: Missing t_off_ns attribute\n");
        return -EINVAL;        
    }
    if (!info->attrs[GNL_RATDMA_TX_WINDOW_WIDTH])
    {
        printk(KERN_ALERT "Invalid request: Missing tx_window_width attribute\n");
        return -EINVAL;        
    }
    if (!info->attrs[GNL_RATDMA_TUN_WIDTH])
    {
        printk(KERN_ALERT "Invalid request: Missing tun_width attribute\n");
        return -EINVAL;        
    }
    if (!info->attrs[GNL_RATDMA_OFFSET_DELAY])
    {
        printk(KERN_ALERT "Invalid request: Missing offset_delay attribute\n");
        return -EINVAL;        
    }

    printk(KERN_INFO "[TDMA]: Valid request\n");

    // update kernel variables with values from message
    devname = (unsigned char *)nla_data(info->attrs[GNL_RATDMA_DEVNAME]);
    printk(KERN_INFO "[TDMA]: devname set to %s\n", devname);

    t_on_s = nla_get_u64(info->attrs[GNL_RATDMA_T_ON_S]);
    printk(KERN_INFO "[TDMA]: t_on_s set to %lu\n", t_on_s);

    t_off_s = nla_get_u64(info->attrs[GNL_RATDMA_T_OFF_S]);
    printk(KERN_INFO "[TDMA]: t_off_s set to %lu\n", t_off_s);

    t_on_ns = nla_get_u64(info->attrs[GNL_RATDMA_T_ON_NS]);
    printk(KERN_INFO "[TDMA]: t_on_ns set to %lu\n", t_on_ns);

    t_off_ns = nla_get_u64(info->attrs[GNL_RATDMA_T_OFF_NS]);
    printk(KERN_INFO "[TDMA]: t_off_ns set to %lu\n", t_off_ns);

    // not yet used...
    // tx_window_width = nla_get_u64(info->attrs[GNL_RATDMA_TX_WINDOW_WIDTH]);
    // tun_width = nla_get_u64(info->attrs[GNL_RATDMA_TUN_WIDTH]);
    // offset_delay = nla_get_u64(info->attrs[GNL_RATDMA_OFFSET_DELAY]);
    return 0;
}

static const struct genl_ops ops[] = {
    {
        .cmd = GNL_RATDMA_RECV_MSG,
        .doit = handle_nl_recv_msg,
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

int init_netlink(void)
{
    return genl_register_family(&raTDMA_family);
}

int remove_netlink(void)
{
    return genl_unregister_family(&raTDMA_family);
}
// netlink socket to receive messages
// static struct sock *nl_socket = NULL;

// static int nl_recv_msg(struct sk_buff *skb)
// {
//     struct nlmsghdr *nlh;
//     // struct sk_buff *skb_out;
//     struct tdma_vars_t *data;
//     int pid, retval;

//     // get netlink message header from socket buffer
//     nlh = nlmsg_hdr(skb);
//     pid = nlh->nlmsg_pid;

//     printk(KERN_INFO "Entering: %s\n", __FUNCTION__);
//     if (nlh == NULL)
//     {
//         printk(KERN_ALERT "[TDMA]: skb is NULL!\n");
//         retval = -1;
//         return retval;
//     }

//     // TODO: hardcoded 1 - maybe set macros/enum for different message types
//     if (nlh->nlmsg_type == NLMSG_DONE)
//     {
//         printk(KERN_INFO "Found netlink message\n");

//         // get data struct from message
//         data = (struct tdma_vars_t *)NLMSG_DATA(nlh);

//         // set variable values
//         devname = data->devname;
//         t_on_s = data->t_on_s;
//         t_off_s = data->t_off_s;
//         t_on_ns = data->t_on_ns;
//         t_off_ns = data->t_off_ns;

//         // TODO: unimplemented variables
//         // tx_window_width = data->tx_window_width;
//         // tun_width = data->tun_width;
//         // offset_delay = data->offset_delay;

//         printk(KERN_INFO "[TDMA]: devname set to %s\n", devname);
//         printk(KERN_INFO "[TDMA]: t_on_s set to %lu\n", t_on_s);
//         printk(KERN_INFO "[TDMA]: t_off_s set to %lu\n", t_off_s);
//         printk(KERN_INFO "[TDMA]: t_on_ns set to %lu\n", t_on_ns);
//         printk(KERN_INFO "[TDMA]: t_off_ns set to %lu\n", t_off_ns);
//     }

//     retval = 0;
//     return retval;
// }

// static void nl_recv_msg_wrapper(struct sk_buff *skb)
// {
//     nl_recv_msg(skb);
// }

// static struct netlink_kernel_cfg nl_cfg = {
//     .input = nl_recv_msg_wrapper,
// };

static enum hrtimer_restart enable_queue(struct hrtimer *timer) 
{
    ktime_t time = ktime_add(ktime_get_real(), ktime_set(t_on_s, t_on_ns));
    hrtimer_start(&off_timer, time, HRTIMER_MODE_ABS);

    printk(KERN_ALERT "ENABLE QUEUE!\n");
    netif_wake_queue(device);

    return HRTIMER_NORESTART;
}

static enum hrtimer_restart disable_queue(struct hrtimer *timer) 
{
    ktime_t time = ktime_add(ktime_get_real(), ktime_set(t_off_s, t_off_ns));
    hrtimer_start(&on_timer, time, HRTIMER_MODE_ABS);

    printk(KERN_ALERT "DISABLE QUEUE!\n");
    netif_stop_queue(device);

    return HRTIMER_NORESTART;
}

static int start(void) 
{
    int retval;
    ktime_t time;

    printk(KERN_INFO "[TDMA]: Starting raTDMA netlink socket...\n");

    // start netlink socket
    retval = init_netlink();
    if (retval < 0)
    {
        printk(KERN_ALERT "[TDMA]: failed to create raTDMA netlink family\n");
        return -retval;
    }
    printk(KERN_ALERT "[TDMA]: listening on Netlink socket...\n");

    // nl_socket = netlink_kernel_create(&init_net, NETLINK_TEST_FAMILY, &nl_cfg);
    // if (IS_ERR(nl_socket))
    // {
    //     printk(KERN_ALERT "[TDMA]: failed to create Netlink socket\n");
    //     return PTR_ERR(nl_socket);
    // }

    // get device (by devname) to control
    device = dev_get_by_name(&init_net, devname);
    if (!device) 
    {
        printk(KERN_ALERT "Tap device not found!\n");
        retval = -ENODEV;
        return retval;
    }

    // initialize timers
    hrtimer_init(&on_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
    hrtimer_init(&off_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);

    on_timer.function = enable_queue;
    off_timer.function = disable_queue;

    // start timer
    time = ktime_add(ktime_get_real(), ktime_set(1, 0));
    hrtimer_start(&off_timer, time, HRTIMER_MODE_ABS);

    return 0;
}

static void stop(void) 
{
    printk(KERN_ALERT "Goodbye Module\n");

    if (remove_netlink() == 0)
    {
        printk(KERN_ALERT "[TDMA]: released Netlink socket\n");
    }
    // if (!IS_ERR(nl_socket))
    // {
    //     netlink_kernel_release(nl_socket);
    //     printk(KERN_ALERT "[TDMA]: released Netlink socket\n");
    // }
    if (device) 
    {
        netif_start_queue(device);
        dev_put(device);
    }

    hrtimer_cancel(&on_timer);
    hrtimer_cancel(&off_timer);
}

module_init(start);
module_exit(stop);

MODULE_LICENSE("GPL");
