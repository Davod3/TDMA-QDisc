#include <linux/module.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/moduleparam.h>
#include <linux/hrtimer.h>

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

// netlink socket to receive messages
static struct sock *nl_socket = NULL;

static int nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    // struct sk_buff *skb_out;
    struct tdma_vars_t *data;
    int pid, retval;

    // get netlink message header from socket buffer
    nlh = nlmsg_hdr(skb);
    pid = nlh->nlmsg_pid;

    if (nlh == NULL)
    {
        printk(KERN_ALERT "[TDMA]: skb is NULL!\n");
        retval = -1;
        return retval;
    }

    // TODO: hardcoded 1 - maybe set macros/enum for different message types
    if (nlh->nlmsg_type == 1)
    {
        // get data struct from message
        data = (struct tdma_vars_t *)NLMSG_DATA(nlh);

        // set variable values
        devname = data->devname;
        t_on_s = data->t_on_s;
        t_off_s = data->t_off_s;
        t_on_ns = data->t_on_ns;
        t_off_ns = data->t_off_ns;

        // TODO: unimplemented variables
        // tx_window_width = data->tx_window_width;
        // tun_width = data->tun_width;
        // offset_delay = data->offset_delay;

        printk(KERN_ALERT "[TDMA]: devname set to %s\n", devname);
        printk(KERN_ALERT "[TDMA]: t_on_s set to %lu\n", t_on_s);
        printk(KERN_ALERT "[TDMA]: t_off_s set to %lu\n", t_off_s);
        printk(KERN_ALERT "[TDMA]: t_on_ns set to %lu\n", t_on_ns);
        printk(KERN_ALERT "[TDMA]: t_off_ns set to %lu\n", t_off_ns);
    }

    retval = 0;
    return retval;
}

static void nl_recv_msg_wrapper(struct sk_buff *skb)
{
    nl_recv_msg(skb);
}

static struct netlink_kernel_cfg nl_cfg = {
    .input = nl_recv_msg_wrapper,
};

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
    ktime_t time;

    // start netlink socket
    nl_socket = netlink_kernel_create(&init_net, NETLINK_FAMILY, &nl_cfg);
    if (!nl_socket)
    {
        printk(KERN_ALERT "[TDMA]: failed to create Netlink socket\n");
        return -ENOMEM;
    }
    printk(KERN_ALERT "[TDMA]: listening on Netlink socket...\n");

    // get device (by devname) to control
    device = dev_get_by_name(&init_net, devname);
    if(!device) 
    {
        printk(KERN_ALERT "Tap device not found!\n");
        return -ENODEV;
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

    if (nl_socket)
    {
        netlink_kernel_release(nl_socket);
        printk(KERN_ALERT "[TDMA]: released Netlink socket\n");
    }
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
