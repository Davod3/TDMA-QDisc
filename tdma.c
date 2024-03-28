#ifndef TDMA_KERNEL_MOD
#define TDMA_KERNEL_MOD

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
    unsigned long T;        // Cycle duration in ms
    unsigned int n_slots;   // Number of slots
} TDMACycle;

// Holds the device info for the device we are controlling
static struct net_device *device = NULL;

// The name of the device we want to control
char devname[] = "enp0s2";

long unsigned int t_on_s = 0;             //s
long unsigned int t_on_ns = 200000000UL;  //ns
long unsigned int t_off_s = 0;            //s
long unsigned int t_off_ns = 800000000UL; //ns

// export variables
EXPORT_SYMBOL(devname);
EXPORT_SYMBOL(t_on_s);
EXPORT_SYMBOL(t_on_ns);
EXPORT_SYMBOL(t_off_s);
EXPORT_SYMBOL(t_off_ns);

module_param(t_on_ns, long, 0);
MODULE_PARM_DESC(t_on_ns, "Time spent tx in nanoseconds");
module_param(t_off_ns, long, 0);
MODULE_PARM_DESC(t_off_ns, "Time spent not tx in nanoseconds");

static struct hrtimer on_timer;
static struct hrtimer off_timer;

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

    // // start netlink socket
    // retval = init_netlink();
    // if (retval < 0)
    // {
    //     printk(KERN_ALERT "[TDMA]: failed to create raTDMA netlink family\n");
    //     return -retval;
    // }
    // printk(KERN_ALERT "[TDMA]: listening on Netlink socket...\n");

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

    // if (remove_netlink() == 0)
    // {
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
#endif