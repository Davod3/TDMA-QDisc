#pragma once

#include <linux/netlink.h>

#define NETLINK_FAMILY 4200

struct tdma_vars_t
{
    char *devname;
    uint64_t t_on_s;
    uint64_t t_off_s;
    uint64_t t_on_ns;
    uint64_t t_off_ns;
    uint32_t tx_window_width;
    uint32_t tun_width;
    int32_t offset_delay;
};

int init_netlink(void);
