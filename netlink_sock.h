#pragma once

#include <linux/netlink.h>

#define NETLINK_FAMILY 4200
#define NETLINK_TEST_FAMILY 25

/*
 * TDMA VARIABLE BITMAP
 * ----------------------------------------------------------------------------
 * A 32-bit unsigned integer that holds information related to
 * whether a specific variable (from tdma_vars_t) has been set
 * by netcntl, which is updated by bit operations from tdma_vars_e
 *
 * 31                                0
 * 00000000 00000000 00000000 00000000
 *                            ^^^^^^^^      
 *     (currently used by tdma_vars_e)
*/
typedef uint32_t tdma_vars_bitmap_t;

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

enum tdma_vars_e
{
    DEVNAME = 0,
    T_ON_S = 1,
    T_OFF_S = 2,
    T_ON_NS = 3,
    T_OFF_NS = 4,
    TX_WINDOW_WIDTH = 5,
    TUN_WIDTH = 6,
    OFFSET_DELAY = 7,
};

int init_netlink(void);
