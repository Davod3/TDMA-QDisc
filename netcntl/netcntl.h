#ifndef NET_CONTROLLER_H
#define NET_CONTROLLER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/genl/genl.h>

#include "cmdline.h"
#include "../netlink_sock.h"

// macros
#define MAX_LINE_LEN 64
//#define NETLINK_FAMILY 4200

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

// config variables
char devname[MAX_LINE_LEN];
uint64_t t_on_s = 0;
uint64_t t_off_s = 0;
uint64_t t_on_ns = 0;
uint64_t t_off_ns = 0;
uint32_t tx_window_width = 0;
uint32_t tun_width = 0;
int32_t offset_delay = 0;

// default values
char def_devname[] = "enp0s2";
uint64_t def_t_on_s = 0;
uint64_t def_t_off_s = 0;
uint64_t def_t_on_ns = 200000000;
uint64_t def_t_off_ns = 800000000;
uint32_t def_tx_window_width = 5;
uint32_t def_tun_width = 5;
int32_t def_offset_delay = -1;

/* function declarations */

int parse_config_file(uint32_t *bitmap, const char *filename);

// bitmap operations
void set_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var);
bool get_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var);
void clear_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var);

// netlink operations
//void create_netlink_socket(struct nl_sock *sk, int *genl_family);
//void create_nlmsg(struct nl_msg *msg, int *genl_family, struct tdma_vars_t *data);

// variable helpers
struct tdma_vars_t *update_vars(uint32_t *bitmap);
void print_vars(void);

#endif