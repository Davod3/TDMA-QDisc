#ifndef NET_CONTROLLER_H
#define NET_CONTROLLER_H

// standard library imports
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

// custom library imports
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/genl/genl.h>

// custom imports
#include "cmdline.h"
#include "../netlink_sock.h"

/*******************************************************************************/
/* Macro Definitions */
/*******************************************************************************/

#define MAX_LINE_LEN 64

/*******************************************************************************/
/* Shared Data Structures */
/*******************************************************************************/

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

/*******************************************************************************/
/* Shared Variables */
/*******************************************************************************/

// config variables
char devname[MAX_LINE_LEN];
uint64_t t_on_s = 0;
uint64_t t_off_s = 0;
uint64_t t_on_ns = 0;
uint64_t t_off_ns = 0;
uint32_t tx_window_width = 0;
uint32_t tun_width = 0;
int32_t offset_delay = 0;

/*
 * Default Values
 *
 * whenever possible, these should reflect
 * the default values set in tdma.c, and qdisc.c
*/ 
const char def_devname[] = "enp0s2";
const uint64_t def_t_on_s = 0;
const uint64_t def_t_off_s = 0;
const uint64_t def_t_on_ns = 200000000;
const uint64_t def_t_off_ns = 800000000;
const uint32_t def_tx_window_width = 5;
const uint32_t def_tun_width = 5;
const int32_t def_offset_delay = -1;

// ANSI escape codes (colors for stdout)
const char* red = "\033[31m";
const char* green = "\033[32m";
const char* yellow = "\033[33m";
const char* blue = "\033[34m";
const char* magenta = "\033[35m";
const char* cyan = "\033[36m";
const char* reset = "\033[0m";

/*******************************************************************************/
/* Function Declarations */
/*******************************************************************************/

int parse_config_file(uint32_t *bitmap, const char *filename);

// bitmap operations
void set_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var);
bool get_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var);
void clear_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var);

// variable helpers
struct tdma_vars_t *update_vars(uint32_t *bitmap);
void print_vars(void);

#endif