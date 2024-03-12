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
#include <linux/netlink.h>

#include "cmdline.h"
#include "../netlink_sock.h"

// macros
#define MAX_LINE_LEN 64
//#define NETLINK_FAMILY 4200

/* function declarations */

int parse_config_file(tdma_vars_bitmap_t *bitmap, const char *filename);

// bitmap operations
void set_tdma_var_bit(tdma_vars_bitmap_t *bitmap, enum tdma_vars_e var);
bool get_tdma_var_bit(tdma_vars_bitmap_t *bitmap, enum tdma_vars_e var);
void clear_tdma_var_bit(tdma_vars_bitmap_t *bitmap, enum tdma_vars_e var);

void print_vars(void);

#endif