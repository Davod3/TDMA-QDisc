#ifndef NET_CONTROLLER_H
#define NET_CONTROLLER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "cmdline.h"

// macros
#define MAX_LINE_LEN 64
//#define NETLINK_FAMILY 4200

// function declarations
int load_kernel_mod(const char *mod_name, const char *params);
int unload_kernel_mod(const char *mod_name);
int parse_config_file(const char *filename);

#endif