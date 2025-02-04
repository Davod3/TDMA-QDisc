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
#include <malloc.h>
#include <math.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// custom library imports
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/genl/genl.h>

// custom imports
#include "librtnetlink.h"
#include "cmdline.h"
#include "../netlink_sock.h"

/*******************************************************************************/
/* Macro Definitions */
/*******************************************************************************/

#define MAX_LINE_LEN 128
#define TOPOLOGY_KMOD_PATH "../topology.ko"
#define TDMA_KMOD_PATH "../tdma.ko"
#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/*******************************************************************************/
/* Shared Data Structures */
/*******************************************************************************/

struct tdma_vars_t
{
    char *devname;
    uint32_t limit;
    int64_t n_nodes;
    int64_t slot_size;
    int64_t node_id;
    int64_t use_guard;
    int64_t self_configured;
    int64_t broadcast_port;
};

struct tc_tdma_qopt {
    __u32       limit;
	__s64		n_nodes;
	__s64		slot_size;
	__s64		node_id;
    __s64       use_guard;
    __s64       self_configured;
    __s64       broadcast_port;
};

enum tdma_vars_e
{
    DEVNAME = 0,
    LIMIT,
    NODE_ID,
    N_NODES,
    SLOT_SIZE,
    USE_GUARD,
    SELF_CONFIGURED,
    BROADCAST_PORT,
};

struct rtnl_handle rth;

/*******************************************************************************/
/* Shared Variables */
/*******************************************************************************/

// config variables
char devname[MAX_LINE_LEN];
uint32_t limit = 0;
int64_t n_nodes = 1;
int64_t slot_size = 0;
int64_t node_id = 0;
int64_t use_guard = 0;
int64_t self_configured = 0;
int64_t broadcast_port = 0;
bool tdma_mod_loaded = false;
bool topology_mod_loaded = false;

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

int parse_params(uint32_t *bitmap, struct gengetopt_args_info *args_info);

// bitmap operations
void set_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var);
bool get_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var);
void clear_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var);

// variable helpers
struct tdma_vars_t *update_vars(uint32_t *bitmap);

// kernel module helpers
int load_kernel_mod(const char *mod_path, const char *params);
int offload_kernel_mod(const char *mod_path, const char *params);
int is_module_loaded(const char *mod_name);
int start_modules(void);

// Qdisc Utility Functions
static int qdisc_modify(int cmd, const char *dev, unsigned int flags, struct tc_tdma_qopt *opt, struct tdma_vars_t *data);
int add_qdisc(struct tdma_vars_t *data);
int change_qdisc(struct tdma_vars_t *data);

#endif
