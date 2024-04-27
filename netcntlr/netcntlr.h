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
#include "cmdline.h"
#include "../netlink_sock.h"

/*******************************************************************************/
/* Macro Definitions */
/*******************************************************************************/

#define MAX_LINE_LEN 128
#define NETLINK_SOCK_KMOD_PATH "../netlink_sock.ko"
#define TDMA_KMOD_PATH "../tdma.ko"
#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/*******************************************************************************/
/* Shared Data Structures */
/*******************************************************************************/

struct tdma_vars_t
{
    char *devname;
    uint32_t limit;
    int64_t t_frame;
    int64_t t_slot;
    int64_t t_offset;
    uint32_t offset_future;
    uint32_t offset_relative;
    bool graph;
};

struct tc_tdma_qopt
{
    struct tc_ratespec rate;
    struct tc_ratespec peakrate;
    uint32_t limit;
    uint32_t buffer;
    uint32_t mtu;
    int64_t frame;
    int64_t slot;
};

enum tdma_vars_e
{
    DEVNAME = 0,
    LIMIT,
    OFFSET,
    FRAME,
    SLOT,
    OFFSET_FUTURE,
    OFFSET_RELATIVE,
    GRAPH
};

struct rtnl_handle 
{
	int			        fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	uint32_t			seq;
	uint32_t			dump;
	int			        proto;
	FILE		       *dump_fp;
    #define RTNL_HANDLE_F_LISTEN_ALL_NSID		0x01
    #define RTNL_HANDLE_F_SUPPRESS_NLERR		0x02
    #define RTNL_HANDLE_F_STRICT_CHK		    0x04
	int			flags;
};

struct rtnl_handle rth;

/*******************************************************************************/
/* Shared Variables */
/*******************************************************************************/

// config variables
char devname[MAX_LINE_LEN];
uint32_t limit = 0;
int64_t t_frame = 0;
int64_t t_slot = 0;
int64_t t_offset = 0;
uint32_t offset_future = 0;
uint32_t offset_relative = 0;
bool graph = false;
bool tdma_mod_loaded = false;
bool netlink_sock_mod_loaded = false;

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
void print_vars(void);

// kernel module helpers
int load_kernel_mod(const char *mod_path, const char *params);
int offload_kernel_mod(const char *mod_path, const char *params);
int is_module_loaded(const char *mod_name);
int start_modules(void);

// RTNL Utility Functions
int add_attr(struct nlmsghdr *n, int maxlen, int type, void *data, int alen);
struct rtattr *add_attr_nest(struct nlmsghdr *n, int maxlen, int type);
int add_attr_nest_end(struct nlmsghdr *n, struct rtattr *nest);
void cls(struct rtnl_handle *rtnl);
int opn(struct rtnl_handle *rtnl);
static int talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, struct nlmsghdr **answer);
static int qdisc_modify(int cmd, const char *dev, unsigned int flags, struct tc_tdma_qopt *opt);

#endif
