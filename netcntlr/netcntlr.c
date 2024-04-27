#include "netcntlr.h"

int add_attr(struct nlmsghdr *n, int maxlen, int type, void *data, int alen) 
{
    int len = RTA_LENGTH(alen), nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    struct rtattr *rta;

    if (nlmsg_len > maxlen) 
	{
        fprintf(stderr, "too long message\n");
        return -1;
    }

    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = nlmsg_len;
    return 0;
}

struct rtattr *add_attr_nest(struct nlmsghdr *n, int maxlen, int type) 
{
    struct rtattr *nest = NLMSG_TAIL(n);
    add_attr(n, maxlen, type, NULL, 0);
    return nest;
}

int add_attr_nest_end(struct nlmsghdr *n, struct rtattr *nest) 
{
    nest->rta_len = ((void *) NLMSG_TAIL(n)) - ((void *) nest);
    return n->nlmsg_len;
}

void cls(struct rtnl_handle *rtnl) 
{
	if (rtnl->fd >= 0) 
	{
		close(rtnl->fd);
		rtnl->fd = -1;
	}
}

int opn(struct rtnl_handle *rtnl) 
{
    socklen_t addr_len;
    int sndbuf = 32768;
    int rcvbuf = 1024 * 1024;
    int one = 1;

    memset(rtnl, 0, sizeof(*rtnl));
    rtnl->proto = NETLINK_ROUTE;
    rtnl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (rtnl->fd < 0) 
	{
        return -1;
    }
    
    if (setsockopt(rtnl->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0 || setsockopt(rtnl->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
        goto err;

    setsockopt(rtnl->fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));
    
    memset(&rtnl->local, 0, sizeof(rtnl->local));
    rtnl->local.nl_family = AF_NETLINK;
    rtnl->local.nl_groups = 0;

    if (bind(rtnl->fd, (struct sockaddr *)(&rtnl->local), sizeof(rtnl->local)) < 0)
        goto err;
    addr_len = sizeof(rtnl->local);
    if (getsockname(rtnl->fd, (struct sockaddr *)&rtnl->local, &addr_len) < 0)
        goto err;
    if (addr_len != sizeof(rtnl->local))
        goto err;
    if (rtnl->local.nl_family != AF_NETLINK)
        goto err;
    rtnl->seq = time(NULL);
    return 0;

err:
    fprintf(stderr, "err\n");
    cls(rtnl);
    return -1;
}

static int talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, struct nlmsghdr **answer) 
{
    int fd = rtnl->fd;
    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK, };
    struct iovec iov = {
        .iov_base = n,
        .iov_len = n->nlmsg_len,
    };
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    n->nlmsg_seq = ++rtnl->seq;
    n->nlmsg_flags |= NLM_F_ACK;

    if (sendmsg(fd, &msg, 0) < 0)
        return -1;
    return 0;
}

static int qdisc_modify(int cmd, const char *dev, unsigned int flags, struct tc_tdma_qopt *opt) 
{
    // cmd = RTM_NEWQDISC // add | change | replace | link
    // cmd = RTM_DELQDISC // delete
    // flags = NLM_F_EXCL | NLM_F_CREATE // add
    // flags = 0 // change | delete
    // flags = NLM_F_CREATE | NLM_F_REPLACE // replace
    // flags = NLM_F_REPLACE // link

    // char d[IFNAMSIZ] = {};
    char d[16] = {}; // device (interface) name
    // char *d = "enp0s1";
    // strncpy(d, "enp0s1", 16);
    strncpy(d, dev, 16);
    // char k[FILTER_NAMESZ] = {};
    char k[16] = {}; // qdisc (kind) name
    strncpy(k, "tdma", 16);
    // char *k = "tdma";

    struct {
        struct nlmsghdr n;
        struct tcmsg t;
	char buf[64 * 1024];
        // char buf[TCA_BUF_MAX];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | flags,
        .n.nlmsg_type = cmd,

        .t.tcm_family = AF_UNSPEC, // unsigned char
        // .t.tcm_ifindex // int // required
        // .t.tcm_handle = handle, // __u32 // optional
        .t.tcm_parent = TC_H_ROOT, // __u32
        // .t.tcm_info = 0 // __u32 // optional
    };

    struct rtattr *tail;

    // BEGIN hardcoding    // END hardcoding

    if (k[0])
        // addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k) + 1);
        add_attr(&req.n, sizeof(req), TCA_KIND, k, strlen(k) + 1);

    // Add TCA_OPTIONS
    // tail = addattr_nest(&req.n, 1024, TCA_OPTIONS);
    tail = add_attr_nest(&req.n, 1024, TCA_OPTIONS);
    // addattr_l(&req.n, 2024, TCA_TBF_PARMS, opt, sizeof(*opt));
    // addattr_l(&req.n, 2024, TCA_TDMA_PARMS, opt, sizeof(*opt));
    add_attr(&req.n, 2024, TCA_TDMA_PARMS, opt, sizeof(*opt));
    // addattr_nest_end(&req.n, tail);
    add_attr_nest_end(&req.n, tail);

    // if (d[0]) {
    //     int idx;

    //     ll_init_map(&rth);

    //     idx = ll_name_to_index(d);
    //     if (!idx)
    //         return 1;
    //     req.t.tcm_ifindex = idx;
    // }
    // HARDCODING
    req.t.tcm_ifindex = 2;

    // if (rtnl_talk(&rth, &req.n, NULL) < 0)
    if (talk(&rth, &req.n, NULL) < 0)
        return 1;
        
    return 0;
}

int start_modules(void)
{
	if (!netlink_sock_mod_loaded && is_module_loaded("netlink_sock") == 0)
	{
		load_kernel_mod(NETLINK_SOCK_KMOD_PATH, NULL);
		netlink_sock_mod_loaded = true;
	}

	if (!tdma_mod_loaded && is_module_loaded("tdma") == 0)
	{
		load_kernel_mod(TDMA_KMOD_PATH, NULL);
		tdma_mod_loaded = true;
	}

	return 0;
}

int is_module_loaded(const char *mod_name)
{
	FILE *fp;
	char buf[MAX_LINE_LEN];
	int found = 0;

	// open /proc/modules file
	fp = fopen("/proc/modules", "r");
	if (fp == NULL)
	{
		perror("failed to open /proc/modules");
		return -1;
	}

	// read and check each line for module name
	while (fgets(buf, sizeof(buf), fp) != NULL)
	{
		if (strncmp(buf, mod_name, strlen(mod_name)) == 0 && buf[strlen(mod_name)] == ' ')
		{
			found = 1;
			break;
		}
	}

	// close file, return result
	fclose(fp);
	return found;
}

int load_kernel_mod(const char *mod_path, const char *params)
{
	int ret = 0;
	char command[MAX_LINE_LEN];
	snprintf(command, sizeof(command), "sudo insmod %s %s", mod_path, params);
	if (system(command) != 0)
	{
		perror("failed to load kernel module");
		ret = -EINVAL;
	}
	return ret;
}

int offload_kernel_mod(const char *mod_path, const char *params)
{
	int ret = 0;
	char command[MAX_LINE_LEN];
	snprintf(command, sizeof(command), "sudo rmmod %s %s", mod_path, params);
	if (system(command) != 0)
	{
		perror("failed to offload kernel module");
		ret = -EINVAL;
	}
	return ret;
}

void set_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var) 
{ 
	*bitmap |= (1 << var); 
}

bool get_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var) 
{ 
	return (((*bitmap & (1 << var)) != 0) == true); 
}

void clear_tdma_var_bit(uint32_t *bitmap, enum tdma_vars_e var) 
{ 
	*bitmap &= ~(1 << var); 
}

struct tdma_vars_t *update_vars(uint32_t *bitmap)
{
	// allocate memory for data struct
	struct tdma_vars_t *data;
	data = malloc(sizeof(struct tdma_vars_t));
	if (data == NULL)
	{
		perror("failed to allocate memory for data");
		exit(EXIT_FAILURE);
	}
	
	// update variables
	if (get_tdma_var_bit(bitmap, DEVNAME))
	{
		printf("%sattr: %s is set!%s\n", yellow, "DEVNAME", reset);
		data->devname = devname;
		clear_tdma_var_bit(bitmap, DEVNAME);
	}

	if (get_tdma_var_bit(bitmap, LIMIT))
	{
		printf("%sattr: %s is set!%s\n", yellow, "LIMIT", reset);
		data->limit = limit;
		clear_tdma_var_bit(bitmap, LIMIT);
	}

	if (get_tdma_var_bit(bitmap, OFFSET))
	{
		printf("%sattr: %s is set!%s\n", yellow, "OFFSET", reset);
		data->t_offset = t_offset;
		clear_tdma_var_bit(bitmap, OFFSET);
	}

	if (get_tdma_var_bit(bitmap, FRAME))
	{
		printf("%sattr: %s is set!%s\n", yellow, "FRAME", reset);
		data->t_frame = t_frame;
		clear_tdma_var_bit(bitmap, FRAME);
	}

	if (get_tdma_var_bit(bitmap, SLOT))
	{
		printf("%sattr: %s is set!%s\n", yellow, "SLOT", reset);
		data->t_slot = t_slot;
		clear_tdma_var_bit(bitmap, SLOT);
	}

	if (get_tdma_var_bit(bitmap, OFFSET_FUTURE))
	{
		printf("%sattr: %s is set!%s\n", yellow, "OFFSET_FUTURE", reset);
		data->offset_future = offset_future;
		clear_tdma_var_bit(bitmap, OFFSET_FUTURE);
	}

	if (get_tdma_var_bit(bitmap, OFFSET_RELATIVE))
	{
		printf("%sattr: %s is set!%s\n", yellow, "OFFSET_RELATIVE", reset);
		data->offset_relative = offset_relative;
		clear_tdma_var_bit(bitmap, OFFSET_RELATIVE);
	}

	if (get_tdma_var_bit(bitmap, GRAPH))
	{
		printf("%sattr: %s is set!%s\n", yellow, "GRAPH", reset);
		data->graph = graph;
		clear_tdma_var_bit(bitmap, GRAPH);
	}

	// return pointer to data struct
	return data;
}

void print_vars(void)
{
	printf("devname: %s\n", devname);
	printf("limit: %u\n", limit);
	printf("t_frame: %ld\n", t_frame);
	printf("t_slot: %ld\n", t_slot);
	printf("t_offset: %ld\n", t_offset);
	printf("offset_future: %u\n", offset_future);
	printf("offset_relative: %u\n", offset_relative);
	printf("graph: %d\n", (int)graph);
}

int parse_params(uint32_t *bitmap, struct gengetopt_args_info *args_info)
{
	FILE *f;
	char *end_ptr;
	char *filename;
	char line[MAX_LINE_LEN];
	char key[MAX_LINE_LEN];
	char value[MAX_LINE_LEN];

	// use configuration file to save parameter values
	if (args_info->config_file_given)
	{
		// try opening config file
		filename = args_info->config_file_arg;
		f = fopen(filename, "r");
		if (f == NULL)
		{
			perror("Error opening config file");
			return errno;
		}
		// scan lines from file
		while (fgets(line, sizeof(line), f))
		{
			if (sscanf(line, "%[^=]=%s", key, value) == 2)
			{
				if (strcmp(key, "devname") == 0) 
				{
					strcpy(&devname, value);
					set_tdma_var_bit(bitmap, DEVNAME);
				} 
				else if (strcmp(key, "limit") == 0) 
				{
					limit = (uint32_t)strtoul(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, LIMIT);
				} 
				else if (strcmp(key, "t_offset") == 0) 
				{
					t_offset = (int64_t)strtoull(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, OFFSET);
				} 
				else if (strcmp(key, "t_frame") == 0) 
				{
					t_frame = (int64_t)strtoull(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, FRAME);
				} 
				else if (strcmp(key, "t_slot") == 0) 
				{
					t_slot = (int64_t)strtoull(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, SLOT);
				} 
				else if (strcmp(key, "offset_future") == 0) 
				{
					offset_future = (uint32_t)strtoul(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, OFFSET_FUTURE);
				} 
				else if (strcmp(key, "offset_relative") == 0) 
				{
					offset_relative = (uint32_t)strtoul(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, OFFSET_RELATIVE);
				} 
				else if (strcmp(key, "graph") == 0)
				{
					graph = (bool)value;
					set_tdma_var_bit(bitmap, GRAPH);
				}
				else 
				{
					printf("Invalid key: %s specified\n", key);
					errno = 2;
					return errno;
				}
			}
		}
		fclose(f);
	}
	// use command-line flags to save parameter values
	else
	{
		if (args_info->devname_given)
		{
			strcpy(&devname, args_info->devname_arg);
			set_tdma_var_bit(bitmap, DEVNAME);
		}
		if (args_info->limit_given) 	 
		{
			limit = args_info->limit_arg;
			set_tdma_var_bit(bitmap, LIMIT);
		}
		if (args_info->offset_given) 	 
		{
			t_offset = args_info->offset_arg;
			set_tdma_var_bit(bitmap, OFFSET);
		}
		if (args_info->frame_given)
		{ 
			t_frame = args_info->frame_arg;
			set_tdma_var_bit(bitmap, FRAME);
		}
		if (args_info->slot_given)
		{
			t_slot = args_info->slot_arg;
			set_tdma_var_bit(bitmap, SLOT);
		}
		if (args_info->offset_future_given)
		{
			offset_future = args_info->offset_future_arg;
			set_tdma_var_bit(bitmap, OFFSET_FUTURE);
		}
		if (args_info->offset_relative_given)
		{
			offset_relative = args_info->offset_relative_arg;
			set_tdma_var_bit(bitmap, OFFSET_RELATIVE);
		}
		if (args_info->graph_given)
		{
			graph = true;
			set_tdma_var_bit(bitmap, GRAPH);
		}
	}
	
	return 0;
}

int init_netlink_socket(struct nl_sock **sk, int *genl_family)
{
	// check pointers are valid
	if (!sk || !genl_family)
	{
		// invalid argument(s)
		return -EINVAL;
	}
	// allocate memory for netlink socket
	*sk = nl_socket_alloc();
	if (*sk == NULL)
	{
		perror("failed to allocate memory for netlink socket");
		return -ENOMEM;
	}
	// connect socket to generic netlink
	if (genl_connect(*sk) != 0)
	{
		perror("failed to connect netlink socket");
		nl_socket_free(*sk);
		*sk = NULL;
		return -ENOLINK;
	}
	// resolve generic netlink family name
	*genl_family = genl_ctrl_resolve(*sk, NETLINK_FAMILY_NAME);
	if (*genl_family < 0)
	{
		perror("failed to resolve netlink family name");
		nl_socket_free(*sk);
		*sk = NULL;
		return -ENOENT;
	}
	// success
	return 0;
}

void create_nlmsg(struct nl_msg *msg, struct tdma_vars_t *data, int *genl_family)
{
	// create netlink message
	msg = nlmsg_alloc();
	if (msg < 0)
	{
		perror("failed to allocate memory for nlmsg");
		exit(EXIT_FAILURE);
	}
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, *genl_family, 0, 0, GNL_RATDMA_RECV_MSG, 1);

	// save changed variables to nlmsg
	// ensure data stored in portable way
	nla_put_string(msg, GNL_RATDMA_DEVNAME, data->devname);
	nla_put_u32(msg, GNL_RATDMA_LIMIT, data->limit);
	nla_put_s64(msg, GNL_RATDMA_OFFSET, data->t_offset);
	nla_put_s64(msg, GNL_RATDMA_FRAME, data->t_frame);
	nla_put_s64(msg, GNL_RATDMA_SLOT, data->t_slot);
	nla_put_u32(msg, GNL_RATDMA_OFFSET_FUTURE, data->offset_future);
	nla_put_u32(msg, GNL_RATDMA_OFFSET_RELATIVE, data->offset_relative);

	// add flag values to netlink message only if true 
	if (graph)
	{
		printf("nla_put graph: %d\n", (int)data->graph);
		nla_put_flag(msg, GNL_RATDMA_GRAPH);
	}

}

int main(int argc, char *argv[])
{
	struct gengetopt_args_info args_info;
	struct nl_sock *sk;
	struct nl_msg *msg;
	int genl_family;

	struct tdma_vars_t *data;	// tdma var struct
	uint32_t *bitmap; 			// tdma var bitmap

	// initialize bitmap pointer
	bitmap = (int *)malloc(sizeof(int *));
	if (bitmap == NULL)
	{
		perror("failed to allocate memory for bitmap");
		exit(-ENOMEM);
	}

	// check cmdline parser included from gengetopt
	if (cmdline_parser(argc, argv, &args_info) != 0) 
	{
		perror("Could not open cmdline_parser");
		exit(1);
	}

	// use values from config file
	if (args_info.config_file_given)
	{
		if (parse_params(bitmap, &args_info) != 0)
		{
			perror("Error parsing configuration file");
			exit(EXIT_FAILURE);
		}
	}
	// use provided flag values from cmdline
	else
	{
		// set optional gengetopt flags as required
		// ensure network device name is required
		if (!args_info.devname_given)
		{
			printf("Network device must be specified\n");
			cmdline_parser_print_help();
			exit(EXIT_FAILURE);
		}
		// save values
		if (parse_params(bitmap, &args_info) != 0)
		{
			perror("error parsing command line options");
			exit(EXIT_FAILURE);
		}
	}

	// save variable changes to struct
	data = update_vars(bitmap);

	// load kernel modulles
	printf("%sinserting kernel modules...%s\n", magenta, reset);
	if (start_modules() != 0)
	{
		printf("Modules already loaded, proceeding...");
	}

	// create netlink socket to receive messages
	printf("%sCreating netlink socket%s\n", magenta, reset);
	if (init_netlink_socket(&sk, &genl_family) != 0)
	{
		perror("failed to initialize netlink socket");
		exit(EXIT_FAILURE);
	}

	// create netlink message
	create_nlmsg(msg, data, &genl_family);

	// send message to kernel
	printf("%sSending message to kernel...%s\n", magenta, reset);
	if (nl_send_auto(sk, msg) < 0)
	{
		perror("failed to send netlink message");
		return -errno;
	}

	printf("%sSent netlink message!%s\n", magenta, reset);

	// cleanup
	nlmsg_free(msg);
	nl_socket_free(sk);

	exit(EXIT_SUCCESS);
}