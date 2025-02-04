#include "netcntlr.h"
#include <linux/pkt_sched.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/gen_stats.h>
#include <net/if.h>

static int qdisc_modify(int cmd, const char *dev, unsigned int flags, struct tc_tdma_qopt *opt, struct tdma_vars_t *data) 
{

    char *qdisc_name = "tdma";
	int dev_index = if_nametoindex(dev);

    struct {
        struct nlmsghdr n;
        struct tcmsg t;
		char buf[64 * 1024];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | flags,
        .n.nlmsg_type = cmd,
        .t.tcm_family = AF_UNSPEC,
        .t.tcm_parent = TC_H_ROOT,
    };

    struct rtattr *tail;

    if (qdisc_name[0])
        addattr_l(&req.n, sizeof(req), TCA_KIND, qdisc_name, strlen(qdisc_name) + 1);

    // Add TCA_OPTIONS
    tail = addattr_nest(&req.n, 1024, TCA_OPTIONS);
    addattr_l(&req.n, 2024, TCA_TDMA_PARMS, opt, sizeof(*opt));
    addattr_nest_end(&req.n, tail);

    req.t.tcm_ifindex = dev_index;

    if (rtnl_talk(&rth, &req.n, NULL) < 0)
        return -1;
        
    return 0;
}

int start_modules(void)
{

	if (!topology_mod_loaded && is_module_loaded("topology") == 0)
	{
		load_kernel_mod(TOPOLOGY_KMOD_PATH, NULL);
		topology_mod_loaded = true;
	} else {
		return 0;
	}

	if (!tdma_mod_loaded && is_module_loaded("tdma") == 0)
	{
		load_kernel_mod(TDMA_KMOD_PATH, NULL);
		tdma_mod_loaded = true;
	} else {
		return -1;
	}

	return 0;
}

int is_module_loaded(const char *mod_name)
{

	char cmd[MAX_LINE_LEN];
	int found = 0;

	snprintf(cmd, MAX_LINE_LEN, "lsmod | grep %s", mod_name);

	if (system(cmd) == 0)
	{
		found = 1;
		printf("MODULE FOUND %s! \n", mod_name);
	}

	return found;
}

int load_kernel_mod(const char *mod_path, const char *params)
{

	int ret = 0;
	char command[MAX_LINE_LEN];
	snprintf(command, sizeof(command), "insmod %s", mod_path);
	printf("%s\n", command);
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
	snprintf(command, sizeof(command), "rmmod %s %s", mod_path, params);
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

	if(get_tdma_var_bit(bitmap, LIMIT)) {
		
		printf("%sattr: %s is set!%s\n", yellow, "LIMIT", reset);
		data->limit = limit;
		clear_tdma_var_bit(bitmap, LIMIT);

	}

	if (get_tdma_var_bit(bitmap, NODE_ID))
	{
		printf("%sattr: %s is set!%s\n", yellow, "OFFSET", reset);
		data->node_id = node_id;
		clear_tdma_var_bit(bitmap, NODE_ID);
	}

	if (get_tdma_var_bit(bitmap, N_NODES))
	{
		printf("%sattr: %s is set!%s\n", yellow, "FRAME", reset);
		data->n_nodes = n_nodes;
		clear_tdma_var_bit(bitmap, N_NODES);
	}

	if (get_tdma_var_bit(bitmap, SLOT_SIZE))
	{
		printf("%sattr: %s is set!%s\n", yellow, "SLOT", reset);
		data->slot_size = slot_size;
		clear_tdma_var_bit(bitmap, SLOT_SIZE);
	}

	if (get_tdma_var_bit(bitmap, USE_GUARD))
	{
		printf("%sattr: %s is set!%s\n", yellow, "GUARD", reset);
		data->use_guard = use_guard;
		clear_tdma_var_bit(bitmap, USE_GUARD);
	}

	if (get_tdma_var_bit(bitmap, SELF_CONFIGURED))
	{
		printf("%sattr: %s is set!%s\n", yellow, "SELF_CONFIGURED", reset);
		data->self_configured = self_configured;
		clear_tdma_var_bit(bitmap, SELF_CONFIGURED);
	}

	if(get_tdma_var_bit(bitmap, BROADCAST_PORT)) {
		
		printf("%sattr: %s is set!%s\n", yellow, "BROADCAST PORT", reset);
		data->broadcast_port = broadcast_port;
		clear_tdma_var_bit(bitmap, BROADCAST_PORT);

	}

	// return pointer to data struct
	return data;
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
					strcpy(devname, value);
					set_tdma_var_bit(bitmap, DEVNAME);
				} 
				else if (strcmp(key, "node_id") == 0) 
				{
					node_id = (int64_t)strtoull(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, NODE_ID);
				} 
				else if (strcmp(key, "n_nodes") == 0) 
				{
					n_nodes = (int64_t)strtoull(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, N_NODES);
				} 
				else if (strcmp(key, "slot_size") == 0) 
				{
					slot_size = (int64_t)strtoull(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, SLOT_SIZE);
				}
				else if (strcmp(key, "limit") == 0) {
					
					limit = (uint32_t)strtoul(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, LIMIT);

				}
				else if (strcmp(key, "use_guard") == 0) 
				{
					use_guard = (int64_t)strtoull(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, USE_GUARD);
				}
				else if (strcmp(key, "self_configured") == 0) 
				{
					self_configured = (int64_t)strtoull(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, SELF_CONFIGURED);
				}
				else if (strcmp(key, "broadcast_port") == 0) {
					
					broadcast_port = (uint64_t)strtoul(value, &end_ptr, 10);
					set_tdma_var_bit(bitmap, BROADCAST_PORT);

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
			strcpy(devname, args_info->devname_arg);
			set_tdma_var_bit(bitmap, DEVNAME);
		}
		if (args_info->node_id_given) 	 
		{
			node_id = args_info->node_id_arg;
			set_tdma_var_bit(bitmap, NODE_ID);
		}
		if (args_info->n_nodes_given)
		{ 
			n_nodes = args_info->n_nodes_arg;
			set_tdma_var_bit(bitmap, N_NODES);
		}
		if (args_info->slot_size_given)
		{
			slot_size = args_info->slot_size_arg;
			set_tdma_var_bit(bitmap, SLOT_SIZE);
		}
		if(args_info->limit_given)
		{
			limit = args_info->limit_arg;
			set_tdma_var_bit(bitmap, LIMIT);
		}
		if (args_info->use_guard_given) 	 
		{
			use_guard = args_info->use_guard_arg;
			set_tdma_var_bit(bitmap, USE_GUARD);
		}
		if (args_info->self_configured_given) 	 
		{
			self_configured = args_info->self_configured_arg;
			set_tdma_var_bit(bitmap, SELF_CONFIGURED);
		}
		if(args_info->broadcast_port_given)
		{
			broadcast_port = args_info->broadcast_port_arg;
			set_tdma_var_bit(bitmap, BROADCAST_PORT);
		}
	}
	
	return 0;
}

int add_qdisc(struct tdma_vars_t *data) {

	struct tc_tdma_qopt *opt = malloc(sizeof(struct tc_tdma_qopt));
	memset(opt, 0, sizeof(*opt));

	//options
	opt->n_nodes = data->n_nodes;
	opt->slot_size = data->slot_size;
	opt->node_id = data->node_id;
	opt->use_guard = data->use_guard;
	opt->self_configured = data->self_configured;
	opt->broadcast_port = data->broadcast_port;

	printf("Opening rtnl socket...\n");

	//communication
	if(rtnl_open(&rth, 0) < 0) {
		printf("Failed to open rtnl\n");
		free(opt);
		return -1;
	}

	printf("Rtnl socket open! Adding qdisc...\n");


	if(qdisc_modify(RTM_NEWQDISC, data->devname, NLM_F_EXCL | NLM_F_CREATE, opt, data)) {
		printf("Failed to add qdisc\n");
		return -1;
	}

	printf("Qdisc added!\n");

	rtnl_close(&rth);
	free(opt);

	printf("Rtnl socket closed.\n");

	return 0;

}

int change_qdisc(struct tdma_vars_t *data) {

	struct tc_tdma_qopt *opt = malloc(sizeof(struct tc_tdma_qopt));
	memset(opt, 0, sizeof(*opt));

	//options
	opt->n_nodes = data->n_nodes;
	opt->slot_size = data->slot_size;
	opt->node_id = data->node_id;
	opt->use_guard = data->use_guard;
	opt->self_configured = data->self_configured;
	opt->broadcast_port = data->broadcast_port;

	//communication
	if(rtnl_open(&rth, 0) < 0) {
		printf("Failed to open rtnl\n");
		free(opt);
		return -1;
	}

	printf("Rtnl socket open! Adding qdisc...\n");


	if(qdisc_modify(RTM_NEWQDISC, data->devname, 0, opt, data)) {
		printf("Failed to add qdisc\n");
		return -1;
	}

	printf("Qdisc added!\n");

	rtnl_close(&rth);
	free(opt);

	printf("Rtnl socket closed.\n");

	return 0;


}

int main(int argc, char *argv[])
{
	struct gengetopt_args_info args_info;
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

		//Add qdisc
		if(change_qdisc(data) < 0) {
			printf("Failed to add qdisc!\n");
			exit(-1);
		}

	} else {

		printf("Kernel modules loaded!\n");

		//Add qdisc
		if(add_qdisc(data) < 0) {
			printf("Failed to add qdisc!\n");
			exit(-1);
		}

	}

	exit(EXIT_SUCCESS);
}