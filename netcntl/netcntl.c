
#include "netcntl.h"

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
	else data->devname = def_devname; // set default

	if (get_tdma_var_bit(bitmap, T_ON_S))
	{
		printf("%sattr: %s is set!%s\n", yellow, "T_ON_S", reset);
		data->t_on_s = t_on_s;
		clear_tdma_var_bit(bitmap, T_ON_S);
	}
	else data->t_on_s = def_t_on_s; // set default

	if (get_tdma_var_bit(bitmap, T_OFF_S))
	{
		printf("%sattr: %s is set!%s\n", yellow, "T_OFF_S", reset);
		data->t_off_s = t_off_s;
		clear_tdma_var_bit(bitmap, T_OFF_S);
	}
	else data->t_off_s = def_t_off_s; // set default

	if (get_tdma_var_bit(bitmap, T_ON_NS))
	{
		printf("%sattr: %s is set!%s\n", yellow, "T_ON_NS", reset);
		data->t_on_ns = t_on_ns;
		clear_tdma_var_bit(bitmap, T_ON_NS);
	}
	else data->t_on_ns = def_t_on_ns; // set default

	if (get_tdma_var_bit(bitmap, T_OFF_NS))
	{
		printf("%sattr: %s is set!%s\n", yellow, "T_OFF_NS", reset);
		data->t_off_ns = t_off_ns;
		clear_tdma_var_bit(bitmap, T_OFF_NS);
	}
	else data->t_off_ns = def_t_off_ns; // set default

	if (get_tdma_var_bit(bitmap, TX_WINDOW_WIDTH))
	{
		printf("%sattr: %s is set!%s\n", yellow, "TX_WINDOW_WIDTH", reset);
		data->tx_window_width = tx_window_width;
		clear_tdma_var_bit(bitmap, TX_WINDOW_WIDTH);
	}
	else data->tx_window_width = def_tx_window_width; // set default

	if (get_tdma_var_bit(bitmap, TUN_WIDTH))
	{
		printf("%sattr: %s is set!%s\n", yellow, "TUN_WIDTH", reset);
		data->tun_width = tun_width;
		clear_tdma_var_bit(bitmap, TUN_WIDTH);
	}
	else data->tun_width = def_tun_width; // set default

	if (get_tdma_var_bit(bitmap, OFFSET_DELAY))
	{
		printf("%sattr: %s is set!%s\n", yellow, "OFFSET_DELAY", reset);
		data->offset_delay = offset_delay;
		clear_tdma_var_bit(bitmap, OFFSET_DELAY);
	}
	else data->offset_delay = def_offset_delay; // set default

	// return pointer to data struct
	return data;
}

void print_vars(void)
{
	printf("devname: %s\n", devname);
	printf("t_on_s: %lu\n", t_on_s);
	printf("t_off_s: %lu\n", t_off_s);
	printf("t_on_ns: %lu\n", t_on_ns);
	printf("t_off_ns: %lu\n", t_off_ns);
	printf("tx_window_width: %u\n", tx_window_width);
	printf("tun_width: %u\n", tun_width);
	printf("offset_delay: %d\n", offset_delay);
}

int parse_config_file(uint32_t *bitmap, const char *filename)
{
	FILE *f;
	char *end_ptr;
	char line[MAX_LINE_LEN];
	char key[MAX_LINE_LEN];
	char value[MAX_LINE_LEN];

	f = fopen(filename, "r");
	if (f == NULL)
	{
		perror("Error opening config file");
		return errno;
	}

	while (fgets(line, sizeof(line), f))
	{
		if (sscanf(line, "%[^=]=%s", key, value) == 2)
		{
            if (strcmp(key, "devname") == 0) 
			{
				strcpy(&devname, value);
				set_tdma_var_bit(bitmap, DEVNAME);
				printf("set devname: %s\n", value);
            } 
			else if (strcmp(key, "t_on_s") == 0) 
			{
                t_on_s = (uint64_t)strtoull(value, &end_ptr, 10);
				set_tdma_var_bit(bitmap, T_ON_S);
				printf("set t_on_s: %lu\n", t_on_s);
            } 
			else if (strcmp(key, "t_off_s") == 0) 
			{
                t_off_s = (uint64_t)strtoull(value, &end_ptr, 10);
				set_tdma_var_bit(bitmap, T_OFF_S);
				printf("set t_off_s: %lu\n", t_off_s);
            } 
			else if (strcmp(key, "t_on_ns") == 0) 
			{
                t_on_ns = (uint64_t)strtoull(value, &end_ptr, 10);
				set_tdma_var_bit(bitmap, T_ON_NS);
				printf("set t_on_ns: %lu\n", t_on_ns);
            } 
			else if (strcmp(key, "t_off_ns") == 0) 
			{
                t_off_ns = (uint64_t)strtoull(value, &end_ptr, 10);
				set_tdma_var_bit(bitmap, T_OFF_NS);
				printf("set t_off_ns: %lu\n", t_off_ns);
            } 
			else if (strcmp(key, "tx_window_width") == 0) 
			{
                tx_window_width = (uint32_t)strtoul(value, &end_ptr, 10);
				set_tdma_var_bit(bitmap, TX_WINDOW_WIDTH);
				printf("set tx_window_width: %u\n", tx_window_width);
            } 
			else if (strcmp(key, "tun_width") == 0) 
			{
                tun_width = (uint32_t)strtoul(value, &end_ptr, 10);
				set_tdma_var_bit(bitmap, TUN_WIDTH);
				printf("set tun_width: %u\n", tun_width);
            } 
			else if (strcmp(key, "offset_delay") == 0) 
			{
                offset_delay = (uint32_t)strtoul(value, &end_ptr, 10);
				set_tdma_var_bit(bitmap, OFFSET_DELAY);
				printf("set offset_delay: %d\n", (offset_delay));
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
	return 0;
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
	int tmp_a = 0;
	bitmap = &tmp_a;

	// check cmdline parser included from gengetopt
	if (cmdline_parser(argc, argv, &args_info) != 0) 
	{
		perror("Could not open cmdline_parser");
		exit(1);
	}

	// config: use values from config file
	if (args_info.config_file_given)
	{
		if (parse_config_file(bitmap, args_info.config_file_arg) != 0)
		{
			perror("Error parsing configuration file");
			exit(EXIT_FAILURE);
		}
	}
	// config: use provided flag values (cmdline)
	else
	{
		// workaround for making device name required flag
		if (!args_info.devname_given)
		{
			printf("Network device must be specified\n");
			cmdline_parser_print_help();
			exit(EXIT_FAILURE);
		}

		if (args_info.devname_given)
		{
			strcpy(&devname, args_info.devname_arg);
			set_tdma_var_bit(bitmap, DEVNAME);
		}
		if (args_info.time_on_ns_given) 	 
		{
			t_on_ns = args_info.time_on_ns_arg;
			set_tdma_var_bit(bitmap, T_ON_NS);
		}
		if (args_info.time_off_ns_given) 	 
		{
			t_off_ns = args_info.time_off_ns_arg;
			set_tdma_var_bit(bitmap, T_OFF_NS);
		}
		if (args_info.tx_window_width_given)
		{ 
			tx_window_width = args_info.tx_window_width_arg;
			set_tdma_var_bit(bitmap, TX_WINDOW_WIDTH);
		}
		if (args_info.tunnel_width_given)
		{
			tun_width = args_info.tunnel_width_given;
			set_tdma_var_bit(bitmap, TUN_WIDTH);
		}
		if (args_info.offset_delay_given)
		{
			offset_delay = args_info.offset_delay_arg;
			set_tdma_var_bit(bitmap, OFFSET_DELAY);
		}
	}

	printf("%sSaving variables to data%s\n", magenta, reset);

	// save variable changes to struct
	data = update_vars(bitmap);

	printf("%sCreating netlink socket%s\n", magenta, reset);

	// create netlink socket
	sk = nl_socket_alloc();
	if (sk < 0)
	{
		perror("failed to allocate memory for netlink socket");
		exit(EXIT_FAILURE);
	}
	genl_connect(sk);
	genl_family = genl_ctrl_resolve(sk, NETLINK_FAMILY_NAME);

	// create netlink message
	msg = nlmsg_alloc();
	if (msg < 0)
	{
		perror("failed to allocate memory for nlmsg");
		exit(EXIT_FAILURE);
	}
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_family, 0, 0, GNL_RATDMA_RECV_MSG, 1);

	// save changed variables to nlmsg
	// ensure data stored in portable way
	printf("nla_put devname: %s\n", data->devname);
	nla_put_string(msg, GNL_RATDMA_DEVNAME, data->devname);
	printf("nla_put t_on_s: %lu\n", data->t_on_s);
	nla_put_u64(msg, GNL_RATDMA_T_ON_S, data->t_on_s);
	printf("nla_put t_off_s: %lu\n", data->t_off_s);	
	nla_put_u64(msg, GNL_RATDMA_T_OFF_S, data->t_off_s);
	printf("nla_put t_on_ns: %lu\n", data->t_on_ns);	
	nla_put_u64(msg, GNL_RATDMA_T_ON_NS, data->t_on_ns);
	printf("nla_put t_off_ns: %lu\n", data->t_off_ns);	
	nla_put_u64(msg, GNL_RATDMA_T_OFF_NS, data->t_off_ns);
	printf("nla_put tx_window_width: %u\n", data->tx_window_width);	
	nla_put_u32(msg, GNL_RATDMA_TX_WINDOW_WIDTH, data->tx_window_width);
	printf("nla_put tun_width: %u\n", data->tun_width);	
	nla_put_u32(msg, GNL_RATDMA_TUN_WIDTH, data->tun_width);
	printf("nla_put offset_delay: %d\n", data->offset_delay);	
	nla_put_s32(msg, GNL_RATDMA_OFFSET_DELAY, data->offset_delay);

	// send message to kernel
	printf("%sSending message to kernel%s\n", magenta, reset);
	if (nl_send_auto(sk, msg) < 0)
	{
		perror("failed to send netlink message");
		return -errno;
	}
	// TODO Collect Timestamp on Receiving End

	printf("%sSent netlink message with updates:%s\n", magenta, reset);
	print_vars();

	// cleanup
	nlmsg_free(msg);
	nl_socket_free(sk);

	exit(EXIT_SUCCESS);
}
