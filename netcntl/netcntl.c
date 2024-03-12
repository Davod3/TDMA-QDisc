
#include "netcntl.h"

// default values
static char *def_devname = "enp0s2";
static uint64_t def_t_on_s = 0;
static uint64_t def_t_off_s = 0;
static uint64_t def_t_on_ns = 200000000UL;
static uint64_t def_t_off_ns = 800000000UL;
static uint32_t def_tx_window_width = 0;
static uint32_t def_tun_width = 0;
static int32_t def_offset_delay = 0;

// changed values
static char *devname = "";
static uint64_t t_on_s = 0;
static uint64_t t_off_s = 0;
static uint64_t t_on_ns = 0;
static uint64_t t_off_ns = 0;
static uint32_t tx_window_width = 0;
static uint32_t tun_width = 0;
static int32_t offset_delay = 0;

void set_tdma_var_bit(tdma_vars_bitmap_t *bitmap, enum tdma_vars_e var) 
{
	*bitmap |= (1 << var);
}

bool get_tdma_var_bit(tdma_vars_bitmap_t *bitmap, enum tdma_vars_e var)
{
	return (*bitmap & (1 << var)) != 0;
}

void clear_tdma_var_bit(tdma_vars_bitmap_t *bitmap, enum tdma_vars_e var)
{
	*bitmap &= ~(1 << var);
}

void print_vars(void)
{
	printf("devname: %s\n", devname);
	printf("t_on_s: %ud\n", t_on_s);
	printf("t_off_s: %ud\n", t_off_s);
	printf("t_on_ns: %ud\n", t_on_ns);
	printf("t_off_ns: %ud\n", t_off_ns);
	printf("tx_window_width: %ud\n", tx_window_width);
	printf("tun_width: %ud\n", tun_width);
	printf("offset_delay: %d\n", offset_delay);
}

int parse_config_file(tdma_vars_bitmap_t *bitmap, const char *filename)
{
	FILE *f;
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
                devname = (char*)strdup(value);
				set_tdma_var_bit(&bitmap, DEVNAME);
				printf("set devname: %s\n", value);
            } 
			else if (strcmp(key, "t_on_ns") == 0) 
			{
                t_on_ns = atoi(value);
				set_tdma_var_bit(&bitmap, T_ON_NS);
				printf("set t_on_ns: %ld\n", t_on_ns);
            } 
			else if (strcmp(key, "t_off_ns") == 0) 
			{
                t_off_ns = atoi(value);
				set_tdma_var_bit(&bitmap, T_OFF_NS);
				printf("set t_off_ns: %ld\n", t_off_ns);
            } 
			else if (strcmp(key, "tx_window_width") == 0) 
			{
                tx_window_width = atoi(value);
				set_tdma_var_bit(&bitmap, TX_WINDOW_WIDTH);
				printf("set tx_window_width: %d\n", tx_window_width);
            } 
			else if (strcmp(key, "tun_width") == 0) 
			{
                tun_width = atoi(value);
				set_tdma_var_bit(&bitmap, TUN_WIDTH);
				printf("set tun_width: %d\n", tun_width);
            } 
			else if (strcmp(key, "offset_delay") == 0) 
			{
                offset_delay = atoi(value);
				set_tdma_var_bit(&bitmap, OFFSET_DELAY);
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
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov[2];
	struct msghdr msg;
	struct tdma_vars_t data;
	int sockfd, retval;

	// tdma var bitmap
	tdma_vars_bitmap_t bitmap = 0;
	
	// check cmdline parser included from gengetopt
	if (cmdline_parser(argc, argv, &args_info) != 0) 
	{
		perror("Could not open cmdline_parser");
		exit(1);
	}

	// config: use values from config file
	if (args_info.config_file_given)
	{
		if (parse_config_file(&bitmap, args_info.config_file_arg) != 0)
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
			devname = args_info.devname_arg;
			set_tdma_var_bit(&bitmap, DEVNAME);
		}
		if (args_info.time_on_ns_given) 	 
		{
			t_on_ns = args_info.time_on_ns_arg;
			set_tdma_var_bit(&bitmap, T_ON_NS);
		}
		if (args_info.time_off_ns_given) 	 
		{
			t_off_ns = args_info.time_off_ns_arg;
			set_tdma_var_bit(&bitmap, T_OFF_NS);
		}
		if (args_info.tx_window_width_given)
		{ 
			tx_window_width = args_info.tx_window_width_arg;
			set_tdma_var_bit(&bitmap, TX_WINDOW_WIDTH);
		}
		if (args_info.tunnel_width_given)
		{
			tun_width = args_info.tunnel_width_given;
			set_tdma_var_bit(&bitmap, TUN_WIDTH);
		}
		if (args_info.offset_delay_given)
		{
			offset_delay = args_info.offset_delay_arg;
			set_tdma_var_bit(&bitmap, OFFSET_DELAY);
		}
	}

	// variables now changed - update in kernel

	// create netlink socket
	//sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_FAMILY);
	sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST_FAMILY);
	if (sockfd < 0)
	{
		perror("failed to create socket");
		exit(EXIT_FAILURE);
	}

	printf("Created netlink socket\n");

	// set source address
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	// bind socket
	if (bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
	{
		perror("failed to bind socket");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	printf("Binded netlink socket\n");

	// set dest address
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; 	 // kernel
	dest_addr.nl_groups = 0; // unicast

	// allocate memory for message
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct tdma_vars_t)));
	if (!nlh)
	{
		perror("failed to allocate memory for netlink message");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	memset(nlh, 0, NLMSG_SPACE(sizeof(struct tdma_vars_t)));

	// fill netlink message header
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct tdma_vars_t));
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = NLMSG_DONE;

	printf("Created netlink message\n");

	// fill data to send
	if (get_tdma_var_bit(&bitmap, DEVNAME))
	{
		data.devname = devname;
		clear_tdma_var_bit(&bitmap, DEVNAME);
	}
	else data.devname = def_devname; // set default

	if (get_tdma_var_bit(&bitmap, T_ON_NS))
	{
		data.t_on_ns = t_on_ns;
		clear_tdma_var_bit(&bitmap, T_ON_NS);
	}
	else data.t_on_ns = def_t_on_ns; // set default

	if (get_tdma_var_bit(&bitmap, T_OFF_NS))
	{
		data.t_off_ns = t_off_ns;
		clear_tdma_var_bit(&bitmap, T_OFF_NS);
	}
	else data.t_off_ns = def_t_off_ns; // set default

	if (get_tdma_var_bit(&bitmap, TX_WINDOW_WIDTH))
	{
		data.tx_window_width = tx_window_width;
		clear_tdma_var_bit(&bitmap, TX_WINDOW_WIDTH);
	}
	else data.tx_window_width = def_tx_window_width; // set default

	if (get_tdma_var_bit(&bitmap, TUN_WIDTH))
	{
		data.tun_width = tun_width;
		clear_tdma_var_bit(&bitmap, TUN_WIDTH);
	}
	else data.tun_width = def_tun_width; // set default

	if (get_tdma_var_bit(&bitmap, OFFSET_DELAY))
	{
		data.offset_delay = offset_delay;
		clear_tdma_var_bit(&bitmap, OFFSET_DELAY);
	}
	else data.offset_delay = def_offset_delay; // set default

	// if (strcmp(def_devname, devname) != 0) 		data.devname = devname;
    // if (def_t_on_s != t_on_s) 					data.t_on_s = t_on_s;
    // if (def_t_off_s != t_off_s) 				data.t_off_s = t_off_s;
    // if (def_t_on_ns != t_on_ns) 				data.t_on_ns = t_on_ns;
    // if (def_t_off_ns != t_off_ns) 				data.t_off_ns = t_off_ns;
    // if (def_tx_window_width != tx_window_width) data.tx_window_width = tx_window_width;
    // if (def_tun_width != tun_width) 			data.tun_width = tun_width;
    // if (def_offset_delay != offset_delay) 		data.offset_delay = offset_delay;

	// copy data to message payload
	memcpy(NLMSG_DATA(nlh), &data, sizeof(struct tdma_vars_t));

	// set IO vector
	iov[0].iov_base = (void *)nlh;
	iov[0].iov_len = nlh->nlmsg_len;
	iov[1].iov_base = &data;
	iov[1].iov_len = sizeof(struct tdma_vars_t);

	printf("Copied netlink message data payload\n");

	// set message header
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov[0];
	msg.msg_iovlen = 2;

	printf("Sending message over netlink socket...\n");

	// send message
	retval = sendmsg(sockfd, &msg, 0);
	if (retval < 0)
	{
		perror("failed to send netlink message");
		close(sockfd);
		free(nlh);
		exit(EXIT_FAILURE);
	}

	printf("Sent netlink message to NETLINK_FAMILY:%d\n", NETLINK_TEST_FAMILY);

	// cleanup
	close(sockfd);
	free(nlh);

	exit(EXIT_SUCCESS);
}
