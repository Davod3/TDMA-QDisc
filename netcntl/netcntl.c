
#include "netcntl.h"
#include "../netlink_sock.h"

static char *devname;
static uint64_t t_on_s = 0;
static uint64_t t_off_s = 0;
static uint64_t t_on_ns = 0;
static uint64_t t_off_ns = 0;
static uint32_t tx_window_width = 0;
static uint32_t tun_width = 0;
static int32_t offset_delay = 0;

int load_kernel_mod(const char *mod_name, const char *params)
{
	// char command[MAX_LINE_LEN];
	// snprintf(command, sizeof(command), "sudo insmod %s %s", mod_name, params);
	// if (system(command) != 0) 
	// {
	// 	perror("Failed to load kernel module");
	// 	return errno;
	// }
	return 0;
}

int unload_kernel_mod(const char *mod_name)
{
	// char command[MAX_LINE_LEN];
	// snprintf(command, sizeof(command), "sudo rmmod %s", mod_name);
	// if (system(command) != 0) 
	// {
	// 	perror("Failed to unload kernel module");
	// 	return errno;
	// }
	return 0;
}

int parse_config_file(const char *filename)
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
				printf("set devname: %s\n", value);
            } 
			else if (strcmp(key, "t_on_ns") == 0) 
			{
                t_on_ns = atoi(value);
				printf("set t_on_ns: %ld\n", t_on_ns);
            } 
			else if (strcmp(key, "t_off_ns") == 0) 
			{
                t_off_ns = atoi(value);
				printf("set t_off_ns: %ld\n", t_off_ns);
            } 
			else if (strcmp(key, "tx_window_width") == 0) 
			{
                tx_window_width = atoi(value);
				printf("set tx_window_width: %d\n", tx_window_width);
            } 
			else if (strcmp(key, "tun_width") == 0) 
			{
                tun_width = atoi(value);
				printf("set tun_width: %d\n", tun_width);
            } 
			else if (strcmp(key, "offset_delay") == 0) 
			{
                offset_delay = atoi(value);
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
	struct iovec iov;
	struct msghdr msg;
	struct tdma_vars_t data;
	int sockfd, retval;
	
	// check cmdline parser included from gengetopt
	if (cmdline_parser(argc, argv, &args_info) != 0) 
	{
		perror("Could not open cmdline_parser");
		exit(1);
	}

	// config: use values from config file
	if (args_info.config_file_given)
	{
		if (parse_config_file(args_info.config_file_arg) != 0)
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

		if (args_info.devname_given)  		 devname = args_info.devname_arg;
		if (args_info.time_on_ns_given) 	 t_on_ns = args_info.time_on_ns_arg;
		if (args_info.time_off_ns_given) 	 t_off_ns = args_info.time_off_ns_arg;
		if (args_info.tx_window_width_given) tx_window_width = args_info.tx_window_width_arg;
		if (args_info.tunnel_width_given) 	 tun_width = args_info.tunnel_width_given;
		if (args_info.offset_delay_given) 	 offset_delay = args_info.offset_delay_arg;
	}

	// variables now changed - update in kernel

	// create netlink socket
	sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_FAMILY);
	if (sockfd < 0)
	{
		perror("failed to create socket");
		exit(EXIT_FAILURE);
	}

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
	nlh->nlmsg_type = 1;

	// set IO vector
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	// fill data to send
	data.devname = devname;
    data.t_on_s = t_on_s;
    data.t_off_s = t_off_s;
    data.t_on_ns = t_on_ns;
    data.t_off_ns = t_off_ns;
    data.tx_window_width = tx_window_width;
    data.tun_width = tun_width;
    data.offset_delay = offset_delay;

	// copy data to message payload
	memcpy(NLMSG_DATA(nlh), &data, sizeof(struct tdma_vars_t));

	// set message header
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// send message
	retval = sendmsg(sockfd, &msg, 0);
	if (retval < 0)
	{
		perror("failed to send netlink message");
		close(sockfd);
		free(nlh);
		exit(EXIT_FAILURE);
	}

	// cleanup
	close(sockfd);
	free(nlh);

	exit(EXIT_SUCCESS);
}