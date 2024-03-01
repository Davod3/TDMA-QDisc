
#include "netcntl.h"

/* FOR TESTING, REPLACE LATER */
char *devname;
unsigned long t_on_s = 0;
unsigned long t_off_s = 0;
unsigned long t_on_ns = 0;
unsigned long t_off_ns = 0;
uint32_t tx_window_width = 0;
uint32_t tun_width = 0;
int32_t offset_delay = 0;

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
                devname = strdup(value);
				printf("set devname: %s\n", value);
            } 
			else if (strcmp(key, "t_on_ns") == 0) 
			{
                t_on_ns = atoi(value);
				printf("set t_on_ns: %d\n", t_on_ns);
            } 
			else if (strcmp(key, "t_off_ns") == 0) 
			{
                t_off_ns = atoi(value);
				printf("set t_off_ns: %d\n", t_off_ns);
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

	if (cmdline_parser(argc, argv, &args_info) != 0) exit(1);

	// use values from config file
	if (args_info.config_file_given)
	{
		if (parse_config_file(args_info.config_file_arg) != 0)
		{
			perror("Error parsing configuration file");
			exit(EXIT_FAILURE);
		}
	}
	// use provided flag values
	else
	{
		if (args_info.devname_given)  		 devname = args_info.devname_arg;
		if (args_info.time_on_ns_given) 	 t_on_ns = args_info.time_on_ns_arg;
		if (args_info.time_off_ns_given) 	 t_off_ns = args_info.time_off_ns_arg;
		if (args_info.tx_window_width_given) tx_window_width = args_info.tx_window_width_arg;
		if (args_info.tunnel_width_given) 	 tun_width = args_info.tunnel_width_given;
		if (args_info.offset_delay_given) 	 offset_delay = args_info.offset_delay_arg;
	}

	// TODO: launch module/implementation

	exit(EXIT_SUCCESS);
}
