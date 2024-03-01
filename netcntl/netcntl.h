#ifndef NET_CONTROLLER_H
#define NET_CONTROLLER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "cmdline.h"

#define MAX_LINE_LEN 64

// timing configurations
extern unsigned long t_on_s;
extern unsigned long t_off_s;
extern unsigned long t_on_ns;
extern unsigned long t_off_ns;
extern uint32_t tx_window_width;
extern uint32_t tun_width;
extern int32_t offset_delay;

// name of network device we are controlling
extern char *devname;

// function declarations
int parse_config_file(const char *filename);

#endif
