#!/bin/bash

# Enable sch_netem module
sudo modprobe sch_netem

# Compile and insert kernel modules with config values
cd ..
make
cd netcntlr
sudo ./netcntlr -f test-config

# Print lsmod and tc to confirm changes
echo 'Qdisc added...'
echo '-------------------'
lsmod | grep sch_netem
echo '-------------------'
lsmod | grep tdma
echo '-------------------'
lsmod | grep netlink_sock
echo '-------------------'
tc qdisc show
echo '-------------------'
