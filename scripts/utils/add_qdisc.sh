#!/bin/bash

# Enable sch_netem module
sudo modprobe sch_netem

#Set retries to minimum
sudo iwconfig wlan0 retry 1

#Disable RTS/CTS (i hope)
sudo iw dev wlan0 set power_save off
sudo iw phy phy0 set rts off

# Compile and insert kernel modules with config values

cd .. #Project root. Scripts should be called from Script folder
make
cd netcntlr
sudo ./netcntlr -f $1

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
