#!/bin/bash

sudo tc qdisc del dev $1 root
tc qdisc show

cd .. # Project root. Scripts should be called from Scripts folder.
make remove

# Reset transmission limit
sudo iwconfig $1 retry 7
