#!/bin/bash
sudo tc qdisc del dev wlan0 root
tc qdisc show
cd ..
make remove
