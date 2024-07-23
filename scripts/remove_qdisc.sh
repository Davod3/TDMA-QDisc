#!/bin/bash
sudo tc qdisc del dev wlo1 root
tc qdisc show
cd ..
make remove