#!/bin/bash

sudo tc qdisc del dev $1 root
tc qdisc show
cd ..
make remove
