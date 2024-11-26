#!/bin/bash

sudo tc qdisc del dev $1 root
tc qdisc show
cd .. # Scripts folder
cd .. # Project root
make remove
