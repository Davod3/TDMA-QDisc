#!/bin/bash

sudo tc qdisc del dev $1 root
tc qdisc show

cd .. # Project root. Scripts should be called from Scripts folder.
make remove
