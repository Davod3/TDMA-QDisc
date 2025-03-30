#!/bin/bash

# $1  - Number of instances


for i in $(seq 1 $1); do
  iperf3 -s -p 520$i &
done