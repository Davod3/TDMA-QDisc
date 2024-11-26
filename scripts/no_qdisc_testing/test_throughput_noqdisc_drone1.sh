#!/bin/bash

cd .. # Scripts Folder

iperf3 -c 10.10.10.2 -t 60 -p 5201 > ../docs/logs/iperf-log-latest.txt
