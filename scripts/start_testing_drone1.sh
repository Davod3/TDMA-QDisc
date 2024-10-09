#!/bin/bash

./add_qdisc.sh test-config-drone1
ping 10.10.10.2
./remove_qdisc.sh wlx000f600580e1
