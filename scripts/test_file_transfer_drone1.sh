#!/bin/bash

./add_qdisc.sh test-config-drone1
dd if=/dev/zero bs=1M count=1000 | ssh pi@10.10.10.2 'dd of=/dev/null'
./remove_qdisc.sh wlx000f600580e1