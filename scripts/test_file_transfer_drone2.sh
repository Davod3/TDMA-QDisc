#!/bin/bash

./add_qdisc.sh test-config-drone2
dd if=/dev/zero bs=1M count=1000 | ssh pi@10.10.10.1 'dd of=/dev/null'
./remove_qdisc.sh wlx000f60050e55