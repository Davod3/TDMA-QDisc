#!/bin/bash

./add_qdisc.sh test-config
ping google.com
./remove_qdisc.sh wlo1
