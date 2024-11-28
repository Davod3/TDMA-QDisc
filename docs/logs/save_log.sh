#!/bin/bash

#$1 - Log Name
#$2 - Test Type
#$3 - Test Name
#$4 - Log Save Name

mkdir -p ~/TDMA-scheduler/docs/logs/$2/$3/

cp $1 ~/TDMA-scheduler/docs/logs/$2/$3/$4.txt
