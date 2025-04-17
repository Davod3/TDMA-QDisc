#!/bin/bash

#Block broadcasts coming from Node 2
sudo tc qdisc add dev wlan0 clsact
sudo tc filter add dev wlan0 ingress protocol all flower src_mac d8:3a:dd:34:b8:d5 dst_mac ff:ff:ff:ff:ff:ff action drop

#Delete current rule
sudo ip neigh del 10.10.10.2 dev wlan0

#Add bogus permanent rule
sudo ip neigh add 10.10.10.2 lladdr 00:00:00:00:00:00 dev wlan0 nud permanent