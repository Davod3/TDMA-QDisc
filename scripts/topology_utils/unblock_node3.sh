#!/bin/bash

sudo tc qdisc del dev wlan0 clsact
sudo tc filter del dev wlan0 ingress

#Delete current rule
sudo ip neigh del 10.10.10.3 dev wlan0