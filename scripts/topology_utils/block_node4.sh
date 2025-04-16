#!/bin/bash

#Delete current rule
sudo ip neigh del 10.10.10.4 dev wlan0

#Add bogus permanent rule
sudo ip neigh add 10.10.10.4 lladdr 00:00:00:00:00:00 dev wlan0 nud permanent