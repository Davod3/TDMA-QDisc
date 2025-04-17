#!/bin/bash

sudo ebtables -D INPUT -s d8:3a:dd:96:6e:12 -d FF:FF:FF:FF:FF:FF -j DROP

#Delete current rule
sudo ip neigh del 10.10.10.6 dev wlan0