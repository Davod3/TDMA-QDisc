#!/bin/bash

sudo ebtables -D INPUT -s d8:3a:dd:34:b8:d5 -d FF:FF:FF:FF:FF:FF -j DROP

#Delete current rule
sudo ip neigh del 10.10.10.2 dev wlan0