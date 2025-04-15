#!/bin/bash

# Avoid using as this will block NTP packets.

sudo iptables -A INPUT -s 10.10.10.3 -j ACCEPT