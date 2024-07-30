#!/bin/bash

sudo ifconfig $1 down
sudo service NetworkManager start
ifconfig