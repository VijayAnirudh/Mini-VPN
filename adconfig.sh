#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run this script as root or using sudo"
  exit 1
fi

sudo ip addr add 10.0.1.1/24 dev tun0
echo "Address is added into the network"

sudo ifconfig tun0 up
echo "tun0 interface is now up"
