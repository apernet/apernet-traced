#!/bin/bash

ip link set tun1 up
ip route add 8.8.8.8/32 dev tun1
traceroute -e 8.8.8.8
