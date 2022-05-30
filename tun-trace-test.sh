#!/bin/bash
TEST_IP='10.10.10.10'
TUN_NAME='tun0'
PATHDEF='path.conf.example'

./traced $PATHDEF $TUN_NAME &
pid=$!

sleep 1
ip link set $TUN_NAME up
ip route add $TEST_IP dev $TUN_NAME
traceroute -e $TEST_IP -m $((`wc -l < $PATHDEF`+1))

kill $pid
wait