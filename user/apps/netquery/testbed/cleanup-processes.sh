#!/bin/bash

echo "Killing processes"
killall -9 zebra bgpd ripd netqueryd flow-test site-init start-clients.sh
sleep 2

# XXX hack
echo 0 > /proc/sys/net/ipv4/tcp_syncookies
