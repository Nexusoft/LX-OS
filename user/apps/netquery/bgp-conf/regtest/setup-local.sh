iface=lo
vconfig add $iface 2
vconfig add $iface 3
vconfig add $iface 100

ifconfig $iface.2 up
ifconfig $iface.3 up
ifconfig $iface.100 up

echo 1 > /proc/sys/net/ipv4/ip_forward

