INNER="vmnet1 eth7"
OUTER=eth8
OUTER_ROUTED=mesh
LOCAL_EXTADDR=128.84.227.11

# Disable features to pass bare packet to destination
ethtool -K $INNER  tso off tx off rx off
#ethtool -K $OUTER  tso off tx off rx off

# magic number of 1480 MTU is to shorten packet so that pushing on an L2SEC
# header does not cause packet to exceed maximum Ethernet Frame size

brctl addbr mesh
ifconfig mesh 128.84.227.11 netmask 255.255.255.0 mtu 1480
brctl addif mesh $OUTER
iptables -F

route del default gw 128.84.227.1 $OUTER
ifconfig $OUTER 0
ifconfig $OUTER promisc up
# all traffic must go through switch process
for f in $INNER ; do 
    #iptables -t filter -A INPUT -i $f -d $LOCAL_EXTADDR -j ACCEPT
    iptables -t filter -A INPUT -i $f -j DROP

    ifconfig $f up
    ifconfig $f 0
    ifconfig $f promisc up 
done

# routing

route add default gw 128.84.227.1 dev mesh

#route add -net 128.84.227.0 netmask 255.255.255.0 dev $OUTER

