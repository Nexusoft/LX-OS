MYIP=128.84.227.11
MYPORT=3359
. ipsetup

iface=lo
vconfig add $iface 2
vconfig add $iface 3
vconfig add $iface 100

ifconfig $iface.2 up
ifconfig $iface.3 up
ifconfig $iface.100 up

echo "====> Starting netqueryd"
killall -9 netqueryd
./netqueryd -g &
sleep 1
./site-init $MYIP $MYPORT
echo "====> Starting bgp"
. bgp-conf/regtest/start
sleep 20

echo "====> Crawling site; should have a bunch of lo.* interfaces (lo.2, lo.3, lo.100)"
./site-crawl $MYIP $MYPORT 0

# cleanup
killall netqueryd
killall -9 bgpd
killall -9 zebra

vconfig rem $iface.2
vconfig rem $iface.3
vconfig rem $iface.100
