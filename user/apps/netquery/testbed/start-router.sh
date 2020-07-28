#!/bin/bash

node=router$NODEID

. setup-common.sh
. $node/config || ( echo could not open config file! ; exit 255 )


if [ -z "$NQ_NAME" ] ; then
	echo "No NQ NAME!"
	exit 255
fi

# Create a local copy of /local/ashieh/bin/etc
SHARED_ETC=/local/ashieh/bin/etc
LOCAL_ETC=/tmp/zebra-etc
umount -l $SHARED_ETC
mkdir $LOCAL_ETC
chown -R quagga:quagga $LOCAL_ETC
mount --bind $LOCAL_ETC $SHARED_ETC

mksock $SHARED_ETC/zserv.api
chown quagga:quagga $SHARED_ETC/zserv.api

./cleanup-processes.sh


if true ; then
	#cmdline="$ZEBRA -d -f $node/zebra.conf --nl-bufsize 200000 $NQ_FLAGS --nq-name $NQ_NAME "
	#$cmdline > $node/zebrad.stdout 
	cmdline="$ZEBRA -f $node/zebra.conf --nl-bufsize 200000 $NQ_FLAGS --nq-name $NQ_NAME "
	echo $cmdline
	$cmdline > $node/zebrad.stdout 2> $node/zebrad.stderr &
else
	cmdline="$ZEBRA -f $node/zebra.conf --nl-bufsize 200000 $NQ_FLAGS --nq-name $NQ_NAME "
	rm /tmp/zebra.*
	strace -f -ff -o /tmp/zebra $cmdline > $node/zebrad.stdout  &
fi


sleep 5 # let zserv.api get created

cmdline="$RIP -d -f $node/rip.conf"
echo $cmdline
$cmdline > $node/ripd.stdout 

echo 1 > /proc/sys/net/ipv4/ip_forward

