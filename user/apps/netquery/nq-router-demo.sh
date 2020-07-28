ROOT=/local/ashieh/nq-linux/user/apps/netquery

. ${ROOT}/setup-switch-net.sh

function open_window ()
{
	xterm -hold -sk -si -fn lucidasanstypewriter-10 -e "$@" &
}

rm /tmp/switch-enforcer.{err,out}
rm /tmp/netqueryd.{err,out}
rm /tmp/switchd.{err,out}

cd /nfs
killall netqueryd switchd site-init switch-enforcer nqsh
killall xterm
sleep 2

############ NETQUERY DAEMON START #########

${ROOT}/netqueryd -p 9000 > /tmp/netqueryd.out 2> /tmp/netqueryd.err &
rm site.tid
sleep 2
${ROOT}/site-init 128.84.227.11 9000

############ SWITCH DAEMON START #########

## Nexus boot / full network test
#open_window ${ROOT}/switchd -h 128.84.227.11 -p 9000 $INNER TAP 128.84.227.11 8069 128.84.227.8 128.84.227.11

## Nexus TCP firewall
open_window ${ROOT}/switchd -f -h 128.84.227.11 -p 9000 -d eth7 TAP 128.84.227.11 8069 128.84.227.8 128.84.227.11

## Nexus TCP firewall test
#open_window ${ROOT}/switchd -F -h 128.84.227.11 -p 9000 $INNER TAP 128.84.227.11 8069 128.84.227.8 128.84.227.11

## Local SSL test
#${ROOT}/switchd -h 128.84.227.11 -p 9000 -t 3334 &

## NQ write test
#${ROOT}/switchd -h 128.84.227.11 -p 9000 -n $INNER $OUTER_ROUTED 128.84.227.11 8069 128.84.227.8 128.84.227.11  > /tmp/switchd.out 2> /tmp/switchd.err &

############ SWITCH ENFORCER DAEMON START #########

sleep 4
# Default: Accept TPM (as of 4/17/09), accept all
# open_window ${ROOT}/switch-enforcer -h 128.84.227.11 -p 9000 

# Accept TPM, Reject TCP connections to/from ashieh
open_window ${ROOT}/switch-enforcer --tcp-ignore-one 128.84.98.19 -h 128.84.227.11 -p 9000

# accept all
#${ROOT}/switch-enforcer -h 128.84.227.11 -p 9000 -a > /tmp/switch-enforcer.out 2> /tmp/switch-enforcer.err &
# reject all
#${ROOT}/switch-enforcer -h 128.84.227.11 -p 9000 -r > /tmp/switch-enforcer.out 2> /tmp/switch-enforcer.err &

# -n -t 9999

############ TAKE OWNERSHIP OF SWITCH DAEMON AND ENFORCER #########

if true ; then
    sleep 4
    ${ROOT}/net-take-ownership 128.84.227.11 9000 > /tmp/net-operator.out 2> /tmp/net-operator.err 
fi

open_window ${ROOT}/nqsh 128.84.227.11 9000

#ps -AF | grep '0 /local.\+switchd' | grep -v grep
#ps -AF | grep '0 /local.\+netqueryd' | grep -v grep

ps -A | grep 'switchd' | grep -v grep
ps -A | grep 'netqueryd' | grep -v grep
ps -A | grep 'switch-enforcer' | grep -v grep


