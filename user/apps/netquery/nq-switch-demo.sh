ROOT=/local/ashieh/nq-linux/user/apps/netquery

. ${ROOT}/setup-switch-net.sh

function open_window ()
{
	xterm -sk -si -fn lucidasanstypewriter-10 -e "$@" &
}

rm /tmp/switch-enforcer.{err,out}
rm /tmp/netqueryd.{err,out}
rm /tmp/switchd.{err,out}

cd /nfs
killall netqueryd switchd site-init switch-enforcer nqsh
sleep 2

############ NETQUERY DAEMON START #########

${ROOT}/netqueryd -p 9000 > /tmp/netqueryd.out 2> /tmp/netqueryd.err &
rm site.tid
sleep 2
${ROOT}/site-init 128.84.227.11 9000

############ SWITCH DAEMON START #########

## Nexus boot / full network test
open_window ${ROOT}/switchd -h 128.84.227.11 -p 9000 $INNER TAP 128.84.227.11 8069 128.84.227.8 128.84.227.11

## Local SSL test
#${ROOT}/switchd -h 128.84.227.11 -p 9000 -t 3334 &

## NQ write test
#${ROOT}/switchd -h 128.84.227.11 -p 9000 -n $INNER $OUTER_ROUTED 128.84.227.11 8069 128.84.227.8 128.84.227.11  > /tmp/switchd.out 2> /tmp/switchd.err &

############ SWITCH ENFORCER DAEMON START #########

sleep 2
# Default: Accept TPM (as of 4/17/09)
open_window ${ROOT}/switch-enforcer -h 128.84.227.11 -p 9000 
# accept all
#${ROOT}/switch-enforcer -h 128.84.227.11 -p 9000 -a > /tmp/switch-enforcer.out 2> /tmp/switch-enforcer.err &
# reject all
#${ROOT}/switch-enforcer -h 128.84.227.11 -p 9000 -r > /tmp/switch-enforcer.out 2> /tmp/switch-enforcer.err &

# -n -t 9999

open_window ${ROOT}/nqsh 128.84.227.11 9000

#ps -AF | grep '0 /local.\+switchd' | grep -v grep
#ps -AF | grep '0 /local.\+netqueryd' | grep -v grep

ps -A | grep 'switchd' | grep -v grep
ps -A | grep 'netqueryd' | grep -v grep
ps -A | grep 'switch-enforcer' | grep -v grep


