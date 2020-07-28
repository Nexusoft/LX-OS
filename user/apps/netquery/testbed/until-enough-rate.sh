for f in seq 1 10 ; do
	killall remote-start.pl
	count=$( (for foo in $output/* ; do nq-rate.pl $foo ; done) | grep -v '^#' | wc -l )
	echo count = $count
	if (( count >= enough )) ; then
	    echo "Got enough data points"
	    exit 0
	fi
	setsid ./remote-start.pl $script
if false ; then
	pid=$!
	echo Sleeping
	sleep 30
	echo back from sleep, killing
	killall -g -INT remote-start.pl
	echo "Waiting"
	wait $pid
	echo "Done waiting"
fi
	( cd data/flow-latency ; mv `readlink last` $output )
done
