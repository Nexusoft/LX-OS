PID=$$
#NUM_THREADS=160
PORT=4001
IP=10.0.1.21

if [ -z "$NUM_THREADS" ] ; then
    NUM_THREADS=30
fi

if [ -z "$FLOWS_EACH" ] ; then
    FLOWS_EACH=500
fi

#FLOWS_EACH=50

TESTID=`date +%F-%H:%M:%S`
OUTPUT_LINK=/tmp/flow-last
OUTPUT_DIR=/tmp/flow-data-$TESTID/
mkdir -p $OUTPUT_DIR

rm $OUTPUT_LINK
ln -s $OUTPUT_DIR $OUTPUT_LINK
echo $TESTID > $OUTPUT_LINK/timestamp

killall -INT flow-test

../flow-test $IP $PORT 3


if [ ! -z "$DO_CAPTURE" ] ; then
    tshark -i eth0 tcp port $PORT -s 68 -w $OUTPUT_DIR/capture &
    tshark_pid=$?
fi

	for i in $(seq 1 $NUM_THREADS) ; do
		PREFIX=$OUTPUT_DIR/$i
		#MY_PORT=$((PORT + i % 2))
		MY_PORT=$((PORT + 0))
		( echo "NUM_THREADS=$NUM_THREADS, FLOWS_EACH=$FLOWS_EACH, ANALYZE=$ANALYZE" ; ../flow-test $ANALYZE $IP $MY_PORT 2 $FLOWS_EACH) > $PREFIX.out 2> $PREFIX.err &
	done
	wait
kill $tshark_pid
echo "Waiting for tshark"
