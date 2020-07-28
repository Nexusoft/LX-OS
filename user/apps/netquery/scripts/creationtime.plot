latency(x)=x
latency3way(x)=3 * x

set title "Flow creation simulation, time to completion"

set xlabel "One-way propagation time (ms)"
set ylabel "Completion time (ms)"
plot "<cat $infile" using 4:3 with points,\
	latency(x) title "One-way propagation time",\
	latency3way(x) title "3 x propagation time (3-way handshake)"

pause -1
