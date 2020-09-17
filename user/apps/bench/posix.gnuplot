#gnuplot script
set terminal postscript enhanced monochrome
set out 'bench_posix.eps'
set xlabel "bytes/call"
set ylabel "cycles/call (logscale)"
#set key right bottom 
#set yrange [0:12]
set logscale y
set key box
set size 1,0.5

plot 'posix_open.data'  using 1:2 with lp title "open"  lw 2 lt 1 pt 1,\
     'posix_read.data'  using 1:2 with lp title "read"  lw 2 lt 2 pt 1,\
     'posix_write.data' using 1:2 with lp title "write" lw 2 lt 3 pt 1,\
     'posix_close.data' using 1:2 with lp title "close" lw 2 lt 4 pt 1
