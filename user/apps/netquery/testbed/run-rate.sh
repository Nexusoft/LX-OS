#export script=./flow-rate-test.plinc
export script=./flow-rate-test.plinc
export enough=1

killall  remote-start.pl

biggest=4
if false ; then
    ./gen-1path-topo.pl $biggest > test.topo
    ./build-all-conf.pl test.topo
    ./remote-start.pl -S
fi

for topo in 1 $biggest 3 2 ; do
    rm -rf router?/
    ./gen-1path-topo.pl $topo > test.topo
    ./build-all-conf.pl test.topo
    chmod a+w router*
    rm -f router*/*.log
    export output=/tmp/${topo}hop/no-analyze-rate/
    mkdir -p $output
    echo outputdir=$output
    cp test.topo $output

    ./until-enough-rate.sh
done
