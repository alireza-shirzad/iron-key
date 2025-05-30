



set datafile separator ","

set xtics 2 nomirror font ",17"
set ytics nomirror font ",17"

set xrange [*:*]
set grid back lt 1 dt 3 lc rgb 'grey'
set border 3 back

set style line 1 lc rgb "#000000" linewidth 1 
set style line 2 lc rgb "#F13F19" linewidth 1 
set style line 3 lc rgb "#0020FF" linewidth 1
set style line 4 lc rgb "#008000" linewidth 1
set style line 5 lc rgb "#FF8000" linewidth 1

set key left top
# set key spacing 1.5
# set key samplen 4

# set logscale x 2
# set logscale y 10
# set format x "2^{%L}"
# set format y "10^{%L}"

set terminal pdfcairo enhanced color font "Helvetica,15" size 5,5 background rgb 'white'
set xlabel "Number of Rescue invocations" offset 0,-1,0 font ",13"
set ylabel "Prover time (s)" offset -1,0,0 font ",13"
set output 'log_capacity_plot.pdf'


plot 'server_reg_update.csv' using 2:($1==25 ? $4 : 1/0) with lines ls 1 title "Log Capacity 25", \
     '' using 2:($1==26 ? $4 : 1/0) with lines title "Log Capacity 26", \
     '' using 2:($1==27 ? $4 : 1/0) with lines title "Log Capacity 27", \
     '' using 2:($1==28 ? $4 : 1/0) with lines title "Log Capacity 28", \
     '' using 2:($1==29 ? $4 : 1/0) with lines title "Log Capacity 29", \
     '' using 2:($1==30 ? $4 : 1/0) with lines title "Log Capacity 30", \
     '' using 2:($1==31 ? $4 : 1/0) with lines title "Log Capacity 31", \
     '' using 2:($1==32 ? $4 : 1/0) with lines title "Log Capacity 32", \
     '' using 2:($1==33 ? $4 : 1/0) with lines title "Log Capacity 33", \


