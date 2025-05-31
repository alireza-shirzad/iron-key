set datafile separator ","

set xtics 6 nomirror font ",14" 
set ytics 100 nomirror font ",14"

set xrange [6:31] 
set yrange [0.2:*]
set grid back lt 1 dt 3 lc rgb 'grey'
set border lt 1 dt 1 lc rgb 'black'

unset mxtics
unset mytics
set key left top
set key samplen 1 
set key font ",12"
set format x "2^{%0.f}" 

set logscale y 10      # This is for your y-axis (already correct)
set format y "10^{%L}" # This is for your y-axis (already correct)

set terminal pdfcairo enhanced color font "Helvetica ,15" size 2.5,3 background rgb 'white'
set xlabel "Registration batch size" offset 0,0,0 font ",13"
set ylabel "Server registration time (s)" offset 0,0,0 font ",13" 
set output 'reg_log_capacity_plot_with_threshold.pdf' 


plot 'server_reg_update.csv' using 2:($1==21 ? $4 : 1/0) with lines linewidth 2 title "|D|= 2^{21}", \
     '' using 2:($1==25 ? $4 : 1/0) with lines linewidth 2 title "|D|= 2^{25}", \
     '' using 2:($1==27 ? $4 : 1/0) with lines linewidth 2 title "|D|= 2^{27}", \
     '' using 2:($1==30 ? $4 : 1/0) with lines linewidth 2 title "|D|= 2^{30}", \
     '' using 2:($1==31 ? $4 : 1/0) with lines linewidth 2 title "|D|= 2^{31}", \
     '' using 2:($1==32 ? $4 : 1/0) with lines linewidth 2 title "|D|= 2^{32}", \
     '' using 2:($1==33 ? $4 : 1/0) with lines linewidth 2 title "|D|= 2^{33}", \
     (2**x)/1000 with lines dashtype 2 notitle




set xlabel "Key update batch size" offset 0,0,0 font ",13"
set ylabel "Server key update throughput (#updates/s)" offset 0,0,0 font ",13" 
set output 'key_log_capacity_plot_with_threshold.pdf' 

set xrange [0:33] 
set yrange [*:*]
unset key

plot \
    'server_key_update.csv' using 2:($1==33 ? $4 : 1/0) with lines lc rgb "#FF0000" linewidth 2 notitle, \


########################################################################
# --- 3. Throughput plot (annotate max + y=x line) ---------------------
########################################################################
stats 'server_key_update.csv' \
      using 2:( ($1==33)?((2**$2)/$4):1/0 ) name 'T'

set output 'throughput_key_log_capacity_plot_with_threshold.pdf'
set xrange [*:33] 
set yrange [*:T_max_y+400000]


f(x) = x          

plot \
    'server_key_update.csv' using 2:( ($1==33)?((2**$2)/$4):1/0 ) \
        with lines lc rgb "#FF0000" lw 2 notitle, \
    f(x) with lines dt 2 lc rgb "#000000" lw 1 notitle



#############################################################################
# --- PLOT 4: Time vs. Dictionary Size (for specific Update Batch Sizes) ---
#############################################################################
set output 'time_vs_dictsize_plot.pdf'


set xlabel "Dictionary Size" offset 0,0,0 font ",13"
set ylabel "Server key update time (s)" offset 0,0,0 font ",13"

set xrange [*:*]    
set logscale y 10
set format y "10^{%L}"
set yrange [*:*]      

set key center
set key offset 0,-3
set key samplen 1 
set key font ",12"
set format x "2^{%0.f}" 

plot \
    '< sort -t, -k2,2n -k1,1n server_key_update.csv' \
        using 1:( ($2==23)? $4 : 1/0 ) with lines lw 2 title "Update Size 2^{23}", \
    '' using 1:( ($2==21)? $4 : 1/0 ) with lines lw 2 title "Update Size 2^{21}", \
    '' using 1:( ($2==18)? $4 : 1/0 ) with lines lw 2 title "Update Size 2^{18}", \
    '' using 1:( ($2==12)? $4 : 1/0 ) with lines lw 2 title "Update Size 2^{12}", \








set output 'reg_time_vs_dict_size.pdf'


set xlabel "Dictionary Size" offset 0,0,0 font ",13"
set ylabel "Server key update time (s)" offset 0,0,0 font ",13"

set xrange [20:33]    
set logscale y 10
set format y "10^{%L}"
set yrange [*:*]      

set key bottom right
set key offset 0.3,0
set key samplen 1 
set key font ",12"
set format x "2^{%0.f}" 

plot \
    '< sort -t, -k2,2n -k1,1n server_reg_update.csv' \
        u 1:( ($2==23)? $4 : 1/0 )   w l lw 2 lt 1 t "Update Size 2^{23}", \
    [32:*] 2048 w l lw 2 lt 1 dt 2  notitle, \
\
    '' u 1:( ($2==21)? $4 : 1/0 )    w l lw 2 lt 2 t "Update Size 2^{21}", \
    [29:31] 256  w l lw 2 lt 2 dt 2  notitle, \
\
    '' u 1:( ($2==18)? $4 : 1/0 )    w l lw 2 lt 3 t "Update Size 2^{18}", \
    [26:28] 32   w l lw 2 lt 3 dt 2  notitle, \
\
    '' u 1:( ($2==12)? $4 : 1/0 )    w l lw 2 lt 4 t "Update Size 2^{12}", \
    [25:27] 16   w l lw 2 lt 4 dt 2  notitle



set output 'client_lookup.pdf'

set xlabel "Dictionary size"
set ylabel "Verifier Lookup, and Persistency check Time (s)"

# Turn off logscales for this basic test to avoid complications
# set format x "%g" # General numeric format
set format y "%g"
set xrange [*:*]
set yrange [*:*]
set xtics 8 nomirror font ",14" 
set ytics 10 nomirror font ",14"

set key top left

plot 'client_lookup.csv' using 1:($2/1000) with lines lc rgb "#FF0000" linewidth 2 notitle 


set output 'audit.pdf'
set xlabel "Dictionary size"
set ylabel "Auditor time (s)"

# Turn off logscales for this basic test to avoid complications
# set format x "%g" # General numeric format
set format y "%g"
set xrange [*:*]
set yrange [*:*]
set xtics 8 nomirror font ",14" 
set ytics 10 nomirror font ",14"

set key top left

plot 'audit.csv' using 1:($2/1000) with lines lc rgb "#FF0000" linewidth 2 notitle 