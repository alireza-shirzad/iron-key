set datafile separator ","
set key outside
set xlabel "log2(capacity)"
set ylabel "time (s)"
set title "Update Time vs log_capacity (Grouped by log_update)"
set term pdf
set output "server_update.pdf"

# Define line styles with different colors
set style line 1 lt rgb "#1f77b4" pt 7 ps 1.5 lw 2
set style line 2 lt rgb "#ff7f0e" pt 7 ps 1.5 lw 2
set style line 3 lt rgb "#2ca02c" pt 7 ps 1.5 lw 2
set style line 4 lt rgb "#d62728" pt 7 ps 1.5 lw 2
set style line 5 lt rgb "#9467bd" pt 7 ps 1.5 lw 2
set style line 6 lt rgb "#8c564b" pt 7 ps 1.5 lw 2
set style line 7 lt rgb "#e377c2" pt 7 ps 1.5 lw 2
set style line 8 lt rgb "#7f7f7f" pt 7 ps 1.5 lw 2
set style line 9 lt rgb "#bcbd22" pt 7 ps 1.5 lw 2
set style line 10 lt rgb "#17becf" pt 7 ps 1.5 lw 2

# Determine range of log_update (now the grouping key)
stats 'server_update.csv' using 2 nooutput
min_upd = int(STATS_min)
max_upd = int(STATS_max)

plot for [upd=min_upd:max_upd] \
    'server_update.csv' using \
        ($2==upd ? $1 : 1/0):($2==upd ? $3 : 1/0) \
     title sprintf("log2(|update|) = %d", upd) ls (upd - min_upd + 1)