# Gnuplot script to plot time vs log update for different log capacities

# --- Output Settings ---
# Set the terminal to PDF, producing a vector graphics file.
# Adjust font and size as needed.
set terminal pdfcairo enhanced font "arial,10" size 7,5 # Standard A4-like ratio, in inches
set output 'log_capacity_plot.pdf'

# --- Plot Appearance ---
set title "Time vs. Log Update for Different Log Capacities" font ",14"
set xlabel "Log Update" font ",12"
set ylabel "Time (s)" font ",12"

# Place the legend at the top left, outside the plot if possible, otherwise inside.
set key top left Left reverse enhanced autotitle columnhead box

# Set data file separator to comma
set datafile separator ","

# --- Plotting ---
# Assumes your data file is named 'server_key_update.csv' and is in the same directory
# The script also assumes the first row is a header and skips it.
# It uses conditional plotting: ($1==X ? $4 : 1/0) means if column 1 equals X, use column 4, otherwise plot an undefined value (1/0) which gnuplot skips.

plot 'server_reg_update.csv' using 2:($1==25 ? $4 : 1/0) with linespoints title "Log Capacity 25" dashtype 1, \
     '' using 2:($1==26 ? $4 : 1/0) with linespoints title "Log Capacity 26" dashtype 2, \
     '' using 2:($1==27 ? $4 : 1/0) with linespoints title "Log Capacity 27" dashtype 3, \
     '' using 2:($1==28 ? $4 : 1/0) with linespoints title "Log Capacity 28" dashtype 4, \
     '' using 2:($1==29 ? $4 : 1/0) with linespoints title "Log Capacity 29" dashtype 5

# --- Notes ---
# If you have more or different log capacities, you'll need to:
# 1. Add/modify the conditional plotting lines (e.g., $1==NEW_CAPACITY).
# 2. Assign a unique title and dashtype for each new curve.

# To reset settings if you run multiple plot commands in one gnuplot session:
# reset

# It's good practice to unset the output after plotting to close the file properly
unset output
