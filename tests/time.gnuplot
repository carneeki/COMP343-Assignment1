set terminal png
set output "time.values.png"
set xlabel 'Size (MB)'
set ylabel 'Time (s)'
set logscale xy 2
set key bottom right
plot 'time.values' u 1:2 with linespoints title 'Encryption', 'time.values' u 1:3 with linespoints title 'Decryption'

