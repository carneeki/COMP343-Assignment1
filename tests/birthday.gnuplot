set terminal png
set output "birthday.values.png"
set xrange [0:17]
set xtics 1
#set key top left
set ylabel "Typical number of hashes before collision"
set xlabel "Output length in powers of 2"
set linestyle 2 lt 0 linecolor rgb "blue"
q(x) = sqrt((pi)/2 * (2**x))
y = q(16)
plot q(x), y ls 2
