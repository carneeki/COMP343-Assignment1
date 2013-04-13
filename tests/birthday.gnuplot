set terminal png
set output "birthday.values.png"
set xlabel 'bits'
set ylabel 'probability'
set key bottom right
set logscale y
plot 'birthday.values' u 1:2 with linespoints
