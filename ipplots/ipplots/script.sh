i=0
while true
do		
	echo -n $i >> redtime.txt
	TC_LIB_DIR='./tc' tc -s qdisc | grep -A1 newred | grep -v newred >> redtime.txt
	i=`echo "$i + 0.1" | bc`
	sleep 0.1
done
