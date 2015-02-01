i=0
while true
do		
	echo -n $i >> aredtime.txt
	TC_LIB_DIR='./tc' tc -s qdisc | grep -A1 ared | grep -v ared >> aredtime.txt
	i=`echo "$i + 0.1" | bc`
	sleep 0.1
done
