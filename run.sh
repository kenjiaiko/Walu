#!/bin/sh

ant
v=$(($1))
if [ $v -eq 0 ]; then
	java -Xmx21G -Xms21G -XX:+UseG1GC -cp bin/:lib/* net.jumperz.app.MWalu.MWalu data/access.log
else
	cp data/access.log data/access.log.bak
	for ((i=0; i < $v; i++))
	do
		java -Xmx21G -Xms21G -XX:+UseG1GC -cp bin/:lib/* net.jumperz.app.MWalu.MWalu data/access.log
		python updatelog.py data/result_all.txt data/access.log $2
	done
	cp data/access.log.bak data/access.log
	rm data/access.log.bak
fi
