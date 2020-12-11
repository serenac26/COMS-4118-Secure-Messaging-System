#!/bin/bash

ARGC=$#
if [[ $ARGC -eq 1 ]]; then
    TREE=$1
else
    echo "Please provide a tree to test"
    exit 1
fi


pwd=$(pwd)
cd $TREE/bin
sudo chmod g-s mail-in
cd $pwd

for i in inputs/*
do

	echo "*********************************************"
	echo "Test $i"

	# run the test
	cd $TREE/bin
	sudo valgrind --leak-check=full --log-file=${pwd}/log-${i:7}.txt ./mail-in < ${pwd}/$i

	# check for memory leaks
	LEAK=$(cat "${pwd}/log-${i:7}.txt" | grep "ERROR SUMMARY: 0 errors" | wc -l)
	# rm log.txt
   	if [ $LEAK -eq 0 ]; then
        	echo "[Grader] MEMORY LEAK DETECTED AT TEST ${TEST}!"
    	fi


	# get the filename
	filename="${i:7}"

	# compare the outpus
	sudo icdiff -r ../mail/ ${pwd}/outputs/$filename/

	# wipe the newly created files
	sudo find ../mail -type f -print0 | xargs -0 rm &>/dev/null
	
	echo "*********************************************"
	echo ""
	cd $pwd
done

cd $TREE/bin
sudo chmod g+s mail-in