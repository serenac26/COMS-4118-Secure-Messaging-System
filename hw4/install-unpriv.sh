#!/bin/bash

[ -z "${1+xxx}" ] && echo "Dir not specified" && exit
[ -d $1 ] && echo "$1 exists" && exit

mkdir "$1"

cd $1
mkdir bin mail tmp
cd mail
for f in /home/mailbox/*; do
    mkdir ${f:14}
done