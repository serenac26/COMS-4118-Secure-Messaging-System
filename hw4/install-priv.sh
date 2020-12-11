#!/bin/bash

[ -z "${1+xxx}" ] && echo "Dir not specified" && exit

groupadd mailer
chown -hR root:mailer $1

pwd=$(pwd)

cd $1/mail
for f in *; do
    chown ${f}:mailer $f
done

cd $pwd

chmod u=rwx,g=sx,o=x $1/bin/mail-in
chmod u=rwx,g=x,o= $1/bin/mail-out
chmod u=rwx,g=rx,o=rx $1 $1/bin
chmod u=rwx,g=rx,o=rx $1/mail $1/tmp
chmod u=rwx,g=wx,o= $1/mail/*
