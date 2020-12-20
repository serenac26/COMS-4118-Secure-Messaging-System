#!/bin/bash

[ -z "${1+xxx}" ] && echo "Dir not specified" && exit

groupadd -f ring
groupadd -f goot 
groupadd -f loot 
groupadd -f poot 
groupadd -f mint 
groupadd -f mout
groupadd -f vsin 
groupadd -f vuse 

# chown -hR root:root $1/server
chown -hR root:ring $1/client

chmod -R u=rwx,g=,o= $1

chmod u=rwx,g=rx,o=rx $1/client $1/client/bin
chmod -R u=rwx,g=rs,o=x $1/client/bin
chmod -R u=rwx,g=rwx,o= $1/client/private
