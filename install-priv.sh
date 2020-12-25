#!/bin/bash

[ -z "${1+xxx}" ] && echo "Dir not specified" && exit

groupadd -f ring

chown -hR root:root $1/server
chown -hR root:ring $1/client

chmod -R u=rw,g=,o= $1/server
chmod -R u=rwx $1/server/bin

chmod -R u=rwx,g=,o= $1
chmod g=r,o=r $1/client/*.cnf $1/client/*.cert.pem

chmod -R u=rwx,g=rs,o=x $1/client/bin
chmod -R g+x $1/client/bin
chmod u=rwx,g=rx,o=rx $1/client $1/client/bin
chmod o=rx $1/client/bin/*.sh
chmod -R u=rwx,g=rwx,o=wx $1/client/tmp

chmod u+x $1/server/bin/*.sh
chmod +x $1/client/bin/*.sh
