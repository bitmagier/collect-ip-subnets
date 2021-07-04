#!/bin/bash

sudo iptables -v --flush INPUT
# sudo iptables -v -A INPUT -m multiport -p tcp --destination-ports 22 -j sshguard

DATE=$(date +%Y-%m-%d)
SUBNETS_FILE=collected-dangerous-subnets.$DATE.txt
./collect-dangerous-subnets.sh|sort -g > $SUBNETS_FILE
for net in $(cat $SUBNETS_FILE); do
    sudo iptables -v -A INPUT -s $net -j DROP
done

sudo su -c 'iptables-save | grep -v "\-A sshguard" > /etc/iptables/rules.v4'
