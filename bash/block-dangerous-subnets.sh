#!/bin/bash

# clean INPUT chain
sudo iptables -v --flush INPUT

DATE=$(date +%Y-%m-%d)
mkdir -p subnets
SUBNETS_FILE=subnets/collected-dangerous-subnets.$DATE.txt

# collect dangerous subnets
./collect-dangerous-subnets.sh|sort -g > $SUBNETS_FILE
for net in $(cat $SUBNETS_FILE); do
    sudo iptables -v -A INPUT -s $net -j DROP
done

# persist iptables rules (except sshguard chain)
sudo su -c 'iptables-save | grep -v "\-A sshguard" > /etc/iptables/rules.v4'
