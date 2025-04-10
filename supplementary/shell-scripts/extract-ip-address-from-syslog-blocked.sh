#!/bin/bash

# go through last X months of journal and grep all blocked IPs
sudo journalctl -x --since="-36months" --unit sshguard --grep="Blocking" | awk '{ print $7 };'|sed -e 's/"//g'|sed -e 's/\/32//g'
