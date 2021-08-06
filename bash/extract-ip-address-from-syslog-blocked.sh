#!/bin/bash

# go through last 9 months of journal and grep all blocked IPs
sudo journalctl -x --since="-9months"|grep Blocking | awk '{ print $7 };'|sed -e 's/"//g'|sed -e 's/\/32//g'
