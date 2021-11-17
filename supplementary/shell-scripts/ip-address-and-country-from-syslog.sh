#!/bin/bash

ip_list=$(extract-ip-address-from-syslog-blocked.sh| sort -g)

while IFS= read -r ip; do
  echo -n "$ip "
  geoiplookup $ip
done <<< "$ip_list"
