./extract-ip-address-from-syslog-blocked.sh | sort -u|collect-ip-subnets --threshold_class_c 6 --larger_net_pct 0.66 | sort -g
