# collect-ip-subnets
Aggregates a bunch of IP addresses into a list of subnets. A subnet is considered only, if the threshold number of IPs per subnet is reached.

### Typical use case: 
Aggregate a list of potential dangerous subnets from a list of attacking IP addresses (e.g. found by sshguard). 

Build
---
    cargo build --release

Options
---
    -l, --larger_net_pct <larger-net-select-coverage-percentage>     [default: 0.34]
    -c, --threshold_class_c <threshold-class-c>                      [default: 3]

Run
---
    $ cat test_input | collect-ip-subnets
    221.181.96.0/22
    221.181.184.0/23
