# collect-ip-subnets
Tool to analyze a list of IP addresses in order to collect the list of corresponding subnets.

Typical use case: Create a list of potential dangerous subnets from a list of attacking IP addresses (e.g. found by sshguard). 

Build
---
    cargo build --release

Options:
---
    -l, --larger_net_pct <larger-net-select-coverage-percentage>     [default: 0.34]
    -c, --threshold_class_c <threshold-class-c>                      [default: 3]

Run Sample
---
    $ cat test_input | collect-ip-subnets
    221.181.96.0/22
    221.181.184.0/23
