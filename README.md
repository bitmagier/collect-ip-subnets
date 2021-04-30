# collect-ip-subnets
Tool to analyze a list of IP addresses to collect a list of corresponding subnets.

Typical use case: Create a list of potential dangerous subnets from a collection of attacking IP addresses. 

Build
---
cargo build --release

Options:
---
    -l, --larger_net_pct <larger-net-select-coverage-percentage>     [default: 0.34]
    -c, --threshold_class_c <threshold-class-c>                               [default: 3]

Run Sample
---
$ cat test_input | collect-ip-subnets
221.181.96.0/22
221.181.184.0/23