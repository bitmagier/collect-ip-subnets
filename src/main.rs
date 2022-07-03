use std::borrow::Borrow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fmt::Formatter;
use std::io::{self, BufRead};

use structopt::StructOpt;

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
struct IpV4Network {
    net: [u8; 4],
    mask: [u8; 4],
}

impl IpV4Network {
    fn from_address(address: &[u8; 4], mask: &[u8; 4]) -> IpV4Network {
        IpV4Network {
            net: [
                address[0] & mask[0],
                address[1] & mask[1],
                address[2] & mask[2],
                address[3] & mask[3]
            ],
            mask: *mask,
        }
    }

    fn from_address_cidr(address: &[u8; 4], mask_cidr: u8) -> IpV4Network {
        IpV4Network::from_address(
            address,
            &IpV4Network::mask_from_cidr(mask_cidr),
        )
    }

    pub fn contains_subnet(&self, subnet: &IpV4Network) -> bool {
        // check mask
        if self.mask_in_cidr_notation() > subnet.mask_in_cidr_notation() {
            return false;
        }

        // compare network (at self.mask bits)
        self.eq(&IpV4Network::from_address(&subnet.net, &self.mask))
    }

    pub fn mask_in_cidr_notation(&self) -> u8 {
        self.network_bits()
    }

    // 255.0.0.0 => 1111 1111 0000 0000 0000 0000 0000 0000	=> 8
    pub fn network_bits(&self) -> u8 {
        let mut network_bits: u8 = 0;
        for i in 0..=3 {
            let bits = IpV4Network::num_high_one_bits(self.mask[i]);
            network_bits += bits;
            if bits < 8 { break; }
        }
        network_bits
    }

    fn num_high_one_bits(mut n: u8) -> u8 {
        let mut count: u8 = 0;
        while n > 0 {
            count += 1;
            n <<= 1;
        }
        count
    }

    // returns the number of IP addresses, the subnet contains
    pub fn address_space_size(&self) -> u32 {
        // 32 -> 1  | 2 ^ 0 = 1
        // 31 -> 2  | 2 ^ (32 - 31) = 2
        // 24 -> 256 | 2 ^ (32 - 24) = 256
        2u32.pow(32 - self.mask_in_cidr_notation() as u32)
    }


    // 24 -> 255.255.255.0
    // 23 -> 255.255.254.0
    // 22 -> 255.255.252.0
    fn mask_from_cidr(mask_cidr: u8) -> [u8; 4] {
        // 0 -> 0
        // 1 -> 128

        fn convert255(cidr8: u8) -> u8 {
            match cidr8 {
                0 => 0,
                1 => 128,
                2 => 192,
                3 => 224,
                4 => 240,
                5 => 248,
                6 => 252,
                7 => 254,
                8 => 255,
                _ => panic!()
            }
        }

        if mask_cidr > 32 { panic!("invalid cidr mask {}", mask_cidr); }
        let c0 = mask_cidr.min(8);
        let c1 = (mask_cidr as i8 - 8).max(0).min(8) as u8;
        let c2 = (mask_cidr as i8 - 16).max(0).min(8) as u8;
        let c3 = (mask_cidr as i8 - 24).max(0).min(8) as u8;

        [convert255(c0), convert255(c1), convert255(c2), convert255(c3)]
    }
}

fn collect_networks(class_c_networks: HashSet<IpV4Network>, larger_net_select_coverage_percentage: f32) -> HashSet<IpV4Network> {

    // fill higher nets, remove duplicates:

    // all available higher nets (lets say 255.0.0.0 as a upper bound) covering these class_c_networks
    let mut potential_higher_nets: HashSet<IpV4Network> = HashSet::new();
    for c in &class_c_networks {
        for mask in (8..c.mask_in_cidr_notation()).rev() {
            potential_higher_nets.insert(IpV4Network::from_address_cidr(&c.net, mask));
        }
    }

    // fill/sort higher nets by size, large ones first (smallest netmask)
    let mut larger_nets_sorted_top_down: Vec<IpV4Network> = potential_higher_nets.into_iter().collect();
    larger_nets_sorted_top_down.sort_by_key(|a| a.mask_in_cidr_notation());
    let mut larger_nets_sorted_top_down: VecDeque<IpV4Network> = larger_nets_sorted_top_down.into_iter().collect();

    // to compute the result, lets begin with all found class_c_nets
    let mut result = class_c_networks.clone();

    // go through sorted list of higher nets one by one and check if the condition (number of contained class_c_networks reached net_elect_percentage) is met
    // if not, then forget about the net
    // if so, then put this net into result-set and also remove all matching class_c_networks from result-set
    //for higher_net in larger_nets_sorted_top_down {
    while !larger_nets_sorted_top_down.is_empty() {
        let larger_net = match larger_nets_sorted_top_down.pop_front() {
            Some(e) => e,
            None => panic!()
        };

        let matching_class_c_nets: HashSet<&IpV4Network> = class_c_networks.borrow().iter()
            .filter(|e| larger_net.contains_subnet(e))
            .collect();

        let pct_matching_class_c: f32 = (matching_class_c_nets.len() * 256) as f32 / larger_net.address_space_size() as f32;

        if pct_matching_class_c >= larger_net_select_coverage_percentage {
            result.insert(larger_net);
            result.retain(|e| !matching_class_c_nets.contains(e));
            larger_nets_sorted_top_down.retain(|e| !larger_net.contains_subnet(e));
        }
    }

    result
}

impl fmt::Display for IpV4Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}/{}", self.net[0], self.net[1], self.net[2], self.net[3], self.mask_in_cidr_notation())
    }
}

fn mark_class_c_nets(addresses: &HashSet<[u8; 4]>, hits_needed: u8) -> HashSet<IpV4Network> {
    let mut potential_subnets: HashMap<IpV4Network, u8> = HashMap::new();
    const MASK: [u8; 4] = [255, 255, 255, 0];
    for ip in addresses {
        let net = IpV4Network::from_address(ip, &MASK);
        *potential_subnets.entry(net).or_insert(0) += 1;
    }

    let mut result = HashSet::new();
    for (net, hits) in potential_subnets {
        if hits >= hits_needed {
            result.insert(net);
        }
    }
    result
}

fn parse_ipv4_addresses(raw_addresses: Vec<String>) -> Result<HashSet<[u8; 4]>, String> {
    let mut result = HashSet::with_capacity(raw_addresses.len());

    for a in raw_addresses.iter() {
        if !a.is_empty() {
            match parse_ipv4(a) {
                Ok(a) => result.insert(a),
                Err(error) => return Err(error)
            };
        }
    }

    Ok(result)
}

fn parse_ipv4(ip: &str) -> Result<[u8; 4], String> {
    let mut result: [u8; 4] = [0; 4];
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return Err("not 4 parts separated by a '.'".to_string());
    }
    for i in 0..=3 {
        result[i] =
            match parts[i].parse::<u8>() {
                Ok(n) => n,
                Err(e) => return Err(e.to_string())
            }
    }
    Ok(result)
}

fn read_stdin() -> Vec<String> {
    let mut result = Vec::new();
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        result.push(line.expect("unable to read input line"));
    }
    result
}

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long)]
    verbose: bool,

    #[structopt(short = "c", long = "threshold_class_c", default_value = "3")]
    threshold_class_c: u8,

    #[structopt(short = "l", long = "larger_net_pct", default_value = "0.51")]
    larger_net_select_coverage_percentage: f32,
}

/// Aggregates a bunch of IP addresses into a list of subnets.
/// A subnet is considered only, if the threshold number of IPs per subnet is reached.
fn main() {
    let options: Cli = Cli::from_args();
    if options.verbose { println!("{:?}", options); }

    let input = read_stdin();

    let addresses: HashSet<[u8; 4]> = match parse_ipv4_addresses(input) {
        Ok(r) => r,
        Err(e) => panic!("parse failed: {}", e)
    };

    if options.verbose {
        println!("Analyzing {:?} addresses...", addresses.len());
        println!("To select a class C (/24) net, it takes {} IP corresponding addresses", options.threshold_class_c);
        println!("To select a higher class net (/23 upwards), it takes {} percent of contained class-c nets", options.larger_net_select_coverage_percentage);
    }

    let class_c_networks: HashSet<IpV4Network> = mark_class_c_nets(&addresses, options.threshold_class_c);
    let collected_networks: HashSet<IpV4Network> = collect_networks(class_c_networks, options.larger_net_select_coverage_percentage);

    if options.verbose {
        println!("Identified networks:")
    }
    for net in collected_networks {
        println!("{}", net)
    }
}




#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ip_net_creation() {
        let net16 = IpV4Network { net: [192, 168, 0, 0], mask: [255, 255, 0, 0] };
        let net24 = IpV4Network { net: [192, 168, 34, 0], mask: [255, 255, 255, 0] };

        assert_eq!(net16.mask_in_cidr_notation(), 16);
        assert_eq!(net24.mask_in_cidr_notation(), 24);
        assert!(net16.contains_subnet(&net24));
        assert_eq!(net16.address_space_size(), 256 * 256);
        assert_eq!(net24.address_space_size(), 256);
        assert_eq!(IpV4Network::from_address(&[192, 168, 34, 2], &[255, 255, 255, 0]), net24);
        assert_eq!(IpV4Network::from_address_cidr(&[192, 168, 34, 2], 24), net24);
        assert_eq!(IpV4Network::num_high_one_bits(0b1111_1100), 6);
        assert_eq!(IpV4Network::num_high_one_bits(0b1110_0000), 3);
    }
}
