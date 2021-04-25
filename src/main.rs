use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::io::{self, BufRead};

#[derive(PartialEq, Eq, Hash)]
struct IpV4Network {
    net: [u8; 4],
    mask: [u8; 4],
}

impl IpV4Network {
    pub(crate) fn contains_subnet(&self, subnet: &IpV4Network) -> bool {
        // check mask
        if self.mask_in_cidr_notation() > subnet.mask_in_cidr_notation() {
            return false;
        }

        // compare network (at self.mask bits)
        self.eq(&IpV4Network::from_address(&subnet.net, &self.mask))
    }
}

impl IpV4Network {
    fn from_address(address: &[u8; 4], mask: &[u8; 4]) -> IpV4Network {
        IpV4Network {
            net: [address[0] & mask[0], address[1] & mask[1], address[2] & mask[2], address[3] & mask[3]],
            mask: *mask,
        }
    }

    fn mask_in_cidr_notation(&self) -> u8 {
        IpV4Network::count_network_bits(&self.mask)
    }

    fn count_network_bits(mask: &[u8; 4]) -> u8 {
        let mut network_bits: u8 = 0;
        for i in 0..4 {
            let bits = IpV4Network::num_high_zero_bits(mask[i]);
            network_bits += bits;
            if bits < 8 { break; }
        }
        network_bits
    }

    fn num_high_zero_bits(mut n: u8) -> u8 {
        let mut count: u8 = 0;
        for _bit in 0..8 {
            if n >= 128 {
                count += 1
            }
            n = n << 1;
        }
        count
    }
}


impl fmt::Display for IpV4Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}/{}", self.net[0], self.net[1], self.net[2], self.net[3], self.mask_in_cidr_notation())
    }
}


fn read_stdin() -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        result.push(line.unwrap());
    }
    result
}

fn mark_class_c_nets(addresses: &Vec<[u8; 4]>, hits_needed: usize) -> Vec<IpV4Network> {
    let mut potential_subnets: HashMap<IpV4Network, usize> = HashMap::new();
    const MASK: [u8; 4] = [255, 255, 255, 0];
    for ip in addresses {
        let net = IpV4Network::from_address(&ip, &MASK);
        *potential_subnets.entry(net).or_insert(0) += 1;
    }

    let mut result = Vec::new();
    for (net, hits) in potential_subnets {
        if hits >= hits_needed {
            result.push(net);
        }
    }
    result
}

fn mark_class_b_nets(class_c_nets: &Vec<IpV4Network>, hits_needed: usize) -> Vec<IpV4Network> {
    let mut potential_class_b_nets: HashMap<IpV4Network, usize> = HashMap::new();
    const MASK: [u8; 4] = [255, 255, 0, 0];
    for c_net in class_c_nets {
        let class_b_net = IpV4Network::from_address(&c_net.net, &MASK);
        *potential_class_b_nets.entry(class_b_net).or_insert(0) += 1;
    }

    let mut result = Vec::new();
    for (net, hits) in potential_class_b_nets {
        if hits >= hits_needed {
            result.push(net);
        }
    }
    return result;
}

fn parse_ipv4_addresses(raw_addresses: Vec<String>) -> Result<Vec<[u8; 4]>, String> {
    let mut result = Vec::with_capacity(raw_addresses.len());

    for a in raw_addresses.iter() {
        match parse_ipv4(a) {
            Ok(a) => result.push(a),
            Err(error) => return Err(error)
        };
    }

    Ok(result)
}

fn parse_ipv4(ip: &str) -> Result<[u8; 4], String> {
    let mut result: [u8; 4] = [0; 4];
    let parts: Vec<&str> = ip.split(".").collect();
    if parts.len() != 4 {
        return Err("not 4 parts separated by a '.'".to_string());
    }
    for i in 0..4 {
        result[i] =
            match parts[i].parse::<u8>() {
                Ok(n) => n,
                Err(e) => return Err(e.to_string())
            }
    }
    Ok(result)
}

// Commandline tool which takes a list of IP V4 addresses as input and returns a list of subnets,
// from which multiple IP addresses come from, in order to identify attacking network segments
fn main() {
    let verbose = false;

    let number_of_addresses_to_mark_class_c_net = 3;
    let number_of_class_c_nets_to_mark_class_b_net = 6;

    let input: Vec<String> = read_stdin();

    let addresses: Vec<[u8; 4]> = match parse_ipv4_addresses(input) {
        Ok(r) => r,
        Err(e) => panic!("parse failed: {}", e)
    };

    if verbose {
        println!("Analyzing {:?} addresses...", addresses.len());
        println!("To select a class C (/24) net, it needs 3 matching IP addresses");
        println!("To select a class B (/16) net, it needs 6 matching class C subnets");
    }

    let mut class_c_networks: Vec<IpV4Network> = mark_class_c_nets(&addresses, number_of_addresses_to_mark_class_c_net);
    let class_b_networks = mark_class_b_nets(&class_c_networks, number_of_class_c_nets_to_mark_class_b_net);

    for class_b_net in &class_b_networks {
        for i in 0 ..class_c_networks.len() {
            if class_b_net.contains_subnet(&class_c_networks[i]) {
                class_c_networks.remove(i);
            }
        }
    }

    if verbose {
        println!("Identified networks:")
    }
    for x in class_b_networks{
        println!("{}", x)
    }
    for x in class_c_networks{
        println!("{}", x)
    }
}
