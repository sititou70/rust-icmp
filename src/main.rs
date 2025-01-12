mod arp;
mod ether;
mod icmp;
mod ip;
mod util;

use arp::create_arp_request_message;
use ether::*;
use icmp::{create_icmp_echo_request_message, get_icmp_message_data};
use ip::{create_ip_packet, get_ip_packet_data};
use std::process;
use tun_tap::*;
use util::{parse_hwaddr, parse_ipaddr, print_hwaddr, print_ipaddr};

fn main() {
    let iface = Iface::new("tap0", Mode::Tap).expect("Failed to create a TAP device");

    // settings
    let gateway_ipaddr = "192.168.70.1";
    let my_ipaddr = "192.168.70.2";
    let my_hwaddr = "00:00:5e:00:53:01";

    // arp
    let arp_message = create_arp_request_message(my_ipaddr, my_hwaddr, gateway_ipaddr);
    let arp_frame = create_ethernet_frame(0x0806, "ff:ff:ff:ff:ff:ff", my_hwaddr, &arp_message);
    iface
        .send(
            &[
                vec![0_u8, 0, 0, 0], // for IFF_NO_PI
                arp_frame,
            ]
            .concat()
            .to_vec(),
        )
        .unwrap();

    let gateway_hwaddr;
    loop {
        let mut frame = vec![0; 1500];
        iface.recv(&mut frame).unwrap();
        frame.drain(0..4); // for IFF_NO_PI

        // check
        //// destination is my hwaddre
        if frame[0..6] != parse_hwaddr(my_hwaddr) {
            continue;
        }
        //// type is arp
        if frame[12..12 + 2] != [0x08_u8, 0x06_u8] {
            continue;
        }

        let message = get_ethernet_frame_data(&frame);
        //// opecode is reply
        if message[6..6 + 2] != vec![0x00, 0x02] {
            continue;
        }

        gateway_hwaddr = print_hwaddr(&message[8..8 + 6].to_vec());

        println!("arp reply received, gateway_hwaddr: {}", gateway_hwaddr);
        break;
    }

    // icmp
    let icmp_target_ipaddr = "8.8.8.8";
    let icmp_data = "test data";
    let icmp_message =
        create_icmp_echo_request_message(process::id() as u16, 0, &icmp_data.as_bytes().to_vec());
    let icmp_packet = create_ip_packet(1, 123, my_ipaddr, icmp_target_ipaddr, &icmp_message);
    let icmp_frame = create_ethernet_frame(0x0800, &gateway_hwaddr, my_hwaddr, &icmp_packet);
    iface
        .send(
            &[
                vec![0_u8, 0, 0, 0], // for IFF_NO_PI
                icmp_frame,
            ]
            .concat()
            .to_vec(),
        )
        .unwrap();

    loop {
        let mut frame = vec![0; 1500];
        iface.recv(&mut frame).unwrap();
        frame.drain(0..4); // for IFF_NO_PI

        // check
        //// destination is my hwaddr
        if frame[0..6] != parse_hwaddr(my_hwaddr) {
            continue;
        }
        //// type is IPv4
        if frame[12..12 + 2] != [0x08_u8, 0x00_u8] {
            continue;
        }

        let packet = get_ethernet_frame_data(&frame);
        //// version is 4
        if (packet[0] & 0xf0) >> 4 != 4_u8 {
            continue;
        }
        //// protocol is icmp
        if packet[9] != 1 {
            continue;
        }
        //// source addr is icmp_target_ipaddr
        if packet[12..12 + 4] != parse_ipaddr(&icmp_target_ipaddr) {
            continue;
        }

        let message = get_ip_packet_data(&packet);
        //// type is reply
        if message[0] != 0_u8 {
            continue;
        }

        let data = get_icmp_message_data(&message);
        //// data is icmp_data
        if data[0..icmp_data.len()] != icmp_data.as_bytes().to_vec() {
            continue;
        }

        println!(
            "icmp reply received from {}",
            print_ipaddr(&packet[12..12 + 4].to_vec())
        );
        break;
    }
}
