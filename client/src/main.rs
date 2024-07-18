use std::io::prelude::*;
use pnet::packet::ipv4::Ipv4Packet;
use tun::Configuration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the TUN interface
    let mut config = Configuration::default();
    config.address((10, 0, 0, 1))
          .name("tun0")
          .netmask((255, 255, 255, 0))
          .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let mut dev = tun::create(&config).unwrap();

    let mut buf = [0; 1500];

    loop {
        let amount = dev.read(&mut buf).unwrap();
        let ip_packet = Ipv4Packet::new(&buf[..amount]).unwrap();
            let source = ip_packet.get_source();
            let destination = ip_packet.get_destination();
            println!("Received packet from {} to {}", source, destination);
        
    }
}
