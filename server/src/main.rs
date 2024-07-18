    use std::net::{TcpListener, TcpStream};
    use std::io::{Read, Write};
    use std::thread;
    use std::net::Ipv4Addr;
    use tun::Configuration;
    use tun::Device;
    use std::process::Command;

    use pnet::packet::{ipv4::Ipv4Packet, ipv4::MutableIpv4Packet, Packet};

    fn create_vpn_packet(original_packet: &Ipv4Packet, vpn_server_ip: Ipv4Addr) -> Vec<u8> {
        let mut buffer = vec![0u8; original_packet.packet().len() + 20]; // Allocate space for the new IP packet
        let mut new_packet = MutableIpv4Packet::new(&mut buffer).unwrap();

        // Set the fields of the new VPN packet
        new_packet.set_version(4);
        new_packet.set_header_length(5);
        new_packet.set_total_length((20 + original_packet.packet().len()) as u16);
        new_packet.set_ttl(64); // Default TTL value
        new_packet.set_next_level_protocol(original_packet.get_next_level_protocol());
        new_packet.set_source(vpn_server_ip);
        new_packet.set_destination(original_packet.get_destination());

        // Set the payload as the original IP packet
        new_packet.set_payload(original_packet.packet());

        // Compute checksum
        let checksum = pnet::packet::ipv4::checksum(&new_packet.to_immutable());
        new_packet.set_checksum(checksum);

        buffer
    }


    fn create_receive_packet(original_packet: &Ipv4Packet, source: Ipv4Addr) -> Vec<u8> {
        let mut buffer = vec![0u8; original_packet.packet().len() + 20]; // Allocate space for the new IP packet
        let mut new_packet = MutableIpv4Packet::new(&mut buffer).unwrap();

        // Set the fields of the new VPN packet
        new_packet.set_version(4);
        new_packet.set_header_length(5);
        new_packet.set_total_length((20 + original_packet.packet().len()) as u16);
        new_packet.set_ttl(64); // Default TTL value
        new_packet.set_next_level_protocol(original_packet.get_next_level_protocol());
        new_packet.set_source(original_packet.get_source());
        new_packet.set_destination(source);

        // Set the payload as the original IP packet
        new_packet.set_payload(original_packet.packet());

        // Compute checksum
        let checksum = pnet::packet::ipv4::checksum(&new_packet.to_immutable());
        new_packet.set_checksum(checksum);

        buffer
    }

    fn handle_client(mut stream: TcpStream) {
        let mut buffer = [0; 1500];
        while match stream.read(&mut buffer) {
            Ok(size) => {
                if size == 0 {
                    false
                } else {
                    // Print the received packet
                    println!("Received packet: {:?}", &buffer[..size]);
                    // let amount = buffer.len();
                    // if let Some(ip_packet) = Ipv4Packet::new(&buffer[..amount]) {
                    //     let source = ip_packet.get_source();
                    //     let vpn_packet = create_vpn_packet(&ip_packet, Ipv4Addr::new(127, 0, 0, 1));
                    //     let buffer = vpn_packet;
                    //     let mut config = Configuration::default();
                    //     config.address((10, 0, 1, 1))
                    //         .name("tun1")
                    //         .netmask((255, 255, 255, 0))
                    //         .up();

                    //     #[cfg(target_os = "linux")]
                    //     config.platform(|config| {
                    //         config.packet_information(true);
                    //     });

                    //     let mut dev = tun::create(&config).unwrap();
                    //     println!("TUN interface {:?} created", dev.name());

                    //     // Clean up previous IP assignment if necessary
                    //     Command::new("ip")
                    //         .args(&["addr", "flush", "dev", "tun1"])
                    //         .status()
                    //         .expect("failed to flush IP addresses on TUN interface");

                    //     // Assign IP address to the TUN interface
                    //     Command::new("ip")
                    //         .args(&["addr", "add", "10.0.1.1/24", "dev", "tun1"])
                    //         .status()
                    //         .expect("failed to assign IP address");

                    //     // Bring up the TUN interface
                    //     Command::new("ip")
                    //         .args(&["link", "set", "dev", "tun1", "up"])
                    //         .status()
                    //         .expect("failed to bring up TUN interface");
                    //     dev.write(&buffer).unwrap();
                        
                    //     let mut buf = [0; 1500];

                    //     loop {
                    //         let amount = dev.read(&mut buf).unwrap();
                    //         if let Some(ip_packet) = Ipv4Packet::new(&buf[..amount]) {
                    //             let received_packet = create_receive_packet(&ip_packet, source);
                    //             stream.write(&received_packet).unwrap();
                    //             break;
                    //         }
                    //     }
                    //     Command::new("ip")
                    //         .args(&["link", "set", "dev", "tun1", "down"])
                    //         .status()
                    //         .expect("failed to bring down TUN interface");
                    // }
                    true
                }
            }
            Err(_) => {
                eprintln!("An error occurred while reading from the stream.");
                false
            }
        } {}
    }

    fn main() -> std::io::Result<()> {
        let listener = TcpListener::bind("0.0.0.0:8080")?;
        println!("TCP server listening on port 8080");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    thread::spawn(|| handle_client(stream));
                }
                Err(e) => {
                    eprintln!("Failed to accept a connection: {}", e);
                }
            }
        }
        Ok(())
    }
