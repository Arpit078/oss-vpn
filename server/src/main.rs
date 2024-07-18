    use std::net::{TcpListener, TcpStream};
    use std::io::{Read, Write};
    use std::thread;
    use std::net::Ipv4Addr;
    use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
    use pnet::packet::{ipv4::Ipv4Packet, ipv4::MutableIpv4Packet};
    use pnet::packet::Packet;

    fn create_ip_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        payload:&[u8]
    ) -> Vec<u8> {
        // Calculate the total length of the packet
        let total_length = 20 + payload.len(); // 20 bytes for IPv4 header
    
        // Allocate a buffer for the packet
        let mut buffer = vec![0u8; total_length];
    
        // Create a mutable IPv4 packet
        let mut packet = MutableIpv4Packet::new(&mut buffer).unwrap();
    
        // Set the IPv4 header fields
        packet.set_version(0);
        packet.set_header_length(0);
        packet.set_total_length(total_length as u16);
        packet.set_ttl(203); 
        packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocol(8)); // TCP protocol
        packet.set_source(source);
        packet.set_destination(destination);

        packet.set_payload(payload);
        // Compute the checksum
        let checksum = pnet::packet::ipv4::checksum(&packet.to_immutable());
        packet.set_checksum(checksum);
        println!("response packet : {:?}",packet);
    
        // Return the packet as a byte vector
        buffer
    }


    fn handle_client(mut stream: TcpStream) {
        let mut buffer = [0; 1500];
        while match stream.read(&mut buffer) {
            Ok(size) => {
                if size == 0 {
                    false
                } else {
                    let ip_packet = Ipv4Packet::new(&buffer[..size]).unwrap();
                    println!("received ip packet : {:?}",ip_packet);
                    let destination = ip_packet.get_source();
                    let source = ip_packet.get_destination();
                    let source_port = TcpPacket::new(ip_packet.payload()).unwrap().get_source();
                    let http_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
    
                    // Set the payload
                    let mut buf = [0; 1500];
                    let mut payload = MutableTcpPacket::new(& mut buf).unwrap();
                    payload.set_source(8080);
                    payload.set_destination(source_port);
                    payload.set_payload(http_payload);

                    let response_packet = create_ip_packet(source, destination,&buf);
                    stream.write(&response_packet).unwrap();
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
