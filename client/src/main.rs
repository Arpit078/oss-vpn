use std::io::prelude::*;
use pnet::packet::ipv4::{MutableIpv4Packet,Ipv4Packet};
use std::net::TcpStream;
use tun::Configuration;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::Packet;
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
    let mut stream = TcpStream::connect("0.0.0.0:8080")?;
    print!("connected to server");
    loop {
        let amount = dev.read(&mut buf).unwrap();
            let ip_packet = Ipv4Packet::new(&buf[..amount]).unwrap();
            let source = ip_packet.get_source();
            let destination = ip_packet.get_destination();
            // let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

            println!("Received packet from {} to {}", source, destination);    
            // let x = String::from_utf8_lossy(tcp_packet.payload());
            // println!("tcp packet at the client from tun0 : {:?}",(tcp_packet));
            // println!("its payload : {:?}",x);
            let _ = stream.write(&buf[..amount]).unwrap();

            let mut data = [0; 2000];
            let amount = stream.read(&mut data)?;

            let received_ip_packet = Ipv4Packet::new(&data[..amount]).unwrap();
            
            let received_packet = TcpPacket::new(received_ip_packet.payload()).unwrap();
            println!("received ip packet from server : {:?}",received_ip_packet);
            println!("received tcp packet from server : {:?}",received_packet);
            // println!("received payload : {:?}",received_packet.payload());
            dev.write(received_packet.packet())?;
    }
}