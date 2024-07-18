use std::str;

struct EthernetHeader {
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    ethertype: u16,
}

struct IpHeader {
    version: u8,
    ihl: u8,
    tos: u8,
    length: u16,
    id: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_ip: [u8; 4],
    dest_ip: [u8; 4],
}

struct TcpHeader {
    src_port: u16,
    dest_port: u16,
    sequence: u32,
    acknowledgment: u32,
    data_offset: u8,
    reserved: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

fn parse_ethernet_header(data: &[u8]) -> EthernetHeader {
    EthernetHeader {
        dest_mac: [data[0], data[1], data[2], data[3], data[4], data[5]],
        src_mac: [data[6], data[7], data[8], data[9], data[10], data[11]],
        ethertype: u16::from_be_bytes([data[12], data[13]]),
    }
}

fn parse_ip_header(data: &[u8]) -> IpHeader {
    IpHeader {
        version: data[14] >> 4,
        ihl: data[14] & 0x0f,
        tos: data[15],
        length: u16::from_be_bytes([data[16], data[17]]),
        id: u16::from_be_bytes([data[18], data[19]]),
        flags: data[20] >> 5,
        fragment_offset: u16::from_be_bytes([data[20] & 0x1f, data[21]]),
        ttl: data[22],
        protocol: data[23],
        checksum: u16::from_be_bytes([data[24], data[25]]),
        src_ip: [data[26], data[27], data[28], data[29]],
        dest_ip: [data[30], data[31], data[32], data[33]],
    }
}

fn parse_tcp_header(data: &[u8], ip_header_length: u8) -> TcpHeader {
    let offset = 14 + ip_header_length as usize * 4;
    TcpHeader {
        src_port: u16::from_be_bytes([data[offset], data[offset + 1]]),
        dest_port: u16::from_be_bytes([data[offset + 2], data[offset + 3]]),
        sequence: u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]),
        acknowledgment: u32::from_be_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]),
        data_offset: data[offset + 12] >> 4,
        reserved: (data[offset + 12] & 0x0f) >> 1,
        flags: data[offset + 13],
        window_size: u16::from_be_bytes([data[offset + 14], data[offset + 15]]),
        checksum: u16::from_be_bytes([data[offset + 16], data[offset + 17]]),
        urgent_pointer: u16::from_be_bytes([data[offset + 18], data[offset + 19]]),
    }
}

fn parse_http(data: &[u8]) {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut request = httparse::Request::new(&mut headers);

    match request.parse(data) {
        Ok(httparse::Status::Complete(_)) => {
            println!("HTTP Method: {}", request.method.unwrap());
            println!("HTTP Path: {}", request.path.unwrap());
            println!("HTTP Version: {:?}", request.version.unwrap());
            for header in request.headers {
                println!("Header: {}: {}", header.name, str::from_utf8(header.value).unwrap());
            }
        }
        Ok(httparse::Status::Partial) => {
            println!("Incomplete HTTP request");
        }
        Err(e) => {
            println!("Failed to parse HTTP request: {:?}", e);
        }
    }
}

fn main() {
    let packet_data = [204, 107, 30, 91, 197, 171, 76, 174, 28, 54, 32, 66, 8, 0, 69, 0, 4, 204, 0, 3, 64, 0, 58, 17, 50, 127, 172, 64, 155, 141, 192, 168, 1, 41, 1, 187, 206, 97, 4, 184, 84, 67, 91, 152, 91, 161, 207, 106, 14, 21, 10, 32, 92, 128, 23, 170, 182, 131, 209, 66, 59, 44, 80, 67, 6, 242, 15, 37, 183, 22, 115, 1, 84, 95, 35, 201, 43, 61, 171, 204, 189, 189, 81, 1, 182, 191, 181, 11, 211, 227, 101, 94, 150, 220, 138, 9, 160, 143, 68, 45, 62, 243, 84, 144, 89, 74, 42, 74, 23, 110, 251, 59, 77, 239, 75, 0, 164, 67, 156, 88, 196, 61, 35, 167, 97, 216, 223, 130, 150, 147, 205, 172, 196, 173, 227, 176, 97, 57, 161, 6, 169, 149, 72, 18, 104, 158, 135, 15, 16, 10, 92, 108, 86, 136, 14, 48, 203, 60, 230, 118, 39, 203, 82, 61, 35, 117, 172, 143, 49, 196, 153, 186, 230, 27, 61, 186, 189, 223, 91, 59, 239, 161, 159, 157, 253, 55, 96, 250, 137, 184, 231, 6, 135, 77, 157, 47, 235, 204, 232, 106, 33, 213, 77, 247, 18, 120, 109, 133, 177, 132, 146, 7, 207, 139, 51, 244, 225, 70, 255, 2, 186, 83, 131, 12, 45, 227, 159, 227, 70, 147, 233, 251, 187, 206, 80, 241, 82, 147, 62, 217, 235, 225, 65, 247, 219, 100, 246, 98, 112, 190, 22, 47, 209, 204, 169, 26, 115, 143, 11, 74, 107, 62, 91, 71, 191, 52, 94, 33, 81, 234, 240, 165, 73, 176, 72, 122, 196, 72, 6, 195, 52, 107, 209, 153, 174, 24, 120, 222, 14, 185, 242, 115, 85, 135, 44, 84, 246, 6, 144, 50, 16, 235, 218, 171, 14, 0, 196, 38, 221, 120, 208, 121, 220, 208, 144, 154, 205, 241, 166, 148, 137, 61, 30, 61, 187, 55, 205, 152, 251, 51, 117, 59, 6, 56, 54, 231, 27, 240, 181, 92, 80, 147, 244, 236, 196, 98, 169, 186, 253, 206, 45, 51, 224, 181, 204, 56, 75, 167, 165, 85, 109, 81, 226, 97, 175, 60, 105, 3, 41, 96, 54, 95, 132, 202, 156, 144, 47, 104, 55, 203, 49, 62, 240, 22, 204, 34, 113, 237, 210, 13, 94, 216, 39, 79, 193, 131, 134, 132, 110, 247, 139, 82, 15, 44, 247, 114, 71, 199, 188, 186, 48, 167, 254, 205, 177, 124, 188, 9, 29, 238, 225, 73, 42, 183, 98, 130, 103, 58, 238, 182, 65, 206, 92, 131, 233, 194, 156, 58, 207, 205, 100, 223, 66, 120, 87, 111, 35, 202, 82, 76, 1, 254, 85, 116, 117, 2, 6, 116, 250, 130, 220, 128, 97, 127, 15, 124, 30, 77, 124, 243, 115, 165, 177, 186, 35, 129, 55, 110, 18, 101, 79, 128, 64, 134, 185, 36, 62, 5, 49, 70, 249, 237, 39, 228, 192, 205, 103, 239, 39, 22, 164, 63, 84, 87, 201, 64, 83, 142, 207, 162, 244, 25, 4, 22, 231, 113, 178, 82, 75, 117, 222, 17, 54, 76, 33, 35, 213, 160, 162, 210, 160, 208, 2, 251, 115, 230, 49, 30, 212, 167, 184, 162, 152, 246, 60, 61, 23, 76, 58, 179, 4, 83, 208, 176, 173, 166, 136, 158, 152, 233, 196, 96, 204, 24, 14, 14, 81, 126, 162, 14, 34, 238, 170, 57, 135, 8, 45, 67, 231, 226, 105, 247, 103, 235, 211, 37, 62, 183, 161, 71, 174, 76, 166, 133, 125, 143, 112, 44, 51, 209, 55, 148, 250, 127, 234, 133, 225, 40, 220, 221, 13, 159, 112, 32, 208, 154, 145, 239, 187, 37, 155, 239, 48, 50, 236, 84, 139, 252, 15, 244, 210, 129, 14, 71, 83, 141, 45, 18, 228, 251, 124, 52, 142, 104, 190, 233, 188, 169, 100, 190, 8, 220, 48, 71, 120, 198, 126, 44, 96, 166, 4, 4, 72, 166, 100, 178, 42, 226, 175, 25, 25, 63, 254, 226, 194, 145, 126, 62, 255, 249, 176, 232, 109, 115, 204, 151, 130, 189, 164, 99, 242, 204, 168, 93, 33, 126, 74, 119, 21, 6, 54, 49, 102, 127, 195, 85, 3, 119, 2, 36, 147, 110, 250, 142, 140, 121, 210, 104, 244, 218, 147, 225, 39, 129, 122, 238, 191, 194, 220, 137, 63, 182, 0, 168, 214, 142, 11, 249, 211, 147, 153, 126, 126, 38, 45, 69, 81, 17, 229, 198, 124, 156, 150, 15, 213, 14, 247, 60, 39, 225, 91, 36, 168, 76, 224, 61, 84, 10, 192, 85, 236, 217, 160, 36, 163, 88, 107, 190, 51, 34, 43, 146, 57, 143, 104, 148, 117, 208, 200, 74, 84, 3, 150, 8, 155, 58, 14, 13, 80, 22, 188, 13, 48, 141, 144, 19, 204, 196, 70, 110, 67, 91, 89, 4, 242, 215, 144, 69, 52, 26, 119, 54, 142, 211, 192, 192, 233, 175, 8, 180, 12, 44, 216, 135, 89, 120, 0, 48, 129, 90, 93, 188, 101, 119, 167, 59, 223, 178, 204, 49, 214, 189, 245, 90, 158, 191, 47, 185, 231, 191, 123, 208, 170, 216, 250, 70, 106, 209, 204, 109, 164, 60, 1, 0, 171, 39, 253, 238, 22, 75, 66, 196, 112, 67, 50, 99, 191, 235, 167, 3, 182, 78, 100, 64, 185, 51, 207, 168, 181, 254, 62, 122, 60, 147, 83, 242, 168, 135, 141, 214, 5, 102, 26, 69, 213, 96, 151, 235, 222, 0, 69, 142, 197, 45, 218, 119, 105, 12, 208, 84, 223, 55, 253, 154, 162, 19, 213, 108, 84, 54, 127, 209, 224, 99, 236, 198, 132, 96, 118, 145, 174, 75, 194, 14, 248, 16, 126, 133, 252, 33, 240, 146, 84, 172, 143, 117, 165, 172, 70, 70, 186, 103, 148, 75, 146, 223, 133, 252, 152, 158, 193, 253, 81, 252, 250, 201, 95, 151, 116, 204, 132, 109, 191, 6, 87, 43, 184, 177, 137, 67, 207, 24, 212, 105, 240, 134, 255, 235, 211, 251, 107, 37, 71, 238, 195, 78, 128, 115, 34, 238, 67, 103, 112, 29, 108, 166, 210, 177, 207, 71, 211, 214, 211, 130, 139, 246, 89, 85, 128, 14, 52, 79, 19, 192, 172, 234, 27, 74, 172, 122, 137, 109, 74, 221, 132, 86, 200, 69, 15, 254, 164, 75, 67, 255, 252, 202, 218, 176, 248, 148, 100, 221, 102, 7, 198, 237, 193, 168, 23, 70, 117, 69, 83, 13, 124, 24, 168, 109, 202, 52, 210, 185, 250, 95, 109, 134, 73, 79, 13, 7, 32, 32, 24, 187, 118, 106, 214, 174, 32, 146, 162, 76, 107, 190, 194, 117, 213, 178, 10, 58, 101, 133, 194, 240, 39, 215, 50, 206, 124, 107, 234, 134, 133, 141, 248, 195, 156, 174, 55, 70, 118, 79, 243, 216, 86, 109, 198, 125, 70, 8, 199, 52, 254, 149, 237, 38, 233, 3, 165, 120, 232, 69, 32, 52, 143, 111, 39, 81, 252, 114, 112, 156, 25, 58, 230, 157, 125, 126, 125, 235, 194, 120, 60, 211, 240, 189, 208, 191, 33, 204, 207, 193, 72, 239, 12, 119, 99, 133, 106, 185, 54, 99, 114, 83, 170, 208, 78, 20, 53, 129, 213, 194, 248, 213, 118, 79, 180, 71, 12, 35, 248, 10, 120, 198, 105, 196, 224, 156, 247, 45, 97, 43, 208, 244, 217, 250, 244, 232, 55, 113, 127, 89];

    let eth_header = parse_ethernet_header(&packet_data);
    println!(
        "Destination MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        eth_header.dest_mac[0],
        eth_header.dest_mac[1],
        eth_header.dest_mac[2],
        eth_header.dest_mac[3],
        eth_header.dest_mac[4],
        eth_header.dest_mac[5],
    );
    println!(
        "Source MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        eth_header.src_mac[0],
        eth_header.src_mac[1],
        eth_header.src_mac[2],
        eth_header.src_mac[3],
        eth_header.src_mac[4],
        eth_header.src_mac[5],
    );
    println!("EtherType: {:04x}", eth_header.ethertype);

    if eth_header.ethertype == 0x0800 {
        let ip_header = parse_ip_header(&packet_data);
        println!("IP Version: {}", ip_header.version);
        println!("Header Length: {}", ip_header.ihl);
        println!("Type of Service: {}", ip_header.tos);
        println!("Total Length: {}", ip_header.length);
        println!("Identification: {}", ip_header.id);
        println!("Flags: {}", ip_header.flags);
        println!("Fragment Offset: {}", ip_header.fragment_offset);
        println!("Time to Live: {}", ip_header.ttl);
        println!("Protocol: {}", ip_header.protocol);
        println!("Header Checksum: {}", ip_header.checksum);
        println!(
            "Source IP: {}.{}.{}.{}",
            ip_header.src_ip[0], ip_header.src_ip[1], ip_header.src_ip[2], ip_header.src_ip[3]
        );
        println!(
            "Destination IP: {}.{}.{}.{}",
            ip_header.dest_ip[0], ip_header.dest_ip[1], ip_header.dest_ip[2], ip_header.dest_ip[3]
        );

        if ip_header.protocol == 6 {
            let tcp_header = parse_tcp_header(&packet_data, ip_header.ihl);
            println!("Source Port: {}", tcp_header.src_port);
            println!("Destination Port: {}", tcp_header.dest_port);
            println!("Sequence Number: {}", tcp_header.sequence);
            println!("Acknowledgment Number: {}", tcp_header.acknowledgment);
            println!("Data Offset: {}", tcp_header.data_offset);
            println!("Reserved: {}", tcp_header.reserved);
            println!("Flags: {}", tcp_header.flags);
            println!("Window Size: {}", tcp_header.window_size);
            println!("Checksum: {}", tcp_header.checksum);
            println!("Urgent Pointer: {}", tcp_header.urgent_pointer);

            let tcp_data_offset = 14 + ip_header.ihl as usize * 4 + tcp_header.data_offset as usize * 4;
            if tcp_data_offset < packet_data.len() {
                let http_data = &packet_data[tcp_data_offset..];
                parse_http(http_data);
            }
        }
    }
}
