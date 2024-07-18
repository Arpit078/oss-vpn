use std::io::{self, Read, Write};
use std::net::TcpStream;

pub fn client_func() -> io::Result<()> {
    // Connect to the server
    let mut stream = TcpStream::connect("127.0.0.1:7878")?;
    println!("Connected to the server!");

    // Define the message as a Vec<u8>
    let message: Vec<u8> = vec![240, 159, 146, 150];

    // Send the message to the server
    stream.write_all(&message)?;
    println!("Sent message: {:?}", message);
    
    
    // Read the response from the server
    let mut buffer = [0; 512];
    let n = stream.read(&mut buffer)?;
    // println!("Sent message string : {:?}", String::from_utf8_lossy(&message));
    println!("Received response: {:?}", String::from_utf8_lossy(&buffer[..n]));

    Ok(())
}