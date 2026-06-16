use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    let socket = UdpSocket::bind("[::]:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.set_broadcast(true).unwrap();

    let req = [
        0x01, // Unconnected Ping
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Time
        0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56,
        0x78, // Magic
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client GUID
    ];

    println!("Scanning for Bedrock LAN servers...");

    // Broadcast to the standard Bedrock port
    let _ = socket.send_to(&req, "255.255.255.255:7551");

    // Also try checking the user's specific local IPs or localhost
    let _ = socket.send_to(&req, "[::1]:7551");
    let _ = socket.send_to(&req, "192.168.31.124:7551");

    // Sometimes Bedrock runs on random ports if it's a dedicated server, but LAN is usually 7551 broadcasted.
    // Wait for responses
    let mut buf = [0u8; 1024];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, addr)) => {
                if buf[0] == 0x1C {
                    // Unconnected Pong
                    let server_id = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                    let mut offset = 25; // Skip magic
                    let len =
                        u16::from_be_bytes(buf[offset..offset + 2].try_into().unwrap()) as usize;
                    offset += 2;
                    if offset + len <= size {
                        let motd = String::from_utf8_lossy(&buf[offset..offset + len]);
                        println!("Found Bedrock Server at {}!", addr);
                        println!("Raw MOTD: {}", motd);

                        let parts: Vec<&str> = motd.split(';').collect();
                        if parts.len() >= 6 {
                            println!("Game Name: {}", parts[0]);
                            println!("Host Name: {}", parts[1]);
                            println!("Protocol: {}", parts[2]);
                            println!("Version: {}", parts[3]);
                            println!("Players: {}/{}", parts[4], parts[5]);
                            if parts.len() >= 8 {
                                println!("World Name: {}", parts[7]);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Scan finished. Error/Timeout: {}", e);
                break;
            }
        }
    }
}
