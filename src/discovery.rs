use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub host_name: String,
    pub mc_version: String,
    pub players: u32,
    pub max_players: u32,
    pub port: u16,
}

fn parse_raknet_pong(buf: &[u8], len: usize, default_port: u16) -> Option<ServerInfo> {
    if buf[0] == 0x1c && len > 35 {
        let str_data = String::from_utf8_lossy(&buf[35..len]);
        let parts: Vec<&str> = str_data.split(';').collect();
        if parts.len() >= 6 {
            let parsed_port = if parts.len() > 10 {
                parts[10].parse().unwrap_or(default_port)
            } else {
                default_port
            };

            let host_name = parts.get(1).unwrap_or(&"").to_string();
            let mut name = parts.get(7).unwrap_or(&"").to_string();
            if name.is_empty() {
                name = host_name.clone();
            }

            return Some(ServerInfo {
                host_name,
                mc_version: parts.get(3).unwrap_or(&"").to_string(),
                players: parts.get(4).unwrap_or(&"0").parse().unwrap_or(0),
                max_players: parts.get(5).unwrap_or(&"0").parse().unwrap_or(0),
                name,
                port: parsed_port,
            });
        }
    }
    None
}

pub async fn discover_local_server(timeout_dur: Duration) -> Option<ServerInfo> {
    let active = discover_server_on_port(19132, timeout_dur);
    let passive = listen_for_broadcasts(19132, timeout_dur);
    
    tokio::select! {
        Some(info) = active => Some(info),
        Some(info) = passive => Some(info),
        _ = tokio::time::sleep(timeout_dur) => None,
    }
}

async fn listen_for_broadcasts(port: u16, timeout_dur: Duration) -> Option<ServerInfo> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    socket.set_reuse_address(true).ok()?;
    #[cfg(not(windows))]
    let _ = socket.set_reuse_port(true);

    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().ok()?;
    socket.bind(&addr.into()).ok()?;
    socket.set_nonblocking(true).ok()?;

    let std_socket: std::net::UdpSocket = socket.into();
    let udp_socket = UdpSocket::from_std(std_socket).ok()?;

    let mut buf = [0u8; 2048];
    let res = tokio::time::timeout(timeout_dur, async {
        loop {
            if let Ok((len, _addr)) = udp_socket.recv_from(&mut buf).await {
                if let Some(info) = parse_raknet_pong(&buf, len, port) {
                    return Some(info);
                }
            }
        }
    }).await;

    res.ok().flatten()
}

pub async fn discover_server_on_port(port: u16, timeout_dur: Duration) -> Option<ServerInfo> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.set_broadcast(true).ok()?;

    // 1. RakNet Ping setup
    let magic = [
        0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56,
        0x78,
    ];
    let mut ping_packet = Vec::new();
    ping_packet.push(0x01); // ID_UNCONNECTED_PING
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    ping_packet.extend_from_slice(&time.to_be_bytes());
    ping_packet.extend_from_slice(&magic);
    ping_packet.extend_from_slice(&[0u8; 8]); // Client GUID

    // 2. NetherNet Ping setup
    let nethernet_key = *b"Z0B2h4v8j1o7h4l3n8f9d0c4a1p6g5h3";

    let nethernet_ping = {
        let sender_id: u64 = rand::random();
        let mut payload = Vec::new();
        payload.extend_from_slice(&18u16.to_le_bytes()); // 18 bytes length for Header
        payload.extend_from_slice(&0u16.to_le_bytes()); // packet_id = 0 (Request)
        payload.extend_from_slice(&sender_id.to_le_bytes());
        payload.extend_from_slice(&[0u8; 8]); // padding

        use hmac::{Hmac, Mac};
        let mut mac =
            <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&nethernet_key).unwrap();
        mac.update(&payload);
        let hmac_result = mac.finalize().into_bytes();

        use aes::Aes256;
        use ecb::cipher::{BlockEncryptMut, KeyInit};
        use ecb::Encryptor;

        let mut enc = Encryptor::<Aes256>::new((&nethernet_key).into());
        let pad_len = 16 - (payload.len() % 16);
        let mut encrypted = payload.clone();
        encrypted.extend_from_slice(&vec![pad_len as u8; pad_len]);
        for chunk in encrypted.chunks_mut(16) {
            enc.encrypt_block_mut(chunk.into());
        }

        let mut final_datagram = Vec::new();
        final_datagram.extend_from_slice(&hmac_result);
        final_datagram.extend_from_slice(&encrypted);
        final_datagram
    };

    // Send Pings
    let mut ips = vec!["127.0.0.1".to_string(), "255.255.255.255".to_string()];

    // Dynamically add all interface broadcast addresses
    if let Ok(interfaces) = get_if_addrs::get_if_addrs() {
        for iface in interfaces {
            if let get_if_addrs::IfAddr::V4(v4_addr) = iface.addr {
                if let Some(broadcast) = v4_addr.broadcast {
                    ips.push(broadcast.to_string());
                }
            }
        }
    }

    for ip in ips {
        let _ = socket
            .send_to(&ping_packet, format!("{}:{}", ip, port))
            .await;
        let _ = socket
            .send_to(&nethernet_ping, format!("{}:{}", ip, 7551))
            .await;
    }

    let mut buf = [0u8; 2048];
    let res = tokio::time::timeout(timeout_dur, async {
        loop {
            if let Ok((len, _addr)) = socket.recv_from(&mut buf).await {
                if let Some(info) = parse_raknet_pong(&buf, len, port) {
                    return Some(info);
                } else if len >= 48 {
                    // Parse NetherNet Response
                    use aes::Aes256;
                    use ecb::Decryptor;
                    use ecb::cipher::{BlockDecryptMut, KeyInit};
                    
                    let mut dec = Decryptor::<Aes256>::new((&nethernet_key).into());
                    let mut decrypted = buf[32..len].to_vec();
                    for chunk in decrypted.chunks_mut(16) {
                        dec.decrypt_block_mut(chunk.into());
                    }
                    
                    let payload_len = u16::from_le_bytes([decrypted[0], decrypted[1]]) as usize;
                    if payload_len + 2 <= decrypted.len() {
                        let payload = &decrypted[0..payload_len+2];
                        
                        use hmac::{Hmac, Mac};
                        let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&nethernet_key).unwrap();
                        mac.update(payload);
                        
                        // Compare HMAC constant time (or just slice eq)
                        if mac.verify_slice(&buf[0..32]).is_ok() {
                            let packet_id = u16::from_le_bytes([payload[2], payload[3]]);
                            if packet_id == 1 {
                                let mut offset = 20; // 2 (len) + 2 (id) + 8 (sender) + 8 (padding)
                                if offset + 4 <= payload.len() {
                                    let app_data_len = u32::from_le_bytes([payload[offset], payload[offset+1], payload[offset+2], payload[offset+3]]) as usize;
                                    offset += 4;
                                    
                                    if offset + app_data_len <= payload.len() {
                                        let hex_data = &payload[offset..offset+app_data_len];
                                        if let Ok(app_data) = hex::decode(hex_data) {
                                            let mut p = 0;
                                            if p < app_data.len() {
                                                let version = app_data[p];
                                                p += 1;
                                                
                                                if p + 2 <= app_data.len() {
                                                    let sn_len = u16::from_le_bytes([app_data[p], app_data[p+1]]) as usize;
                                                    p += 2;
                                                    if p + sn_len <= app_data.len() {
                                                        let host_name = String::from_utf8_lossy(&app_data[p..p+sn_len]).to_string();
                                                        p += sn_len;
                                                        
                                                        if p + 2 <= app_data.len() {
                                                            let ln_len = u16::from_le_bytes([app_data[p], app_data[p+1]]) as usize;
                                                            p += 2;
                                                            if p + ln_len <= app_data.len() {
                                                                let level_name = String::from_utf8_lossy(&app_data[p..p+ln_len]).to_string();
                                                                p += ln_len;
                                                                
                                                                if p < app_data.len() {
                                                                    let _game_type = app_data[p];
                                                                    p += 1;
                                                                    
                                                                    if p + 4 <= app_data.len() {
                                                                        let players = u32::from_le_bytes([app_data[p], app_data[p+1], app_data[p+2], app_data[p+3]]);
                                                                        p += 4;
                                                                        
                                                                        if p + 4 <= app_data.len() {
                                                                            let max_players = u32::from_le_bytes([app_data[p], app_data[p+1], app_data[p+2], app_data[p+3]]);
                                                                            
                                                                            let mut final_name = level_name.clone();
                                                                            if final_name.is_empty() {
                                                                                final_name = host_name.clone();
                                                                            }

                                                                            info!("Discovered NetherNet server: {} - {} (Players: {}/{})", host_name, final_name, players, max_players);
                                                                            
                                                                            return Some(ServerInfo {
                                                                                name: final_name,
                                                                                host_name,
                                                                                mc_version: format!("Bedrock v1.20.50+ (v{})", version),
                                                                                players,
                                                                                max_players,
                                                                                port, // Return requested RakNet port
                                                                            });
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }).await;

    res.ok().flatten()
}
