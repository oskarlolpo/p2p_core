use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use aes::Aes256;
use ecb::cipher::{BlockEncryptMut, KeyInit};
use ecb::Encryptor;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type Aes256EcbEnc = Encryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub struct Broadcasters {
    nethernet_task: JoinHandle<()>,
}

impl Broadcasters {
    pub async fn start(
        room_name: String,
        host_name: String,
        mc_version: String,
        slots: String,
        proxy_port: u16,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        let r_cancel = cancel.clone();
        let r_room_name = room_name.clone();
        let r_host_name = host_name.clone();
        let r_mc_version = mc_version.clone();
        let r_slots = slots.clone();

        let nethernet_task = tokio::spawn(async move {
            let socket = UdpSocket::bind("0.0.0.0:7551").await;
            let socket = match socket {
                Ok(s) => s,
                Err(_) => {
                    if let Ok(s) = UdpSocket::bind("0.0.0.0:0").await {
                        s
                    } else {
                        return;
                    }
                }
            };

            let key = Self::compute_key();
            let server_id = rand::random::<u64>();

            let mut buf = [0u8; 1024];
            loop {
                tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        if let Ok((len, addr)) = res {
                            if len >= 32 {
                                let response = Self::build_response_packet(
                                    &key, server_id, &r_room_name, &r_host_name, &r_slots, proxy_port
                                );
                                let _ = socket.send_to(&response, addr).await;
                            }
                        }
                    }
                    _ = r_cancel.cancelled() => { break; }
                }
            }
        });

        Ok(Self { nethernet_task })
    }

    fn compute_key() -> [u8; 32] {
        let mut hasher = Sha256::new();
        let seed: u64 = 0xdeadbeef;
        hasher.update(&seed.to_le_bytes());
        let res = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&res);
        key
    }

    fn build_response_packet(
        key: &[u8; 32],
        sender_id: u64,
        room_name: &str,
        host_name: &str,
        slots: &str,
        _proxy_port: u16,
    ) -> Vec<u8> {
        let mut server_data = Vec::new();
        server_data.push(4u8);

        let server_name_bytes = room_name.as_bytes();
        server_data.push(server_name_bytes.len() as u8);
        server_data.extend_from_slice(server_name_bytes);

        let level_name_bytes = host_name.as_bytes();
        server_data.push(level_name_bytes.len() as u8);
        server_data.extend_from_slice(level_name_bytes);

        let parts: Vec<&str> = slots.split('/').collect();
        let (players, max_players) = if parts.len() == 2 {
            (
                parts[0].parse::<i32>().unwrap_or(0),
                parts[1].parse::<i32>().unwrap_or(30),
            )
        } else {
            (0, 30)
        };

        server_data.push(0u8);
        server_data.extend_from_slice(&players.to_le_bytes());
        server_data.extend_from_slice(&max_players.to_le_bytes());
        server_data.push(0u8);
        server_data.push(0u8);
        server_data.push(4u8);
        server_data.push(8u8);

        let hex_data = hex::encode(&server_data).into_bytes();

        let mut app_data_buf = Vec::new();
        app_data_buf.extend_from_slice(&(hex_data.len() as u32).to_le_bytes());
        app_data_buf.extend_from_slice(&hex_data);

        let mut packet_buf = Vec::new();
        packet_buf.extend_from_slice(&1u16.to_le_bytes());
        packet_buf.extend_from_slice(&sender_id.to_le_bytes());
        packet_buf.extend_from_slice(&[0u8; 8]);
        packet_buf.extend_from_slice(&app_data_buf);

        let mut payload = Vec::new();
        payload.extend_from_slice(&(packet_buf.len() as u16).to_le_bytes());
        payload.extend_from_slice(&packet_buf);

        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("HMAC");
        mac.update(&payload);
        let hmac_result = mac.finalize().into_bytes();

        let mut enc = Aes256EcbEnc::new(key.into());
        let pos = payload.len();
        let pad_len = 16 - (pos % 16);
        let mut encrypted = payload.clone();
        encrypted.extend_from_slice(&vec![pad_len as u8; pad_len]);

        for chunk in encrypted.chunks_mut(16) {
            enc.encrypt_block_mut(chunk.into());
        }

        let mut final_datagram = Vec::new();
        final_datagram.extend_from_slice(&hmac_result);
        final_datagram.extend_from_slice(&encrypted);

        final_datagram
    }
}
