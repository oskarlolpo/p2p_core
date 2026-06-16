use anyhow::{Context, Result};
use rupnp::ssdp::{SearchTarget, URN};
use std::net::UdpSocket;
use std::time::Duration;
use tracing::{error, info, warn};

/// Хранит состояние проброшенного порта.
/// При выходе из области видимости (Drop) порт будет автоматически закрыт на роутере.
pub struct UpnpMapping {
    device: rupnp::Device,
    service_urn: URN,
    external_port: u16,
}

const WAN_IP_CONNECTION: URN = URN::service("schemas-upnp-org", "WANIPConnection", 1);
const WAN_PPP_CONNECTION: URN = URN::service("schemas-upnp-org", "WANPPPConnection", 1);

impl UpnpMapping {
    /// Пытается найти UPnP-шлюз и пробросить указанный UDP-порт.
    pub async fn attempt_map(local_port: u16, description: &str) -> Result<Self> {
        let local_ip =
            get_local_ip().context("Не удалось определить локальный IPv4 адрес хоста")?;

        info!(
            "UPnP: Начинаем поиск устройств (5s) через IP {}...",
            local_ip
        );

        let search_target = SearchTarget::RootDevice;
        let devices = rupnp::discover(&search_target, Duration::from_secs(5), None)
            .await
            .context("Ошибка при запуске UPnP дискавери")?;

        let mut devices = std::pin::pin!(devices);
        use futures_util::StreamExt;

        let mut errors = Vec::new();
        let mut devices_found = 0;

        while let Some(device) = devices.next().await {
            let device = match device {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Ищем подходящий сервис (IP или PPP соединение)
            let service_urn = if device.find_service(&WAN_IP_CONNECTION).is_some() {
                Some(WAN_IP_CONNECTION)
            } else if device.find_service(&WAN_PPP_CONNECTION).is_some() {
                Some(WAN_PPP_CONNECTION)
            } else {
                None
            };

            if let Some(urn) = service_urn {
                devices_found += 1;
                let service = device.find_service(&urn).unwrap();
                info!(
                    "UPnP: Найден шлюз '{}', сервис {}",
                    device.friendly_name(),
                    urn
                );

                let args = format!(
                    "<NewRemoteHost></NewRemoteHost>\
                     <NewExternalPort>{}</NewExternalPort>\
                     <NewProtocol>UDP</NewProtocol>\
                     <NewInternalPort>{}</NewInternalPort>\
                     <NewInternalClient>{}</NewInternalClient>\
                     <NewEnabled>1</NewEnabled>\
                     <NewPortMappingDescription>{}</NewPortMappingDescription>\
                     <NewLeaseDuration>0</NewLeaseDuration>",
                    local_port, local_port, local_ip, description
                );

                match service.action(device.url(), "AddPortMapping", &args).await {
                    Ok(_) => {
                        info!(
                            "UPnP: Порт {} (UDP) успешно проброшен на шлюзе {}",
                            local_port,
                            device.friendly_name()
                        );
                        return Ok(Self {
                            device,
                            service_urn: urn,
                            external_port: local_port,
                        });
                    }
                    Err(e) => {
                        let err_msg = format!("'{}' error: {}", device.friendly_name(), e);
                        warn!(
                            "UPnP: Ошибка AddPortMapping на '{}': {}. Ищем дальше...",
                            device.friendly_name(),
                            e
                        );
                        errors.push(err_msg);
                        continue;
                    }
                }
            }
        }

        if devices_found == 0 {
            anyhow::bail!("UPnP-шлюз не найден в локальной сети (SSDP timeout). Убедитесь, что сетевой профиль 'Частная' (Private).")
        } else {
            anyhow::bail!(
                "UPnP-шлюз найден, но отклонил запрос: {}",
                errors.join("; ")
            )
        }
    }
}

pub fn get_local_ip() -> Result<std::net::IpAddr> {
    let mut valid_ips = Vec::new();
    if let Ok(interfaces) = get_if_addrs::get_if_addrs() {
        for iface in interfaces {
            let name = iface.name.to_lowercase();
            // Skip virtual and loopback interfaces
            if name.contains("loopback")
                || name.contains("docker")
                || name.contains("wsl")
                || name.contains("vethernet")
                || name.contains("virtual")
                || name.contains("vmware")
                || name.contains("vbox")
                || name.contains("tun")
                || name.contains("tap")
                || name.contains("vpn")
                || name.contains("radmin")
                || name.contains("hyper-v")
            {
                continue;
            }

            if let get_if_addrs::IfAddr::V4(addr) = iface.addr {
                if !addr.ip.is_loopback() && !addr.ip.is_link_local() {
                    // Explicitly ignore common WSL/Docker subnets 172.17.x.x - 172.31.x.x
                    // and Hamachi/Radmin 26.x.x.x
                    let oct = addr.ip.octets();
                    if oct[0] == 172 && (16..=31).contains(&oct[1]) {
                        continue;
                    }
                    if oct[0] == 26 {
                        continue;
                    }
                    valid_ips.push(std::net::IpAddr::V4(addr.ip));
                }
            }
        }
    }

    // Try routing via OS default
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                let ip = local_addr.ip();
                if valid_ips.contains(&ip) {
                    return Ok(ip);
                } else if let std::net::IpAddr::V4(v4) = ip {
                    let oct = v4.octets();
                    // Use it only if it's not a common virtual subnet or Radmin VPN
                    if !(oct[0] == 172 && (16..=31).contains(&oct[1])) && oct[0] != 26 {
                        return Ok(ip);
                    }
                }
            }
        }
    }

    // Sort to prefer 192.168.x.x, then 10.x.x.x
    valid_ips.sort_by_key(|ip| {
        if let std::net::IpAddr::V4(v4) = ip {
            let oct = v4.octets();
            if oct[0] == 192 && oct[1] == 168 {
                return 0;
            }
            if oct[0] == 10 {
                return 1;
            }
        }
        2
    });

    if let Some(ip) = valid_ips.first() {
        return Ok(*ip);
    }

    anyhow::bail!("Не удалось найти локальный IP адрес")
}

impl Drop for UpnpMapping {
    fn drop(&mut self) {
        let device = self.device.clone();
        let urn = self.service_urn.clone();
        let port = self.external_port;

        info!(
            "UPnP: Запущена очистка порта {} на '{}'...",
            port,
            device.friendly_name()
        );

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                if let Some(service) = device.find_service(&urn) {
                    let args = format!(
                        "<NewRemoteHost></NewRemoteHost>\
                         <NewExternalPort>{}</NewExternalPort>\
                         <NewProtocol>UDP</NewProtocol>",
                        port
                    );

                    match service
                        .action(device.url(), "DeletePortMapping", &args)
                        .await
                    {
                        Ok(_) => info!("UPnP: Порт {} успешно удален.", port),
                        Err(e) => error!("UPnP: Ошибка удаления порта {}: {}", port, e),
                    }
                }
            });
        });
    }
}
