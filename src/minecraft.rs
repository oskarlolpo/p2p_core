use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task,
    time::{timeout, Duration},
};

use crate::models::{
    ExternalServerProbe, LanPortDetection, LocalPlayerSnapshot, LocalTargetState,
    MinecraftClientRuntimeInfo, MinecraftNicknameDetection, PreflightReport,
};

const STATUS_PROTOCOL_CANDIDATES: &[i32] = &[767, 764, 760, 47];
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Deserialize)]
struct StatusResponse {
    version: MinecraftVersion,
    players: Option<MinecraftPlayers>,
    description: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct MinecraftVersion {
    name: String,
}

#[derive(Debug, Deserialize)]
struct MinecraftPlayers {
    online: u32,
    max: u32,
    #[serde(default)]
    sample: Vec<MinecraftPlayerSample>,
}

#[derive(Debug, Deserialize)]
struct MinecraftPlayerSample {
    name: String,
}

pub async fn detect_local_version(port: u16) -> Result<String> {
    let mut last_error = None;
    for protocol_version in STATUS_PROTOCOL_CANDIDATES {
        match query_status("127.0.0.1", port, *protocol_version).await {
            Ok(response) => return Ok(response.version.name),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("failed to get a valid Minecraft status response")))
}
fn probe_bedrock_server_sync(host: &str, port: u16) -> Result<ExternalServerProbe> {
    let start = std::time::Instant::now();
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").context("Failed to bind UDP socket")?;
    socket.set_read_timeout(Some(std::time::Duration::from_millis(800)))?;
    socket.set_write_timeout(Some(std::time::Duration::from_millis(800)))?;

    let mut req = vec![0x01]; // Unconnected Ping
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    req.extend_from_slice(&time.to_be_bytes()); // time
    req.extend_from_slice(&[
        0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56,
        0x78,
    ]); // magic
    req.extend_from_slice(&[0u8; 8]); // client guid

    socket
        .send_to(&req, format!("{}:{}", host, port))
        .context("Failed to send UDP ping")?;

    let mut buf = [0u8; 1024];
    let (len, _) = socket
        .recv_from(&mut buf)
        .context("UDP read timeout or fail")?;

    if len > 35 && buf[0] == 0x1C {
        // Unconnected Pong
        let str_len = u16::from_be_bytes([buf[33], buf[34]]) as usize;
        if 35 + str_len <= len {
            let server_id = String::from_utf8_lossy(&buf[35..35 + str_len]);
            let parts: Vec<&str> = server_id.split(';').collect();
            if parts.len() >= 6 {
                let name = parts[1].to_string();
                let version = parts[3].to_string();
                let online_players: u32 = parts[4].parse().unwrap_or(0);
                let max_players: u32 = parts[5].parse().unwrap_or(0);

                return Ok(ExternalServerProbe {
                    room_name: name.clone(),
                    host_name: name,
                    version: Some(version),
                    online_players,
                    max_players,
                    ping_ms: Some(start.elapsed().as_millis() as u64),
                });
            }
        }
    }
    anyhow::bail!("Invalid or no Bedrock response")
}

pub async fn probe_external_server(host: String, port: u16) -> Result<ExternalServerProbe> {
    let start = std::time::Instant::now();
    let mut last_error = None;

    // First, if checking local, use the robust multi-protocol broadcast discovery
    // This handles both RakNet and NetherNet AND bypasses Windows UWP loopback isolation
    if host == "127.0.0.1" || host == "localhost" || host == "::1" {
        if let Some(info) =
            crate::discovery::discover_server_on_port(port, std::time::Duration::from_millis(800))
                .await
        {
            return Ok(ExternalServerProbe {
                room_name: info.name.clone(),
                host_name: info.host_name,
                version: Some(info.mc_version),
                online_players: info.players,
                max_players: info.max_players,
                ping_ms: Some(start.elapsed().as_millis() as u64),
            });
        }
    }

    if let Ok(Ok(bedrock_probe)) = task::spawn_blocking({
        let host = host.clone();
        move || probe_bedrock_server_sync(&host, port)
    })
    .await
    {
        return Ok(bedrock_probe);
    }
    for protocol_version in STATUS_PROTOCOL_CANDIDATES {
        match query_status(&host, port, *protocol_version).await {
            Ok(response) => {
                let players = response.players.unwrap_or(MinecraftPlayers {
                    online: 0,
                    max: 0,
                    sample: Vec::new(),
                });
                return Ok(ExternalServerProbe {
                    room_name: status_description_to_string(&response.description)
                        .unwrap_or_else(|| host.clone()),
                    host_name: host.clone(),
                    version: Some(response.version.name),
                    online_players: players.online,
                    max_players: players.max,
                    ping_ms: Some(start.elapsed().as_millis() as u64),
                });
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("failed to query external server status")))
}

pub async fn build_preflight_report(port: u16) -> PreflightReport {
    // Always detect the best Bedrock LAN port from system listeners
    // (e.g. port 7551 when a world is opened to LAN)
    let detected_lan_port = task::spawn_blocking(|| {
        detect_lan_ports_from_system_listeners()
            .into_iter()
            .find(|l| l.source_line.contains("UDP"))
            .map(|l| l.port)
    })
    .await
    .ok()
    .flatten();

    if let Err(reachability_error) = probe_local_tcp(port).await {
        // TCP reachability failed. However, for Bedrock (UDP) servers, TCP won't work.
        // We fallback to checking if the port is actively listening in netstat.
        let is_system_listener = task::spawn_blocking(move || {
            detect_lan_ports_from_system_listeners()
                .into_iter()
                .any(|l| l.port == port)
        })
        .await
        .unwrap_or(false);

        if is_system_listener {
            return PreflightReport {
                local_port: port,
                reachable: true,
                state: LocalTargetState::Reachable,
                minecraft_version: Some("Detected (UDP/Bedrock)".to_string()),
                recommended_host_action:
                    "Local Minecraft was detected via system listeners. You can launch the host."
                        .into(),
                note: Some(format!(
                    "TCP reachability failed, but port is open in netstat: {reachability_error:#}"
                )),
                detected_lan_port,
            };
        }

        return PreflightReport {
            local_port: port,
            reachable: false,
            state: LocalTargetState::Unreachable,
            minecraft_version: None,
            recommended_host_action:
                "Open the world to LAN or start the local Minecraft server, then try hosting again.".into(),
            note: Some(format!(
                "Local TCP reachability check failed and port not found in netstat: {reachability_error:#}"
            )),
            detected_lan_port,
        };
    }

    match detect_local_version(port).await {
        Ok(version) => {
            let mut note = "The world is already open to LAN or the local server is accepting connections.".to_string();
            let version_lower = version.to_lowercase();
            if version_lower.contains("paper") || version_lower.contains("purpur") || version_lower.contains("spigot") {
                note = format!("{}\n\nTips: Detected a Paper/Purpur/Spigot server. For skin support, consider installing the SkinsRestorer plugin.", note);
            }
            PreflightReport {
                local_port: port,
                reachable: true,
                state: LocalTargetState::Reachable,
                minecraft_version: Some(version),
                recommended_host_action:
                    "Local Minecraft is reachable. You can launch the host and publish the room.".into(),
                note: Some(note),
                detected_lan_port,
            }
        },
        Err(version_error) => {
            PreflightReport {
                local_port: port,
                reachable: true,
                state: LocalTargetState::Reachable,
                minecraft_version: None,
                recommended_host_action:
                    "The TCP port is reachable, but Minecraft version detection failed. You can still launch the host.".into(),
                note: Some(format!("Version detection failed during status ping: {version_error:#}")),
                detected_lan_port,
            }
        }
    }
}

pub async fn detect_minecraft_nickname() -> Result<MinecraftNicknameDetection> {
    task::spawn_blocking(detect_minecraft_nickname_blocking)
        .await
        .context("failed to await Minecraft nickname detector task")?
}

pub async fn detect_client_runtime_info() -> Result<MinecraftClientRuntimeInfo> {
    task::spawn_blocking(detect_client_runtime_info_blocking)
        .await
        .context("failed to await Minecraft runtime detector task")?
}

pub async fn get_available_lan_ports_command(
    ignored_ports: Vec<u16>,
) -> Result<Vec<LanPortDetection>, String> {
    let all_detected = task::spawn_blocking(detect_all_lan_ports_blocking)
        .await
        .map_err(|e| format!("Task join error: {e}"))?
        .map_err(|e| format!("Detection failed: {e}"))?;

    // Фильтруем игнорируемые порты
    let filtered = all_detected
        .into_iter()
        .filter(|d| !ignored_ports.contains(&d.port))
        .collect();

    Ok(filtered)
}

pub async fn read_local_player_snapshot(port: u16) -> Result<LocalPlayerSnapshot> {
    let response = detect_status_response("127.0.0.1", port).await;
    match response {
        Ok(res) => {
            let players = res.players.unwrap_or(MinecraftPlayers {
                online: 0,
                max: 0,
                sample: Vec::new(),
            });
            Ok(LocalPlayerSnapshot {
                online_players: players.online,
                max_players: players.max,
                sample_names: players
                    .sample
                    .into_iter()
                    .filter_map(|sample| sanitize_minecraft_nickname(&sample.name))
                    .collect(),
            })
        }
        Err(error) => {
            tracing::debug!("Failed to read local player snapshot: {error:#}");
            Ok(LocalPlayerSnapshot {
                online_players: 0,
                max_players: 0,
                sample_names: Vec::new(),
            })
        }
    }
}

async fn query_status(host: &str, port: u16, protocol_version: i32) -> Result<StatusResponse> {
    let target = format!("{host}:{port}");
    let fut = async {
        let mut stream = TcpStream::connect(&target)
            .await
            .with_context(|| format!("failed to connect to {target}"))?;

        let handshake = build_handshake_packet(host, port, protocol_version)?;
        stream.write_all(&handshake).await?;
        stream.write_all(&[0x01, 0x00]).await?;
        stream.flush().await?;

        let _packet_length = read_varint(&mut stream).await?;
        let packet_id = read_varint(&mut stream).await?;
        if packet_id != 0 {
            return Err(anyhow!("unexpected packet id {packet_id}"));
        }

        let payload_len = read_varint(&mut stream).await?;
        if payload_len < 0 {
            return Err(anyhow!("received a negative status payload length"));
        }

        let mut payload = vec![0u8; payload_len as usize];
        stream.read_exact(&mut payload).await?;

        let response: StatusResponse =
            serde_json::from_slice(&payload).context("failed to parse Minecraft status JSON")?;
        Ok(response)
    };

    timeout(Duration::from_secs(2), fut)
        .await
        .context("timed out while querying the local Minecraft target")?
}

async fn detect_status_response(host: &str, port: u16) -> Result<StatusResponse> {
    let mut last_error = None;
    for protocol_version in STATUS_PROTOCOL_CANDIDATES {
        match query_status(host, port, *protocol_version).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("failed to get a valid Minecraft status response")))
}

async fn probe_local_tcp(port: u16) -> Result<()> {
    let target = format!("127.0.0.1:{port}");
    let stream = timeout(Duration::from_secs(2), TcpStream::connect(&target))
        .await
        .context("timed out during the local Minecraft TCP probe")?
        .with_context(|| format!("failed to connect to {target}"))?;
    stream
        .writable()
        .await
        .with_context(|| format!("local Minecraft target {target} never became writable"))?;
    Ok(())
}

pub fn detect_all_lan_ports_blocking() -> Result<Vec<LanPortDetection>> {
    let all_detections = detect_lan_ports_from_system_listeners();

    // Убираем дубликаты по номеру порта
    let mut unique = HashMap::new();
    for det in all_detections {
        unique.entry(det.port).or_insert(det);
    }

    let mut result: Vec<LanPortDetection> = unique.into_values().collect();
    // Сортируем (порты из логов обычно более надежные или свежие, если их нашли первыми)
    result.sort_by_key(|d| d.port);

    if result.is_empty() {
        return Err(anyhow!("could not find any Minecraft LAN ports"));
    }

    Ok(result)
}

#[derive(Debug, Clone)]
struct JavaProcessMetadata {
    pid: u32,
    command_line: String,
    working_dir: Option<PathBuf>,
    server_port: Option<u16>,
}

fn detect_lan_ports_from_system_listeners() -> Vec<LanPortDetection> {
    let java_processes = collect_java_process_metadata();

    let mut candidates = Vec::new();

    // 1. Check TCP (Java)
    if let Ok(output) = hidden_command("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
    {
        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout);
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with("TCP") {
                    continue;
                }
                let columns = trimmed.split_whitespace().collect::<Vec<_>>();
                if columns.len() < 5 {
                    continue;
                }
                if !columns[3].eq_ignore_ascii_case("LISTENING") {
                    continue;
                }

                let local = columns[1];
                let Ok(pid) = columns[4].parse::<u32>() else {
                    continue;
                };
                let Some((host, port)) = split_host_port_label(local) else {
                    continue;
                };
                if port == 0 || port < 1024 || !is_local_bind_host(&host) {
                    continue;
                }

                if let Some(meta) = java_processes.get(&pid) {
                    let mut priority = 0;
                    let cmd = meta.command_line.to_lowercase();

                    // 0. Base check: is it even likely to be Minecraft?
                    let is_mc_related = cmd.contains("minecraft")
                        || cmd.contains(".minecraft")
                        || cmd.contains("fabric-loader")
                        || cmd.contains("forge")
                        || cmd.contains("quilt")
                        || cmd.contains("net.minecraft")
                        || cmd.contains("server.jar")
                        || cmd.contains("papermc")
                        || cmd.contains("spigot");

                    let is_javaw = cmd.contains("javaw");

                    if !is_mc_related && !is_javaw {
                        priority -= 500;
                    } else if is_mc_related {
                        priority += 150;
                    } else {
                        priority += 10;
                    }

                    // 1. If it's the standard port 25565
                    if port == 25565 {
                        priority += 100;
                    }

                    if let Some(target) = meta.server_port {
                        if port == target {
                            priority += 250;
                        }
                    }

                    // 3. Specific server jar checks
                    if cmd.contains("purpur")
                        || cmd.contains("paper")
                        || cmd.contains("spigot")
                        || cmd.contains("velocity")
                        || cmd.contains("waterfall")
                    {
                        priority += 100;
                    }

                    // 4. Client-side "Open to LAN" detection
                    if is_mc_related
                        && (cmd.contains("minecraft.applet")
                            || cmd.contains("net.minecraft.client.main.main"))
                    {
                        priority += 80;
                        if port > 49151 {
                            priority += 70;
                        }
                    }

                    candidates.push((priority, port, pid, local.to_string(), "TCP"));
                }
            }
        }
    }

    // 2. Check UDP (Bedrock)
    if let Ok(output) = hidden_command("netstat")
        .args(["-ano", "-p", "udp"])
        .output()
    {
        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout);
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with("UDP") {
                    continue;
                }
                let columns = trimmed.split_whitespace().collect::<Vec<_>>();
                if columns.len() < 4 {
                    continue;
                }

                let local = columns[1];
                let Ok(pid) = columns[3].parse::<u32>() else {
                    continue;
                };
                let Some((host, port)) = split_host_port_label(local) else {
                    continue;
                };
                if port == 0 || port < 1024 || !is_local_bind_host(&host) {
                    continue;
                }

                if let Some(meta) = java_processes.get(&pid) {
                    let cmd = meta.command_line.to_lowercase();
                    if cmd.contains("minecraft.windows") {
                        let mut priority = 200;

                        // Standard Bedrock dedicated server ports
                        if port == 19132 || port == 19133 {
                            priority += 300;
                        }
                        // Port 7551: confirmed as the main LAN broadcast + game port
                        // when opening a Bedrock world to LAN (binds 0.0.0.0 and broadcasts
                        // on subnet:7551 every ~2s for LAN discovery)
                        else if port == 7551 {
                            priority += 250;
                        }
                        // Other high ports (ephemeral game session ports)
                        else if port > 49151 {
                            priority += 50;
                        }

                        // Bonus: if bound to 0.0.0.0 or [::] — it accepts all interfaces,
                        // which is a strong signal that this is the main listening port
                        if host == "0.0.0.0" || host == "::" || host == "0" {
                            priority += 100;
                        }

                        if priority > 0 {
                            candidates.push((priority, port, pid, local.to_string(), "UDP"));
                        }
                    }
                }
            }
        }
    }

    candidates.sort_by(|a, b| b.0.cmp(&a.0));

    candidates
        .into_iter()
        .map(|(prio, port, pid, local, proto)| LanPortDetection {
            port,
            source_path: "system:netstat+ps".into(),
            source_line: format!(
                "netstat {} {} pid {} (priority {})",
                proto, local, pid, prio
            ),
        })
        .collect()
}

fn detect_lan_port_from_system_listeners() -> Option<LanPortDetection> {
    detect_lan_ports_from_system_listeners().into_iter().next()
}

fn collect_java_process_metadata() -> HashMap<u32, JavaProcessMetadata> {
    let mut map = HashMap::new();

    // ИСПРАВЛЕНИЕ: Добавлен javaw.exe и Minecraft.Windows.exe.
    let ps_script = "Get-CimInstance Win32_Process -Filter \"name = 'java.exe' OR name = 'javaw.exe' OR name = 'Minecraft.Windows.exe'\" | Select-Object ProcessId, CommandLine, WorkingDirectory | ConvertTo-Json";
    let output = hidden_command("powershell")
        .args(["-Command", ps_script])
        .output();

    let Ok(output) = output else {
        return map;
    };
    if !output.status.success() {
        return map;
    }

    let json_text = String::from_utf8_lossy(&output.stdout);

    // Axum/Serde can be tricky with single vs array JSON from PowerShell
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct PsProcess {
        process_id: u32,
        command_line: Option<String>,
        working_directory: Option<String>,
    }

    let items: Vec<PsProcess> = if json_text.trim().starts_with('[') {
        serde_json::from_str(&json_text).unwrap_or_default()
    } else {
        serde_json::from_str::<PsProcess>(&json_text)
            .map(|i| vec![i])
            .unwrap_or_default()
    };

    for item in items {
        let working_dir = item.working_directory.as_ref().map(PathBuf::from);
        let server_port = working_dir.as_ref().and_then(|path| {
            let props = path.join("server.properties");
            if props.exists() {
                fs::read_to_string(props).ok().and_then(|c| {
                    c.lines()
                        .find(|l| l.starts_with("server-port="))
                        .and_then(|l| l.split('=').nth(1))
                        .and_then(|v| v.trim().parse::<u16>().ok())
                })
            } else {
                None
            }
        });

        map.insert(
            item.process_id,
            JavaProcessMetadata {
                pid: item.process_id,
                command_line: item.command_line.unwrap_or_default(),
                working_dir,
                server_port,
            },
        );
    }

    map
}

fn split_host_port_label(value: &str) -> Option<(String, u16)> {
    if value.is_empty() {
        return None;
    }

    if value.starts_with('[') {
        let close = value.find(']')?;
        let host = value.get(1..close)?.to_string();
        let port = value.get(close + 2..)?.parse::<u16>().ok()?;
        return Some((host, port));
    }

    let (host, port) = value.rsplit_once(':')?;
    Some((host.to_string(), port.parse::<u16>().ok()?))
}

fn is_local_bind_host(host: &str) -> bool {
    let normalized = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "127.0.0.1" | "0.0.0.0" | "::1" | "::" | "*" | "localhost"
    )
}

fn hidden_command(program: &str) -> Command {
    let mut command = Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    command
}

fn detect_nickname_from_running_processes() -> Option<MinecraftNicknameDetection> {
    let processes = collect_java_process_metadata();
    for meta in processes.values() {
        let cmd = &meta.command_line;
        if let Some(idx) = cmd.find("--username ") {
            let start = idx + 11;
            let substr = &cmd[start..];
            let end = substr.find(' ').unwrap_or(substr.len());
            let raw_nick = substr[..end].trim_matches(|c| c == '"' || c == '\'');
            if let Some(nick) = sanitize_minecraft_nickname(raw_nick) {
                return Some(MinecraftNicknameDetection {
                    nickname: nick,
                    source_path: format!("running process (pid {})", meta.pid),
                });
            }
        }
    }
    None
}

fn detect_minecraft_nickname_blocking() -> Result<MinecraftNicknameDetection> {
    if let Some(detection) = detect_nickname_from_running_processes() {
        return Ok(detection);
    }

    let candidates = collect_nickname_sources();
    for path in candidates {
        if !path.exists() {
            continue;
        }
        if let Some(contents) = read_text_lossy(&path) {
            if let Some(nickname) = parse_nickname_from_file(&path, &contents) {
                return Ok(MinecraftNicknameDetection {
                    nickname,
                    source_path: path.display().to_string(),
                });
            }
        }
    }
    Err(anyhow!(
        "could not detect minecraft nickname from launcher files or logs"
    ))
}

fn detect_client_runtime_info_blocking() -> Result<MinecraftClientRuntimeInfo> {
    let nickname = detect_minecraft_nickname_blocking().ok();
    let candidates = collect_nickname_sources();

    for path in candidates {
        if !path.exists() {
            continue;
        }
        let Some(contents) = read_text_lossy(&path) else {
            continue;
        };
        let launcher = infer_launcher_from_path(&path);
        let (minecraft_version, mod_loader) = infer_runtime_from_file(&path, &contents);
        if launcher.is_some() || minecraft_version.is_some() || mod_loader.is_some() {
            return Ok(MinecraftClientRuntimeInfo {
                nickname: nickname.as_ref().map(|value| value.nickname.clone()),
                launcher,
                minecraft_version,
                mod_loader,
                source_path: Some(path.display().to_string()),
                note: nickname
                    .as_ref()
                    .map(|value| format!("nickname source: {}", value.source_path)),
            });
        }
    }

    Err(anyhow!(
        "could not detect launcher, Minecraft version, or mod loader from local launcher files/logs"
    ))
}

fn collect_nickname_sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(app_data) = std::env::var_os("APPDATA") {
        let app_data = PathBuf::from(app_data);
        files.push(app_data.join(".minecraft").join("launcher_accounts.json"));
        files.push(app_data.join(".minecraft").join("launcher_profiles.json"));
        files.push(app_data.join(".minecraft").join("logs").join("latest.log"));
        files.push(
            app_data
                .join(".tlauncher")
                .join("legacy")
                .join("Minecraft")
                .join("logs")
                .join("latest.log"),
        );
        files.push(
            app_data
                .join(".tlauncher")
                .join("legacy")
                .join("Minecraft")
                .join("game")
                .join("logs")
                .join("latest.log"),
        );
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        let local_app_data = PathBuf::from(local_app_data);
        files.push(
            local_app_data
                .join(".minecraft")
                .join("launcher_accounts.json"),
        );
        files.push(
            local_app_data
                .join(".minecraft")
                .join("launcher_profiles.json"),
        );
        files.push(
            local_app_data
                .join(".minecraft")
                .join("logs")
                .join("latest.log"),
        );
        files.push(
            local_app_data
                .join("Packages")
                .join("Microsoft.4297127D64EC6_8wekyb3d8bbwe")
                .join("LocalCache")
                .join("Roaming")
                .join(".minecraft")
                .join("logs")
                .join("latest.log"),
        );
    }
    if let Some(user_profile) = std::env::var_os("USERPROFILE") {
        let user_profile = PathBuf::from(user_profile);
        files.push(
            user_profile
                .join("AppData")
                .join("Roaming")
                .join(".minecraft")
                .join("logs")
                .join("latest.log"),
        );
    }
    // Сортируем источники ника по дате изменения файла (самые свежие первыми)
    files.retain(|p| p.is_file());
    files.sort_by(|a, b| {
        let meta_a = std::fs::metadata(a)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let meta_b = std::fs::metadata(b)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        meta_b.cmp(&meta_a)
    });
    files.dedup();

    files
}

pub fn get_latest_bedrock_world_name() -> Option<String> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")?;
    let worlds_dir = PathBuf::from(local_app_data)
        .join("Packages")
        .join("Microsoft.4297127D64EC6_8wekyb3d8bbwe")
        .join("LocalState")
        .join("games")
        .join("com.mojang")
        .join("minecraftWorlds");

    if !worlds_dir.exists() || !worlds_dir.is_dir() {
        return None;
    }

    let mut latest_world: Option<(PathBuf, std::time::SystemTime)> = None;

    if let Ok(entries) = fs::read_dir(&worlds_dir) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    if let Ok(modified) = metadata.modified() {
                        if let Some((_, latest_time)) = latest_world {
                            if modified > latest_time {
                                latest_world = Some((entry.path(), modified));
                            }
                        } else {
                            latest_world = Some((entry.path(), modified));
                        }
                    }
                }
            }
        }
    }

    if let Some((path, _)) = latest_world {
        let levelname_path = path.join("levelname.txt");
        if levelname_path.exists() {
            if let Some(contents) = read_text_lossy(&levelname_path) {
                let trimmed = contents.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    None
}

fn parse_nickname_from_file(path: &Path, contents: &str) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if name == "launcher_accounts.json" {
        return parse_launcher_accounts_nick(contents);
    }
    if name == "launcher_profiles.json" {
        return parse_launcher_profiles_nick(contents);
    }
    if name.ends_with(".log") || name.ends_with(".txt") {
        return parse_logs_nick(contents);
    }
    None
}

fn parse_launcher_accounts_nick(contents: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(contents).ok()?;
    let accounts = value.get("accounts")?.as_object()?;

    let active_id = value.get("activeAccountLocalId").and_then(|item| {
        item.as_str()
            .map(str::to_string)
            .or_else(|| item.as_u64().map(|id| id.to_string()))
    });

    if let Some(active_id) = active_id {
        if let Some(name) = accounts
            .get(&active_id)
            .and_then(|account| account.get("minecraftProfile"))
            .and_then(|profile| profile.get("name"))
            .and_then(|item| item.as_str())
            .and_then(sanitize_minecraft_nickname)
        {
            return Some(name);
        }
    }

    for account in accounts.values() {
        if let Some(name) = account
            .get("minecraftProfile")
            .and_then(|profile| profile.get("name"))
            .and_then(|item| item.as_str())
            .and_then(sanitize_minecraft_nickname)
        {
            return Some(name);
        }
    }

    None
}

fn parse_launcher_profiles_nick(contents: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(contents).ok()?;
    let selected_profile = value
        .get("selectedUser")
        .and_then(|item| item.get("profile"))
        .and_then(|item| item.as_str())?;
    let auth_db = value.get("authenticationDatabase")?.as_object()?;
    for account in auth_db.values() {
        if let Some(display_name) = account
            .get("profiles")
            .and_then(|profiles| profiles.get(selected_profile))
            .and_then(|profile| profile.get("displayName"))
            .and_then(|name| name.as_str())
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
        {
            return Some(display_name);
        }
    }

    value
        .as_object()
        .and_then(|obj| obj.get("profiles"))
        .and_then(|profiles| profiles.as_object())
        .and_then(|profiles| profiles.values().find_map(|profile| profile.get("name")))
        .and_then(|name| name.as_str())
        .and_then(sanitize_minecraft_nickname)
}

fn parse_logs_nick(contents: &str) -> Option<String> {
    for line in contents.lines().rev() {
        for marker in [
            "Setting user: ",
            "Session Name is ",
            "Username: ",
            "Logged in as ",
        ] {
            if let Some(index) = line.find(marker) {
                let part = &line[index + marker.len()..];
                let nick = part
                    .chars()
                    .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                    .collect::<String>();
                if let Some(name) = sanitize_minecraft_nickname(&nick) {
                    return Some(name);
                }
            }
        }
    }
    None
}

fn infer_runtime_from_file(path: &Path, contents: &str) -> (Option<String>, Option<String>) {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name == "launcher_profiles.json" || name == "launcher_accounts.json" {
        let version = parse_launcher_version(contents);
        return (version, None);
    }
    if name.ends_with(".log") || name.ends_with(".txt") {
        return parse_log_runtime(contents);
    }
    (None, None)
}

fn parse_launcher_version(contents: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(contents).ok()?;
    value
        .as_object()
        .and_then(|obj| obj.get("profiles"))
        .and_then(|profiles| profiles.as_object())
        .and_then(|profiles| {
            profiles.values().find_map(|profile| {
                profile
                    .get("lastVersionId")
                    .and_then(|item| item.as_str())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            })
        })
}

fn parse_log_runtime(contents: &str) -> (Option<String>, Option<String>) {
    let mut minecraft_version = None;
    let mut mod_loader = None;

    for line in contents.lines().rev() {
        let trimmed = line.trim();

        // Optimization: skip empty lines
        if trimmed.is_empty() {
            continue;
        }

        if minecraft_version.is_none() {
            if let Some((version, loader)) = parse_fabric_runtime(trimmed) {
                minecraft_version = Some(version);
                mod_loader = Some(loader);
            } else if let Some((version, loader)) = parse_quilt_runtime(trimmed) {
                minecraft_version = Some(version);
                mod_loader = Some(loader);
            } else if let Some((version, loader)) = parse_forge_runtime(trimmed) {
                minecraft_version = Some(version);
                mod_loader = Some(loader);
            } else if let Some(version) = parse_launched_version(trimmed) {
                minecraft_version = Some(version);
            }

            // If we found version, we might still want to find mod loader if it wasn't in the same line
            if minecraft_version.is_some() && mod_loader.is_some() {
                break;
            }
        }

        // Secondary check for mod loader if not found yet
        if mod_loader.is_none() {
            if trimmed.contains("FabricLoader") || trimmed.contains("net.fabricmc.loader") {
                mod_loader = Some("Fabric".into());
            } else if trimmed.contains("Forge mod loading")
                || trimmed.contains("net.minecraftforge.fml")
            {
                mod_loader = Some("Forge".into());
            } else if trimmed.contains("QuiltLoader") {
                mod_loader = Some("Quilt".into());
            }
        }
    }

    (minecraft_version, mod_loader)
}

fn parse_fabric_runtime(line: &str) -> Option<(String, String)> {
    let (_, tail) = line.split_once("Loading Minecraft ")?;
    let (version, loader_tail) = tail.split_once(" with Fabric Loader ")?;
    Some((
        version.trim().to_string(),
        format!("Fabric {}", loader_tail.trim()),
    ))
}

fn parse_quilt_runtime(line: &str) -> Option<(String, String)> {
    let (_, tail) = line.split_once("Loading Minecraft ")?;
    let (version, loader_tail) = tail.split_once(" with Quilt Loader ")?;
    Some((
        version.trim().to_string(),
        format!("Quilt {}", loader_tail.trim()),
    ))
}

fn parse_forge_runtime(line: &str) -> Option<(String, String)> {
    let (_, tail) = line.split_once("Forge mod loading, version ")?;
    let (forge_version, rest) = tail.split_once(", for MC ")?;
    let mc_version = rest
        .split_whitespace()
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some((
        mc_version.to_string(),
        format!("Forge {}", forge_version.trim()),
    ))
}

fn parse_launched_version(line: &str) -> Option<String> {
    let (_, tail) = line.split_once("Launched Version: ")?;
    let version = tail.split_whitespace().next()?.trim();
    (!version.is_empty()).then(|| version.to_string())
}

fn infer_launcher_from_path(path: &Path) -> Option<String> {
    let normalized = path.display().to_string().to_ascii_lowercase();
    if normalized.contains("prismlauncher") {
        return Some("PrismLauncher".into());
    }
    if normalized.contains("multimc") {
        return Some("MultiMC".into());
    }
    if normalized.contains("curseforge") {
        return Some("CurseForge".into());
    }
    if normalized.contains(".tlauncher") {
        return Some("TLauncher".into());
    }
    if normalized.contains("microsoft.4297127d64ec6_8wekyb3d8bbwe") {
        return Some("Minecraft Launcher (MS Store)".into());
    }
    if normalized.contains(".minecraft") {
        return Some("Minecraft Launcher".into());
    }
    None
}

fn sanitize_minecraft_nickname(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.len() < 3 || normalized.len() > 16 {
        return None;
    }
    normalized
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        .then_some(normalized.to_string())
}

fn read_text_lossy(path: &Path) -> Option<String> {
    use encoding_rs::WINDOWS_1251;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    let len = metadata.len();

    // For json files, read fully. For logs, read last 32 KB.
    let is_json = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .eq_ignore_ascii_case("json");
    let read_len = if is_json {
        len
    } else {
        std::cmp::min(len, 32 * 1024)
    };

    if len > read_len {
        file.seek(SeekFrom::End(-(read_len as i64))).ok()?;
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    if bytes.is_empty() {
        return Some(String::new());
    }

    // Preserve non-ASCII characters (e.g. Cyrillic) instead of dropping them.
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Some(String::from_utf8_lossy(&bytes[3..]).into_owned());
    }

    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        let mut utf16_units = Vec::with_capacity((bytes.len() - 2) / 2);
        let little_endian = bytes.starts_with(&[0xFF, 0xFE]);
        let data = &bytes[2..];
        for chunk in data.chunks_exact(2) {
            let value = if little_endian {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], chunk[1]])
            };
            utf16_units.push(value);
        }
        return Some(String::from_utf16_lossy(&utf16_units));
    }

    if let Ok(text) = String::from_utf8(bytes.clone()) {
        return Some(text);
    }

    let (decoded, _, _) = WINDOWS_1251.decode(&bytes);
    Some(decoded.to_string())
}

fn status_description_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.trim().to_string()),
        serde_json::Value::Object(map) => {
            if let Some(text) = map.get("text").and_then(|value| value.as_str()) {
                if !text.trim().is_empty() {
                    return Some(text.trim().to_string());
                }
            }
            if let Some(extra) = map.get("extra").and_then(|value| value.as_array()) {
                let combined = extra
                    .iter()
                    .filter_map(status_description_to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim()
                    .to_string();
                if !combined.is_empty() {
                    return Some(combined);
                }
            }
            None
        }
        _ => None,
    }
}

fn build_handshake_packet(host: &str, port: u16, protocol_version: i32) -> Result<Vec<u8>> {
    let mut packet = Vec::new();
    packet.push(0x00);
    write_varint(&mut packet, protocol_version)?;
    write_varint(&mut packet, host.len() as i32)?;
    packet.extend_from_slice(host.as_bytes());
    packet.extend_from_slice(&port.to_be_bytes());
    write_varint(&mut packet, 1)?;

    let mut framed = Vec::new();
    write_varint(&mut framed, packet.len() as i32)?;
    framed.extend_from_slice(&packet);
    Ok(framed)
}

fn write_varint(buffer: &mut Vec<u8>, value: i32) -> Result<()> {
    let mut value = u32::try_from(value).context("negative VarInt is not supported")?;
    loop {
        if value & !0x7F == 0 {
            buffer.push(value as u8);
            return Ok(());
        }

        buffer.push(((value & 0x7F) | 0x80) as u8);
        value >>= 7;
    }
}

async fn read_varint(stream: &mut TcpStream) -> Result<i32> {
    let mut value = 0i32;
    let mut position = 0;

    loop {
        if position >= 35 {
            return Err(anyhow!("VarInt is too long"));
        }

        let byte = stream.read_u8().await?;
        value |= i32::from(byte & 0x7F) << position;

        if byte & 0x80 == 0 {
            return Ok(value);
        }

        position += 7;
    }
}
