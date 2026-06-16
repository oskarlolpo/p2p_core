pub mod bedrock_broadcaster;
pub mod broadcaster;
pub mod cert;
pub mod discovery;
pub mod e4mc;
pub mod lobby;
pub mod manager;
pub mod minecraft;
pub mod models;
pub mod nethernet_broadcaster;
pub mod proxy;
pub mod signaling;
pub mod stun;
pub mod tauri_shim;
pub mod test_server;
pub mod tunnel;
pub mod upnp;
pub mod wss_relay;

pub async fn discover_server() -> Option<discovery::ServerInfo> {
    discovery::discover_local_server(std::time::Duration::from_secs(3)).await
}

pub async fn start_broadcasters(
    room_name: String,
    host_name: String,
    mc_version: String,
    slots: String,
    proxy_port: u16,
) -> anyhow::Result<()> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let _ = broadcaster::Broadcasters::start(
        room_name, host_name, mc_version, slots, proxy_port, cancel,
    )
    .await?;
    // For now we intentionally "leak" or run it detached. We can manage cancellation later.
    Ok(())
}
