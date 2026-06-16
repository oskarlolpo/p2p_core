#[tokio::main]
async fn main() {
    println!("Scanning for LAN ports from logs...");
    match p2p_core::minecraft::get_available_lan_ports_command(vec![]).await {
        Ok(ports) => {
            println!("Found ports: {:?}", ports);
            for p in ports {
                println!("Trying to discover on port {}...", p.port);
                let res = p2p_core::discovery::discover_server_on_port(
                    p.port,
                    std::time::Duration::from_secs(2),
                )
                .await;
                println!("Result: {:?}", res);
            }
        }
        Err(e) => println!("Error finding ports: {}", e),
    }
}
