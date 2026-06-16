use anyhow::{anyhow, Result};
use futures_util::StreamExt;
use reqwest::Client;
use reqwest_eventsource::{Event, EventSource};
use serde_json::Value;
use std::time::Duration;

const ABLY_KEY_ID: &str = "aGkPAA.1VHkjw";
const ABLY_KEY_SECRET: &str = "Bai-67g05FcqHdfVOMiSfjYlK3aLz8wOzj5WeTgz4cw";
const ABLY_API_KEY: &str = "aGkPAA.1VHkjw:Bai-67g05FcqHdfVOMiSfjYlK3aLz8wOzj5WeTgz4cw";
const LOBBY_CHANNEL: &str = "minecraft-lobby";

#[derive(Clone)]
pub struct LobbyManager {
    client: Client,
}

impl LobbyManager {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    /// Запрашивает текущее состояние лобби (присутствие хостов)
    pub async fn fetch_presence(&self) -> Result<Vec<Value>> {
        let presence_url = format!("https://rest.ably.io/channels/{}/presence", LOBBY_CHANNEL);
        let messages_url = format!(
            "https://rest.ably.io/channels/{}/messages?limit=50",
            LOBBY_CHANNEL
        );

        let mut all_messages = Vec::new();

        // 1. Fetch Presence
        let pres_res = self
            .client
            .get(&presence_url)
            .basic_auth(ABLY_KEY_ID, Some(ABLY_KEY_SECRET))
            .send()
            .await;

        if let Ok(res) = pres_res {
            if res.status().is_success() {
                if let Ok(data) = res.json::<Vec<Value>>().await {
                    all_messages.extend(data);
                }
            }
        }

        // 2. Fetch Messages (since desktop hosts use messages now)
        let msg_res = self
            .client
            .get(&messages_url)
            .basic_auth(ABLY_KEY_ID, Some(ABLY_KEY_SECRET))
            .send()
            .await;

        if let Ok(res) = msg_res {
            if res.status().is_success() {
                if let Ok(data) = res.json::<Vec<Value>>().await {
                    all_messages.extend(data);
                }
            }
        }

        let mut servers = Vec::new();
        for msg in all_messages {
            // Only process messages named "host-presence" or actual presence messages (which have no "name" field or have an action field)
            if let Some(name) = msg.get("name").and_then(|n| n.as_str()) {
                if name != "host-presence" {
                    continue;
                }
            }
            if let Some(mut data) = msg.get("data").cloned() {
                // Ignore if it's a string, we expect an object
                if let Some(obj) = data.as_object_mut() {
                    if let Some(client_id) = msg.get("clientId") {
                        obj.insert("client_id".to_string(), client_id.clone());
                        obj.insert("peer_id".to_string(), client_id.clone());
                    }
                    servers.push(data);
                } else if let Some(s) = data.as_str() {
                    if let Ok(mut parsed) = serde_json::from_str::<Value>(s) {
                        if let Some(obj) = parsed.as_object_mut() {
                            if let Some(client_id) = msg.get("clientId") {
                                obj.insert("client_id".to_string(), client_id.clone());
                                obj.insert("peer_id".to_string(), client_id.clone());
                            }
                            servers.push(parsed);
                        }
                    }
                }
            }
        }

        // Deduplicate by peer_id to prevent the same host appearing multiple times
        let mut unique_servers = std::collections::HashMap::new();
        for server in servers {
            if let Some(peer_id) = server.get("peer_id").and_then(|v| v.as_str()) {
                unique_servers.entry(peer_id.to_string()).or_insert(server);
            }
        }

        Ok(unique_servers.into_values().collect())
    }

    /// Публикует присутствие хоста (добавляет его в лобби)
    pub async fn enter_presence(&self, client_id: &str, data: Value) -> Result<()> {
        let url = format!("https://rest.ably.io/channels/{}/messages", LOBBY_CHANNEL);

        let payload = serde_json::json!({
            "name": "host-presence",
            "clientId": client_id,
            "data": data
        });

        let res = self
            .client
            .post(&url)
            .basic_auth(ABLY_KEY_ID, Some(ABLY_KEY_SECRET))
            .json(&payload)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(anyhow!("Ably enter_presence failed: {}", res.status()));
        }

        Ok(())
    }

    /// Удаляет хоста из лобби
    pub async fn leave_presence(&self, client_id: &str) -> Result<()> {
        let url = format!("https://rest.ably.io/channels/{}/presence", LOBBY_CHANNEL);

        let payload = serde_json::json!({
            "clientId": client_id,
            "action": 3 // 3 = LEAVE
        });

        let res = self
            .client
            .post(&url)
            .basic_auth(ABLY_KEY_ID, Some(ABLY_KEY_SECRET))
            .json(&payload)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(anyhow!("Ably leave_presence failed: {}", res.status()));
        }

        Ok(())
    }

    /// Отправляет сообщение (например connect-request) в нужный канал
    pub async fn publish_event(&self, channel: &str, event_name: &str, data: Value) -> Result<()> {
        let url = format!("https://rest.ably.io/channels/{}/messages", channel);

        let payload = serde_json::json!({
            "name": event_name,
            "data": data
        });

        let res = self
            .client
            .post(&url)
            .basic_auth(ABLY_KEY_ID, Some(ABLY_KEY_SECRET))
            .json(&payload)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(anyhow!("Ably publish_event failed: {}", res.status()));
        }

        Ok(())
    }

    /// Создает SSE подписку на указанный канал
    pub fn subscribe_channel(&self, channel: &str) -> EventSource {
        let url = format!(
            "https://realtime.ably.io/sse?v=1.2&channels={}&key={}",
            channel, ABLY_API_KEY
        );

        EventSource::get(url)
    }
}
