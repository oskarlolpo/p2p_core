use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct Event {
    pub name: String,
    pub payload: Value,
}

pub trait Emitter {
    fn emit<S: Serialize>(&self, event: &str, payload: S) -> Result<(), anyhow::Error>;
}

#[derive(Clone)]
pub struct AppHandle {
    sender: mpsc::UnboundedSender<Event>,
}

impl AppHandle {
    pub fn new(sender: mpsc::UnboundedSender<Event>) -> Self {
        Self { sender }
    }
}

impl Emitter for AppHandle {
    fn emit<S: Serialize>(&self, event: &str, payload: S) -> Result<(), anyhow::Error> {
        let payload = serde_json::to_value(payload)?;
        let _ = self.sender.send(Event {
            name: event.to_string(),
            payload,
        });
        Ok(())
    }
}
