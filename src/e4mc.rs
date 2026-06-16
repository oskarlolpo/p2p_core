use anyhow::Result;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct E4mcConfig {
    pub enabled_by_default: bool,
}

impl E4mcConfig {
    pub fn from_env() -> Self {
        Self::default()
    }
}

pub struct E4mcRuntime {
    pub domain: String,
    pub task: tokio::task::JoinHandle<Result<()>>,
}

impl E4mcRuntime {
    pub async fn wait(self) -> Result<()> {
        let _ = self.task.await;
        Ok(())
    }
}

pub async fn start_host_runtime(
    _config: E4mcConfig,
    _local_port: u16,
    _cancel: CancellationToken,
) -> Result<E4mcRuntime> {
    Err(anyhow::anyhow!("e4mc disabled"))
}
