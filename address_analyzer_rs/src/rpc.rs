use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Duration;

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: &'static str,
    method: &'a str,
    params: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

pub struct BitcoinRpcClient {
    client: reqwest::Client,
    url: String,
    auth: Option<(String, String)>,
}

impl BitcoinRpcClient {
    pub fn new(url: String, user: Option<String>, pass: Option<String>) -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10));
        
        Self {
            client: builder.build().unwrap_or_default(),
            url,
            auth: user.zip(pass),
        }
    }

    async fn call<T: for<'de> Deserialize<'de>>(&self, method: &str, params: Vec<serde_json::Value>) -> Result<T> {
        let req = RpcRequest {
            jsonrpc: "1.0",
            id: "cryscout",
            method,
            params,
        };

        let mut builder = self.client.post(&self.url)
            .json(&req);

        if let Some((user, pass)) = &self.auth {
            builder = builder.basic_auth(user, Some(pass));
        }

        let resp: RpcResponse<T> = builder.send().await?
            .json().await?;

        if let Some(err) = resp.error {
            return Err(anyhow!("RPC error: {}", err));
        }

        resp.result.ok_or_else(|| anyhow!("Empty RPC result"))
    }

    pub async fn get_block_count(&self) -> Result<u64> {
        self.call("getblockcount", vec![]).await
    }

    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        self.call("getblockhash", vec![height.into()]).await
    }

    pub async fn get_block_verbose(&self, hash: &str) -> Result<serde_json::Value> {
        self.call("getblock", vec![hash.into(), 2.into()]).await
    }

    pub async fn get_raw_transaction_verbose(&self, txid: &str) -> Result<serde_json::Value> {
        self.call("getrawtransaction", vec![txid.into(), true.into()]).await
    }

    pub async fn get_block_raw(&self, hash: &str) -> Result<String> {
        self.call("getblock", vec![hash.into(), 0.into()]).await
    }

    pub async fn get_raw_transaction(&self, txid: &str) -> Result<String> {
        self.call("getrawtransaction", vec![txid.into(), false.into()]).await
    }

    pub async fn get_raw_mempool(&self) -> Result<Vec<String>> {
        self.call("getrawmempool", vec![]).await
    }
}
