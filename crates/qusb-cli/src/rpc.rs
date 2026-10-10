//! Plain JSON-RPC over ureq.
use serde_json::{json, Value};
use std::time::Duration;

type R<T> = Result<T, Box<dyn std::error::Error>>;

pub struct Rpc {
    url: String,
    agent: ureq::Agent,
}

impl Rpc {
    pub fn new(url: String) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build();
        Rpc { url, agent }
    }

    fn call(&self, method: &str, params: Value) -> R<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let r: Value = self.agent.post(&self.url).send_json(body)?.into_json()?;
        if let Some(e) = r.get("error") {
            return Err(format!("rpc {method}: {e}").into());
        }
        Ok(r["result"].clone())
    }

    pub fn balance(&self, addr: &str) -> R<u64> {
        self.call("getBalance", json!([addr, {"commitment": "confirmed"}]))?["value"]
            .as_u64()
            .ok_or_else(|| "bad balance".into())
    }
    pub fn min_rent_zero_data(&self) -> R<u64> {
        self.call("getMinimumBalanceForRentExemption", json!([0]))?
            .as_u64()
            .ok_or_else(|| "bad rent value".into())
    }
    pub fn blockhash(&self) -> R<[u8; 32]> {
        let r = self.call("getLatestBlockhash", json!([{"commitment": "confirmed"}]))?;
        qusb_core::b58::dec32(r["value"]["blockhash"].as_str().ok_or("bad blockhash")?)
            .map_err(Into::into)
    }
    /// Err carries the program logs when the simulation fails.
    pub fn simulate(&self, tx_b64: &str) -> R<()> {
        let r = self.call("simulateTransaction", json!([tx_b64, {"encoding": "base64", "sigVerify": true, "replaceRecentBlockhash": false, "commitment": "confirmed"}]))?;
        let v = &r["value"];
        if !v["err"].is_null() {
            let logs = v["logs"]
                .as_array()
                .map(|l| {
                    l.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join("\n  ")
                })
                .unwrap_or_default();
            return Err(format!("simulation failed: {}\n  {logs}", v["err"]).into());
        }
        Ok(())
    }
    pub fn send(&self, tx_b64: &str) -> R<String> {
        let r = self.call(
            "sendTransaction",
            json!([tx_b64, {"encoding": "base64", "skipPreflight": true}]),
        )?;
        r.as_str()
            .map(String::from)
            .ok_or_else(|| "bad signature".into())
    }
    /// Polls up to about a minute; true when confirmed or finalized.
    pub fn confirm(&self, sig: &str) -> R<bool> {
        for _ in 0..40 {
            let r = self.call("getSignatureStatuses", json!([[sig]]))?;
            let s = &r["value"][0];
            if !s.is_null() {
                if !s["err"].is_null() {
                    return Err(format!("transaction failed: {}", s["err"]).into());
                }
                if matches!(
                    s["confirmationStatus"].as_str(),
                    Some("confirmed" | "finalized")
                ) {
                    return Ok(true);
                }
            }
            std::thread::sleep(Duration::from_millis(1500));
        }
        Ok(false)
    }
}
