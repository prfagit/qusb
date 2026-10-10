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

    /// Retries the answers a busy endpoint gives (429, 502, 503, 504) with a growing pause, about 15
    /// seconds in all. Safe for every method here: reads repeat, and a transaction sent twice is
    /// still one signature.
    fn call(&self, method: &str, params: Value) -> R<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut wait = 500;
        let r: Value = loop {
            match self.agent.post(&self.url).send_json(&body) {
                Err(ureq::Error::Status(429 | 502 | 503 | 504, _)) if wait <= 8000 => {
                    std::thread::sleep(Duration::from_millis(wait));
                    wait *= 2;
                }
                r => break r?.into_json()?,
            }
        };
        if let Some(e) = r.get("error") {
            return Err(format!("rpc {method}: {e}").into());
        }
        Ok(r["result"].clone())
    }

    /// Lamports for each address, in order; 0 for an account that does not exist.
    pub fn balances(&self, addrs: &[String]) -> R<Vec<u64>> {
        let mut out = vec![];
        for c in addrs.chunks(100) {
            let r = self.call(
                "getMultipleAccounts",
                json!([c, {"commitment": "confirmed", "dataSlice": {"offset": 0, "length": 0}}]),
            )?;
            let v = r["value"].as_array().filter(|v| v.len() == c.len());
            for a in v.ok_or("bad accounts reply")? {
                out.push(match a {
                    Value::Null => 0,
                    a => a["lamports"].as_u64().ok_or("bad accounts reply")?,
                });
            }
        }
        Ok(out)
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
    /// The oldest slot this node still has blocks for. 0 on a node with full history.
    pub fn first_available_block(&self) -> R<u64> {
        self.call("getFirstAvailableBlock", json!([]))?
            .as_u64()
            .ok_or_else(|| "this RPC node does not say how far back its history goes".into())
    }
    /// One page, newest first and up to 1000, of the signatures of transactions that name `addr`.
    pub fn signatures(&self, addr: &str, before: Option<&str>) -> R<Vec<String>> {
        let mut opt = json!({"limit": 1000, "commitment": "confirmed"});
        if let Some(b) = before {
            opt["before"] = json!(b);
        }
        self.call("getSignaturesForAddress", json!([addr, opt]))?
            .as_array()
            .ok_or("bad signatures reply")?
            .iter()
            .map(|x| {
                Ok(x["signature"]
                    .as_str()
                    .ok_or("bad signatures reply")?
                    .into())
            })
            .collect()
    }
    pub fn transaction(&self, sig: &str) -> R<Value> {
        let r = self.call(
            "getTransaction",
            json!([sig, {"encoding": "json", "maxSupportedTransactionVersion": 0, "commitment": "confirmed"}]),
        )?;
        if r.is_null() {
            return Err(format!("this RPC node lists transaction {sig} but cannot return it; use a node with full history").into());
        }
        Ok(r)
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
    pub fn send(&self, tx_b64: &str) -> R<()> {
        self.call(
            "sendTransaction",
            json!([tx_b64, {"encoding": "base64", "skipPreflight": true}]),
        )?;
        Ok(())
    }
    /// Polls for about 90 seconds, longer than a blockhash lives. Ok(true) once confirmed; Ok(false)
    /// if that was never seen, which is not proof of failure; Err only when the chain says it failed.
    pub fn confirm(&self, sig: &str) -> R<bool> {
        for _ in 0..60 {
            // A poll that fails says nothing about the transaction: keep asking.
            if let Ok(r) = self.call("getSignatureStatuses", json!([[sig]])) {
                let s = &r["value"][0];
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
