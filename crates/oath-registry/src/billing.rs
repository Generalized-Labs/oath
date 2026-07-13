use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

#[derive(Clone)]
pub struct StripeBilling {
    client: reqwest::Client,
    secret_key: String,
    webhook_secret: String,
}

impl StripeBilling {
    pub fn new(secret_key: String, webhook_secret: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            secret_key,
            webhook_secret,
        }
    }
    pub async fn create_checkout(
        &self,
        organization: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<String> {
        let response: Value = self
            .client
            .post("https://api.stripe.com/v1/checkout/sessions")
            .bearer_auth(&self.secret_key)
            .form(&[
                ("mode", "subscription"),
                ("line_items[0][price]", price_id),
                ("line_items[0][quantity]", "1"),
                ("success_url", success_url),
                ("cancel_url", cancel_url),
                ("client_reference_id", organization),
                ("metadata[organization]", organization),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        response
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("Stripe checkout response has no URL")
    }
    pub fn verify_webhook(&self, header: &str, body: &[u8], now: u64) -> Result<Value> {
        let mut timestamp = None;
        let mut signatures = Vec::new();
        for part in header.split(',') {
            if let Some(v) = part.strip_prefix("t=") {
                timestamp = v.parse::<u64>().ok();
            }
            if let Some(v) = part.strip_prefix("v1=") {
                signatures.push(v);
            }
        }
        let timestamp = timestamp.context("Stripe signature has no timestamp")?;
        anyhow::ensure!(
            now.abs_diff(timestamp) <= 300,
            "Stripe webhook timestamp is outside tolerance"
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(self.webhook_secret.as_bytes())?;
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        let expected = mac.finalize().into_bytes();
        let valid = signatures
            .into_iter()
            .filter_map(|value| hex::decode(value).ok())
            .any(|candidate| candidate == expected.as_slice());
        anyhow::ensure!(valid, "invalid Stripe webhook signature");
        Ok(serde_json::from_slice(body)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsigned_webhooks() {
        let billing = StripeBilling::new("sk".into(), "whsec".into());
        assert!(billing.verify_webhook("t=1,v1=00", b"{}", 1).is_err());
    }
}
