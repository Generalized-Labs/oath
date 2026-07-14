use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct OidcVerifier {
    client: reqwest::Client,
    issuer: String,
    audience: String,
    jwks_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityClaims {
    pub sub: String,
    pub iss: String,
    pub aud: serde_json::Value,
    pub exp: u64,
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
}

impl IdentityClaims {
    pub fn has_step_up_authentication(&self) -> bool {
        self.amr.iter().any(|method| {
            matches!(
                method.to_ascii_lowercase().as_str(),
                "mfa" | "otp" | "hwk" | "fido" | "webauthn" | "swk"
            )
        }) || self
            .acr
            .as_deref()
            .map(|value| {
                value
                    .split([':', '/', ' '])
                    .any(|component| component.eq_ignore_ascii_case("mfa"))
            })
            .unwrap_or(false)
    }
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

impl OidcVerifier {
    pub async fn discover(issuer: &str, audience: &str) -> Result<Self> {
        let issuer = issuer.trim_end_matches('/');
        let client = reqwest::Client::builder().https_only(true).build()?;
        let discovery: DiscoveryDocument = client
            .get(format!("{issuer}/.well-known/openid-configuration"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("decode OIDC discovery document")?;
        anyhow::ensure!(discovery.issuer == issuer, "OIDC discovery issuer mismatch");
        Ok(Self {
            client,
            issuer: issuer.into(),
            audience: audience.into(),
            jwks_uri: discovery.jwks_uri,
        })
    }

    pub async fn verify(&self, token: &str) -> Result<IdentityClaims> {
        let header = decode_header(token).context("decode OIDC token header")?;
        let kid = header.kid.context("OIDC token is missing kid")?;
        let jwks: JwkSet = self
            .client
            .get(&self.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("decode JWKS")?;
        let jwk = jwks.find(&kid).context("OIDC signing key not found")?;
        let key = DecodingKey::from_jwk(jwk)?;
        let algorithm = header.alg;
        anyhow::ensure!(
            matches!(
                algorithm,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::ES256
                    | Algorithm::ES384
                    | Algorithm::EdDSA
            ),
            "OIDC signing algorithm is not allowed"
        );
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.validate_exp = true;
        let claims = decode::<IdentityClaims>(token, &key, &validation)?.claims;
        Ok(claims)
    }
}

#[derive(Clone)]
pub struct InvitationMailer {
    client: reqwest::Client,
    api_key: String,
    from: String,
    base_url: String,
}

impl InvitationMailer {
    pub fn resend(api_key: String, from: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            from,
            base_url: "https://api.resend.com".into(),
        }
    }

    #[cfg(test)]
    pub fn with_base_url(api_key: String, from: String, base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            from,
            base_url,
        }
    }

    pub async fn send_invitation(
        &self,
        email: &str,
        organization: &str,
        accept_url: &str,
    ) -> Result<()> {
        self.client.post(format!("{}/emails",self.base_url.trim_end_matches('/')))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({"from":self.from,"to":[email],"subject":format!("Join {organization} on Oath"),"text":format!("Accept your Oath invitation: {accept_url}")}))
            .send().await?.error_for_status().context("send invitation email")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(amr: &[&str], acr: Option<&str>) -> IdentityClaims {
        IdentityClaims {
            sub: "subject".into(),
            iss: "https://issuer.example".into(),
            aud: serde_json::json!("oath"),
            exp: u64::MAX,
            email: None,
            email_verified: false,
            amr: amr.iter().map(|value| (*value).into()).collect(),
            acr: acr.map(Into::into),
        }
    }

    #[test]
    fn recognizes_step_up_without_treating_password_as_mfa() {
        assert!(claims(&["pwd", "webauthn"], None).has_step_up_authentication());
        assert!(claims(&[], Some("urn:example:loa:mfa")).has_step_up_authentication());
        assert!(!claims(&["pwd"], None).has_step_up_authentication());
        assert!(!claims(&[], Some("urn:example:loa:not-mfa")).has_step_up_authentication());
    }
}
